#!/usr/bin/env python3
"""Device uptime for every SNMP device: read from the device itself, not from the SNMP agent's run time.

Source per device (best available, the first that reports a value):
  - Huawei VRP: hwEntityUpTime (HUAWEI-ENTITY-EXTENT-MIB, main board, seconds) - never wraps
  - hrSystemUptime (HOST-RESOURCES-MIB): operating system uptime - Arista, Juniper, A10
  - sysUpTime: Cisco IOS / IOS-XE and HPE Comware (there it counts from the last reload; they have no
    hrSystemUptime, and the HPE hh3cEntityExtUpTime is frozen) - also Arista leaves that return hrSystemUptime = 0
hrSystemUptime and sysUpTime are 32-bit TimeTicks and roll over to 0 every 497.1 days. This script runs every
minute, follows each device's counter and counts the roll-overs itself: a drop to exactly where the counter would
be after a roll-over adds 497.1 days; any other drop is a reboot and restarts the count. The result is sent to the
"Uptime (network)" and "Uptime (hardware)" items (trapper items; key, name and history unchanged, so dashboards,
reports and the stock "has been restarted" trigger keep working).

Roll-overs before monitoring started cannot be seen in the counter. They are taken from, in this order:
  - host macro {$UPTIME.WRAPS} (number of 497.1-day periods to add; set it after checking the uptime on the CLI -
    applied once, whenever its value changes)
  - snmpEngineTime, only as proof that the device has been up at least that long (never shown as the uptime)

  device_uptime.py           every minute (cron /etc/cron.d/zabbix-device-uptime): compute and send
  device_uptime.py --setup   hourly: raw SNMP items + trapper items on every SNMP template linked to a host
State: /var/lib/zabbix/device-uptime-state.json. Replaces fix_uptime_wrap.py (2026-10-09).
"""
import json
import os
import socket
import struct
import sys
import time

import add_routers as R
import setup_isp_links as base

W = 2 ** 32 / 100   # TimeTicks roll-over, seconds (497.1 days)
NET, HW = "system.net.uptime[sysUpTime.0]", "system.hw.uptime[hrSystemUptime.0]"
RAW_SYS, RAW_HR, RAW_ENGINE, RAW_ENT = ("snmp.raw.sysuptime", "snmp.raw.hruptime", "snmp.raw.enginetime",
                                       "snmp.raw.entityuptime")
RAW_NAMES = {NET: (RAW_SYS, "SNMP raw: sysUpTime (32-bit, wraps every 497 days)"),
             HW: (RAW_HR, "SNMP raw: hrSystemUptime (32-bit, wraps every 497 days)")}
SEED = "{$UPTIME.WRAPS}"
STATE = "/var/lib/zabbix/device-uptime-state.json"
TAGS = [{"tag": "component", "value": "raw"}]
DESCRIPTION = ("Device uptime from the device itself (hwEntityUpTime, hrSystemUptime or sysUpTime - not the SNMP "
               "agent run time), 32-bit roll-overs (497.1 days) counted by /opt/isp/zabbix/device_uptime.py, which "
               "sends this value every minute. Host macro {$UPTIME.WRAPS} adds roll-overs from before monitoring.")
HUAWEI_ENT_JS = r"""
var best = 0;
value.split('\n').forEach(function (line) {
    var m = line.match(/ = (?:INTEGER|Gauge32|Counter32): (\d+)/);
    if (m && parseInt(m[1], 10) > best) best = parseInt(m[1], 10);
});
if (best === 0) throw 'no hwEntityUpTime';
return best;
"""


# ---------------------------------------------------------------- setup
def setup_template(z, t):
    tid = t["templateid"]
    items = {i["key_"]: i for i in z.call("item.get", {
        "templateids": tid, "filter": {"key_": [NET, HW, RAW_SYS, RAW_HR, RAW_ENGINE, RAW_ENT]},
        "output": ["itemid", "key_", "type", "snmp_oid", "delay"], "selectPreprocessing": "extend"})}
    if NET not in items:
        return
    delay = items[RAW_SYS]["delay"] if RAW_SYS in items else items[NET]["delay"]
    for key in (NET, HW):   # still the stock SNMP item: keep its OID as the raw item
        it = items.get(key)
        if it and it["type"] == str(R.SNMP):
            raw_key, raw_name = RAW_NAMES[key]
            R.ensure_item(z, tid, raw_key, name=raw_name, type=R.SNMP, snmp_oid=it["snmp_oid"], delay=delay,
                          units="uptime", value_type=R.UINT, history="7d", trends="0", tags=TAGS,
                          preprocessing=[{k: p[k] for k in ("type", "params", "error_handler", "error_handler_params")}
                                         for p in it["preprocessing"]])
    R.ensure_item(z, tid, RAW_ENGINE, name="SNMP raw: snmpEngineTime (seconds since SNMP agent start)", type=R.SNMP,
                  snmp_oid="get[1.3.6.1.6.3.10.2.1.3.0]", delay=delay, units="uptime", value_type=R.UINT,
                  history="7d", trends="0", tags=TAGS,
                  description="SNMP agent run time: only a lower bound for roll-overs before monitoring started.")
    if t["host"].startswith("Huawei VRP"):
        R.ensure_item(z, tid, RAW_ENT, name="SNMP raw: hwEntityUpTime (main board uptime, seconds)", type=R.SNMP,
                      snmp_oid="walk[1.3.6.1.4.1.2011.5.25.31.1.1.1.1.10]", delay=delay, units="uptime",
                      value_type=R.UINT, history="7d", trends="0", tags=TAGS,
                      preprocessing=R.pp((R.JAVASCRIPT, HUAWEI_ENT_JS.strip())))
    for key in (NET, HW):
        it = items.get(key)
        if it and it["type"] != "2":
            z.call("item.update", {"itemid": it["itemid"], "type": 2, "params": "", "snmp_oid": "",
                                   "preprocessing": [], "description": DESCRIPTION})
            print(f"{t['host']}: {key} -> device uptime (trapper)")


def setup(z):
    found = z.call("item.get", {"templated": True, "filter": {"key_": NET}, "output": ["hostid"]})
    for t in z.call("template.get", {"templateids": list({i["hostid"] for i in found}),
                                     "output": ["templateid", "host"], "selectHosts": "count"}):
        if int(t["hosts"]):   # only templates linked directly to hosts
            setup_template(z, t)


# ---------------------------------------------------------------- run
def send(values):
    """Zabbix sender protocol to the local server; returns the server's 'info' text."""
    body = json.dumps({"request": "sender data", "data": values}).encode()
    with socket.create_connection(("127.0.0.1", 10051), timeout=10) as s:
        s.sendall(b"ZBXD\x01" + struct.pack("<II", len(body), 0) + body)
        resp = b""
        while chunk := s.recv(65536):
            resp += chunk
    return json.loads(resp[13:]).get("info", "")


def run(z):
    now = time.time()
    try:
        with open(STATE) as fh:
            state = json.load(fh)
    except (OSError, ValueError):
        state = {}
    targets = z.call("item.get", {"monitored": True, "filter": {"key_": [NET, HW], "type": 2},
                                  "output": ["hostid", "key_"], "selectHosts": ["host"]})
    hosts = {}
    for i in targets:
        hosts.setdefault(i["hostid"], {"host": i["hosts"][0]["host"], "keys": []})["keys"].append(i["key_"])
    raws = z.call("item.get", {"hostids": list(hosts), "filter": {"key_": [RAW_SYS, RAW_HR, RAW_ENGINE, RAW_ENT]},
                               "output": ["hostid", "key_", "lastvalue", "lastclock", "state"]}) if hosts else []
    seeds = {m["hostid"]: m["value"] for m in z.call("usermacro.get", {
        "hostids": list(hosts), "filter": {"macro": SEED}, "output": ["hostid", "value"]})} if hosts else {}
    raw = {}
    for i in raws:   # only fresh, supported, non-zero readings
        if i["state"] == "0" and i["lastvalue"] not in ("", "0") and now - int(i["lastclock"]) < 600:
            raw.setdefault(i["hostid"], {})[i["key_"]] = (int(float(i["lastvalue"])), int(i["lastclock"]))
    out = []
    for hid, h in hosts.items():
        r = raw.get(hid, {})
        src = next((k for k in (RAW_ENT, RAW_HR, RAW_SYS) if k in r), None)
        if not src:
            continue   # device not answering: send nothing (no false "restarted")
        value, clock = r[src]
        st = state.get(hid)
        if not st or st["src"] != src:   # first reading from this source: roll-overs from before monitoring
            n = 0
            if src != RAW_ENT and RAW_ENGINE in r:   # the device has been up at least as long as its SNMP agent
                n = max(0, -int(-(r[RAW_ENGINE][0] - value - 86400) // W))
            st = {"src": src, "n": n}
            print(f"{h['host']}: source {src}, {n} earlier roll-over(s) from snmpEngineTime")
        elif value < st["value"] - 5:   # the counter went back (it only ever increases)
            expected = st["value"] + (clock - st["clock"])
            if src != RAW_ENT and expected >= W - 3600 and abs(value - (expected - W)) < max(900, 0.01 * (clock - st["clock"])):
                st["n"] += 1
                print(f"{h['host']}: {src} rolled over (497.1 days) - now {st['n']} roll-over(s)")
            else:
                st["n"] = 0
                print(f"{h['host']}: device restarted ({src} {st['value']} -> {value})")
        if hid in seeds and seeds[hid] != st.get("seed"):   # manual correction after checking the CLI
            st["n"], st["seed"] = int(seeds[hid] or 0), seeds[hid]
            print(f"{h['host']}: {SEED} = {seeds[hid]} applied")
        st.update(value=value, clock=clock)
        state[hid] = st
        uptime = int(round(value + (0 if src == RAW_ENT else st["n"] * W)))
        out += [{"host": h["host"], "key": k, "value": str(uptime), "clock": clock} for k in h["keys"]]
    if out:
        info = send(out)
        if "failed: 0" not in info:
            print("sender:", info)
    tmp = STATE + ".tmp"
    with open(tmp, "w") as fh:
        json.dump(state, fh)
    os.replace(tmp, STATE)


def main():
    z = base.Zabbix()
    if "--setup" in sys.argv:
        setup(z)
    else:
        run(z)


if __name__ == "__main__":
    main()
