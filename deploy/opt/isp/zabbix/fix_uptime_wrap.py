#!/usr/bin/env python3
"""Correct SNMP uptime for the 32-bit wrap on every SNMP template in use.

sysUpTime and hrSystemUptime are TimeTicks (1/100 s) in 32 bits: they roll over to 0 every 2^32/100 s = 497.1 days,
so a switch up 85 weeks showed 98 days (2026-10-09, 10G-WAN-Switch02). snmpEngineTime (SNMP-FRAMEWORK-MIB, plain
seconds) does not wrap but restarts with the SNMP agent, so it is only a lower bound for the real uptime. Hence:

    uptime = raw + W * n,  W = 497.1 days,  n = smallest n >= 0 with raw + W*n >= snmpEngineTime - 1 day

Per template that has "system.net.uptime[sysUpTime.0]" as an SNMP item and is linked to a host:
  - raw SNMP items "snmp.raw.sysuptime", "snmp.raw.hruptime" (if the template has hrSystemUptime), "snmp.raw.enginetime"
    (copies of the original OID / preprocessing, history 7d, no trends)
  - the original "Uptime (network)" / "Uptime (hardware)" items become calculated items with the corrected value;
    key, name and history stay, so dashboards, reports and the stock "has been restarted" trigger keep working.
    A real reboot still resets them (raw and engine time both restart -> n = 0).
Limitation: if the SNMP agent alone restarted after a wrap, engine time cannot tell, and the shown uptime is short by
497 days again. Idempotent; cron /etc/cron.d/zabbix-uptime-wrap (hourly) also fixes templates linked later.
"""
import add_routers as R
import setup_isp_links as base

W = 42949672.96   # 2^32 TimeTicks in seconds
NET, HW = "system.net.uptime[sysUpTime.0]", "system.hw.uptime[hrSystemUptime.0]"
RAW = {NET: ("snmp.raw.sysuptime", "SNMP raw: sysUpTime (32-bit, wraps every 497 days)"),
       HW: ("snmp.raw.hruptime", "SNMP raw: hrSystemUptime (32-bit, wraps every 497 days)")}
ENGINE = ("snmp.raw.enginetime", "SNMP raw: snmpEngineTime (seconds since SNMP agent start)", "get[1.3.6.1.6.3.10.2.1.3.0]")
TAGS = [{"tag": "component", "value": "raw"}]


def formula(raw):
    r, e = f"last(//{raw})", f"last(//{ENGINE[0]})"
    fix = f"{W}*max(0,ceil(({e}-{r}-86400)/{W}))"
    # hrSystemUptime = 0 means "not supported" (stock preprocessing): keep 0 so the restart trigger uses sysUpTime
    return f"round({r}+{fix},0)" if raw == RAW[NET][0] else f"round({r}+({r}>0)*{fix},0)"


def fix_template(z, t):
    tid = t["templateid"]
    items = {i["key_"]: i for i in z.call("item.get", {
        "templateids": tid, "filter": {"key_": [NET, HW, ENGINE[0], RAW[NET][0], RAW[HW][0]]},
        "output": ["itemid", "key_", "type", "snmp_oid", "delay", "params"], "selectPreprocessing": "extend"})}
    if NET not in items:
        return
    delay = items[NET]["delay"]
    R.ensure_item(z, tid, ENGINE[0], name=ENGINE[1], type=R.SNMP, snmp_oid=ENGINE[2], delay=delay, units="uptime",
                  value_type=R.UINT, history="7d", trends="0", tags=TAGS,
                  description="Does not wrap, but restarts with the SNMP agent: lower bound for the uptime (fix_uptime_wrap.py).")
    changed = []
    for key in (NET, HW):
        it = items.get(key)
        if not it:
            continue
        raw_key, raw_name = RAW[key]
        if it["type"] == str(R.SNMP):   # still the original SNMP item: copy it to the raw item, then convert
            R.ensure_item(z, tid, raw_key, name=raw_name, type=R.SNMP, snmp_oid=it["snmp_oid"], delay=delay,
                          units="uptime", value_type=R.UINT, history="7d", trends="0", tags=TAGS,
                          preprocessing=[{k: p[k] for k in ("type", "params", "error_handler", "error_handler_params")}
                                         for p in it["preprocessing"]])
        if it["type"] != str(R.CALCULATED) or it["params"] != formula(raw_key):
            z.call("item.update", {"itemid": it["itemid"], "type": R.CALCULATED, "params": formula(raw_key),
                                   "snmp_oid": "", "preprocessing": [],
                                   "description": "Uptime corrected for the 32-bit TimeTicks wrap (497.1 days) using "
                                                  "snmpEngineTime; raw value in '" + raw_name + "'. fix_uptime_wrap.py"})
            changed.append(key)
    if changed:
        print(f"{t['host']}: corrected {changed}")


def main():
    z = base.Zabbix()
    found = z.call("item.get", {"templated": True, "filter": {"key_": NET}, "output": ["hostid"]})
    templates = z.call("template.get", {"templateids": list({i["hostid"] for i in found}),
                                        "output": ["templateid", "host"], "selectHosts": "count"})
    for t in templates:
        if int(t["hosts"]):   # only templates linked directly to hosts
            fix_template(z, t)


if __name__ == "__main__":
    main()
