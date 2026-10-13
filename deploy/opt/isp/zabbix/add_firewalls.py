#!/usr/bin/env python3
"""Pi Firewall Fabric (added 2026-10-12, user request): SonicWall / FortiGate firewalls + the 1G-VDOM switch.

Templates (kept on every run):
  "SonicWall by SNMP - PIDC"  copy of "Network Generic Device by SNMP" with 64-bit traffic counters (10 s),
                              Port state, and SONICWALL-FIREWALL-IP-STATISTICS-MIB: sessions + table size / use,
                              CPU (total, management, forwarding & inspection), RAM, NAT translations, DPI-SSL,
                              IPsec VPN SAs + encrypted / decrypted traffic, model / serial / firmware.
                              SonicWall answers GETBULK wrongly (drops table columns): its hosts poll with bulk off.
  "FortiGate by SNMP - PIDC"  copy of the stock "FortiGate by SNMP" (sessions, VPN tunnels, HA, SD-WAN, VDOMs,
                              sensors) + Port state and the same "Firewall: ..." items, so one dashboard fits both.
Both get the vendor-neutral "Health: ..." items (add_vmware_fabric.health_items) used by the fabric dashboards.

Hosts (DEVICES): a device whose SNMP answers gets its full template; one that only answers ping is monitored by ICMP
only (tag snmp=pending); one that answers neither is created DISABLED. Re-running upgrades a device as soon as its
SNMP answers (never downgrades), so after SNMP is opened on a firewall just run:
    python3 add_firewalls.py && python3 build_firewall_dashboard.py
The 1G-VDOM switch's vendor is unknown until SNMP answers; its sysObjectID then picks the switch template.
"""
import subprocess

import add_full_coverage
import add_routers as R
import add_switches
import add_vmware_fabric as fab
import setup_isp_links as base

GROUP = "Pi Firewall Fabric"
CRED = "/root/.credentials/"
SONICWALL, SONICWALL_SRC = "SonicWall by SNMP - PIDC", "Network Generic Device by SNMP"
FORTIGATE, FORTIGATE_SRC = "FortiGate by SNMP - PIDC", "FortiGate by SNMP"
ICMP_ONLY = fab.ICMP_ONLY
DEVICES = [  # host, visible name, IP, model, template (None = switch, by sysObjectID), vendor, role, community file
    ("Sonicwall-NSA4600-Primary", "Sonicwall-NSA4600-Primary (PIDC-Sonicwall)", "172.20.96.14", "SonicWall NSA 4600",
     SONICWALL, "sonicwall", "firewall", "sonicwall_nsa_snmp_community"),     # SonicOS 6.5.4.12, HA active
    ("Sonicwall-NSA4600-Secondary", "Sonicwall-NSA4600-Secondary (PIDC-Sonicwall)", "172.20.96.15", "SonicWall NSA 4600",
     SONICWALL, "sonicwall", "firewall", "sonicwall_nsa_snmp_community"),     # HA standby
    ("Sonicwall-TZ500-GNOC", "Sonicwall-TZ500-GNOC", "10.128.16.22", "SonicWall TZ500",
     SONICWALL, "sonicwall", "firewall", "sonicwall_tz500_snmp_community"),
    ("GE17-PiSB-Forti120G", "GE17-PiSB-Forti120G", "172.28.44.31", "FortiGate 120G",
     FORTIGATE, "fortinet", "firewall", "vmware_fabric_snmp_community"),     # __REDACTED__
    ("Fortigate-300E", "Fortigate-300E", "172.16.32.127", "FortiGate 300E",
     FORTIGATE, "fortinet", "firewall", "fortigate_300e_snmp_community"),
    ("Fortigate-200F", "Fortigate-200F", "172.20.117.16", "FortiGate 200F",
     FORTIGATE, "fortinet", "firewall", "fortigate_200f_snmp_community"),
    ("1G-VDOM-SW", "1G-VDOM-SW", "172.20.96.206", "switch",
     None, None, "switch", "vmware_fabric_snmp_community"),                   # __REDACTED__
]
# sysObjectID enterprise -> (switch template, vendor tag) for the switch
SWITCH_VENDORS = {"30065": (fab.ARISTA, "arista"), "9": (fab.CATALYST, "cisco"), "2011": (fab.HUAWEI, "huawei"),
                  "25506": (fab.COMWARE, "hpe"), "2636": (fab.JUNIPER, "juniper")}

SW = "1.3.6.1.4.1.8741.1.3"          # SONICWALL-FIREWALL-IP-STATISTICS-MIB sonicwallFwStatsModule
SW_INFO = "1.3.6.1.4.1.8741.2.1.1"   # SONICWALL-COMMON-MIB snwlSysInfo
SA = SW + ".2.1.1.1"                 # sonicSAStatEntry: 2 peer gateway, 9 encrypt bytes, 11 decrypt bytes
FW_TAGS = [{"tag": "component", "value": "firewall"}]

# Sum / count of a sonicSAStatTable column from walk[] text ('.oid = TYPE: value' lines)
SA_JS = r"""
var col = '.%s.', n = 0, sum = 0, peers = {};
value.split('\n').forEach(function (l) {
    var i = l.indexOf(' = '); if (i < 0) return;
    var oid = l.slice(0, i), v = l.slice(i + 3).replace(/^[A-Za-z0-9-]+: /, '').replace(/"/g, '').trim();
    if (oid.indexOf('%s' + col) < 0) return;
    n++; sum += parseFloat(v) || 0; peers[v] = 1;
});
return %s;
"""


def sa_js(col, result):
    return (SA_JS % (col, SA, result)).strip()


def snmp_answers(ip, community):
    """sysObjectID if the device answers SNMP v2c (no bulk), else None."""
    r = subprocess.run(["snmpget", "-v2c", "-c", community, "-t", "3", "-r", "1", "-Oqvn", ip, "1.3.6.1.2.1.1.2.0"],
                       capture_output=True, text=True)
    out = r.stdout.strip()
    return out.lstrip(".") if r.returncode == 0 and out.startswith(".1.3.6.1.4.1.") else None


def pings(ip):
    return subprocess.run(["ping", "-c", "2", "-W", "2", ip], capture_output=True).returncode == 0


# ---------------------------------------------------------------------------------------------------- templates
def item(z, tid, key, name, oid=None, delay="1m", **kw):
    kw.setdefault("value_type", R.UINT)
    kw.setdefault("tags", FW_TAGS)
    kw.setdefault("history", "90d")
    if oid:
        kw.update(type=R.SNMP, snmp_oid=f"get[{oid}]")
    if kw.get("type") != R.DEPENDENT:   # dependent items take no interval
        kw["delay"] = delay
    return R.ensure_item(z, tid, key, name=name, **kw)


def trigger(z, template, description, expression, priority, comments=""):
    if not z.call("trigger.get", {"templateids": fab.template_id(z, template), "filter": {"description": description},
                                  "output": ["triggerid"]}):
        z.call("trigger.create", {"description": description, "expression": expression, "priority": priority,
                                  "comments": comments, "tags": FW_TAGS})


def macro(z, tid, name, value, description):
    if not z.call("usermacro.get", {"hostids": tid, "filter": {"macro": name}, "output": ["hostmacroid"]}):
        z.call("usermacro.create", {"hostid": tid, "macro": name, "value": value, "description": description})


def setup_sonicwall(z):
    fab.setup_snmp_get_template(z, SONICWALL_SRC, SONICWALL, (
        "PIDC SonicWall template (copy of 'Network Generic Device by SNMP'): 64-bit traffic 10s, status 30s, Port "
        "state, sessions, CPU / RAM, NAT, DPI-SSL, IPsec VPN, model / firmware. Managed by /opt/isp/zabbix/add_firewalls.py."))
    tid = fab.template_id(z, SONICWALL)
    # 64-bit counters (the stock copy polls 32-bit ifInOctets, which wraps in seconds on a busy 1/10G port) and
    # ifHighSpeed (ifSpeed tops out at 4.29 Gbps). The keys keep their stock names (graphs / triggers use them).
    rule = z.call("discoveryrule.get", {"templateids": tid, "filter": {"key_": "net.if.discovery"},
                                        "output": ["itemid"]})[0]["itemid"]
    hc = {"net.if.in[ifInOctets.{#SNMPINDEX}]": "1.3.6.1.2.1.31.1.1.1.6",
          "net.if.out[ifOutOctets.{#SNMPINDEX}]": "1.3.6.1.2.1.31.1.1.1.10",
          "net.if.speed[ifSpeed.{#SNMPINDEX}]": "1.3.6.1.2.1.31.1.1.1.15"}
    for p in z.call("itemprototype.get", {"discoveryids": rule, "output": ["key_", "snmp_oid"],
                                          "selectPreprocessing": "extend"}):
        if p["key_"] in hc and p["snmp_oid"] != f"get[{hc[p['key_']]}.{{#SNMPINDEX}}]":
            upd = {"itemid": p["itemid"], "snmp_oid": f"get[{hc[p['key_']]}.{{#SNMPINDEX}}]"}
            if "speed" in p["key_"]:   # ifHighSpeed is in Mbps
                upd["preprocessing"] = R.pp((base.MULTIPLIER, "1000000"))
            z.call("itemprototype.update", upd)

    pct = {"units": "%", "value_type": R.FLOAT}
    item(z, tid, "fw.sessions", "Firewall: Active sessions", f"{SW}.1.2.0", "30s", description="sonicCurrentConnCacheEntries")
    item(z, tid, "fw.sessions.max", "Firewall: Session table size", f"{SW}.1.1.0", "1h",
         preprocessing=R.pp((base.DISCARD_UNCHANGED_HEARTBEAT, "1d")), description="sonicMaxConnCacheEntries")
    item(z, tid, "fw.sessions.pused", "Firewall: Session table use", None, "1m", type=R.CALCULATED,
         params="100*last(//fw.sessions)/last(//fw.sessions.max)", **pct)
    item(z, tid, "system.cpu.util[sonicCurrentCPUUtil.0]", "CPU utilization", f"{SW}.1.3.0", "30s",
         tags=[{"tag": "component", "value": "cpu"}], **pct)
    item(z, tid, "fw.cpu.mgmt", "Firewall: Management CPU utilization", f"{SW}.1.6.0", "1m", **pct)
    item(z, tid, "fw.cpu.fwd", "Firewall: Forwarding and inspection CPU utilization", f"{SW}.1.7.0", "1m", **pct)
    item(z, tid, "vm.memory.util[sonicCurrentRAMUtil.0]", "Memory utilization", f"{SW}.1.4.0", "30s",
         tags=[{"tag": "component", "value": "memory"}], **pct)
    item(z, tid, "fw.nat", "Firewall: NAT translations", f"{SW}.1.5.0", "1m")
    item(z, tid, "fw.dpissl", "Firewall: DPI-SSL connections", f"{SW}.5.1.0", "1m")
    item(z, tid, "fw.dpissl.max", "Firewall: DPI-SSL connection limit", f"{SW}.5.3.0", "1h",
         preprocessing=R.pp((base.DISCARD_UNCHANGED_HEARTBEAT, "1d")))
    vpn = item(z, tid, "fw.vpn.walk", "SonicWall: SNMP walk IPsec SAs", None, "1m", type=R.SNMP,
               snmp_oid=R.walk(f"{SA}.2", f"{SA}.9", f"{SA}.11"), value_type=R.TEXT, history="0", trends="0",
               tags=[{"tag": "component", "value": "raw"}])
    for key, name, js, extra in (
            ("fw.vpn.up", "Firewall: VPN tunnels up (IPsec SAs)", sa_js(2, "n"), {}),
            ("fw.vpn.peers", "Firewall: VPN peers", sa_js(2, "Object.keys(peers).length"), {}),
            ("fw.vpn.enc", "Firewall: VPN traffic encrypted (sent into tunnels)", sa_js(9, "sum"),
             {"units": "bps", "steps": ((base.CHANGE_PER_SECOND, ""), (base.MULTIPLIER, "8"))}),
            ("fw.vpn.dec", "Firewall: VPN traffic decrypted (received from tunnels)", sa_js(11, "sum"),
             {"units": "bps", "steps": ((base.CHANGE_PER_SECOND, ""), (base.MULTIPLIER, "8"))})):
        steps = ((R.JAVASCRIPT, js),) + extra.pop("steps", ())
        item(z, tid, key, name, None, type=R.DEPENDENT, master_itemid=vpn,
             value_type=R.FLOAT if "units" in extra else R.UINT, preprocessing=R.pp(*steps), **extra)
    for key, name, oid in (("fw.model", "SonicWall: Model", f"{SW_INFO}.1.0"),
                           ("fw.serial", "SonicWall: Serial number", f"{SW_INFO}.2.0"),
                           ("fw.firmware", "SonicWall: Firmware version", f"{SW_INFO}.3.0"),
                           ("fw.rom", "SonicWall: ROM version", f"{SW_INFO}.4.0")):
        item(z, tid, key, name, oid, "1h", value_type=R.TEXT, trends="0",
             tags=[{"tag": "component", "value": "system"}],
             preprocessing=R.pp((base.DISCARD_UNCHANGED_HEARTBEAT, "1d")))

    macro(z, tid, "{$CPU.UTIL.CRIT}", "75", "CPU alert threshold (%)")
    macro(z, tid, "{$MEMORY.UTIL.MAX}", "85", "Memory alert threshold (%)")
    macro(z, tid, "{$FW.SESSIONS.PUSED.MAX}", "80", "Session (connection) table use alert threshold (%)")
    t = f"/{SONICWALL}/"
    trigger(z, SONICWALL, "High CPU utilization (over {$CPU.UTIL.CRIT}% for 5m)",
            f"min({t}system.cpu.util[sonicCurrentCPUUtil.0],5m)>{{$CPU.UTIL.CRIT}}", 3)
    trigger(z, SONICWALL, "High memory utilization (over {$MEMORY.UTIL.MAX}% for 5m)",
            f"min({t}vm.memory.util[sonicCurrentRAMUtil.0],5m)>{{$MEMORY.UTIL.MAX}}", 3)
    trigger(z, SONICWALL, "Session table over {$FW.SESSIONS.PUSED.MAX}% full",
            f"min({t}fw.sessions.pused,5m)>{{$FW.SESSIONS.PUSED.MAX}}", 3,
            "New connections are dropped when the connection cache is full.")
    trigger(z, SONICWALL, "Session table nearly full (over 95%)", f"min({t}fw.sessions.pused,5m)>95", 4)
    trigger(z, SONICWALL, "Firmware version changed", f"change({t}fw.firmware)=1", 1)
    fab.HEALTH[SONICWALL] = {"cpu": "last(//system.cpu.util[sonicCurrentCPUUtil.0])",
                             "mem": "last(//vm.memory.util[sonicCurrentRAMUtil.0])", "fan_ok": 1, "psu_ok": 1}
    fab.health_items(z, SONICWALL)


def setup_fortigate(z):
    R.clone_template(z, FORTIGATE_SRC, FORTIGATE, (
        "PIDC copy of 'FortiGate by SNMP': Port state + the vendor-neutral Firewall / Health items used by the "
        "Pi Firewall Fabric dashboard. Managed by /opt/isp/zabbix/add_firewalls.py."), dashboards=False)
    tid = fab.template_id(z, FORTIGATE)
    rule = z.call("discoveryrule.get", {"templateids": tid, "filter": {"key_": "net.if.discovery"},
                                        "output": ["itemid", "name"]})[0]
    if rule["name"] != "Network interfaces discovery":   # tune() looks the rule up by this name
        z.call("discoveryrule.update", {"itemid": rule["itemid"], "name": "Network interfaces discovery"})
    import tune_arista_template
    tune_arista_template.tune(z, FORTIGATE)
    ses = z.call("item.get", {"templateids": tid, "filter": {"key_": "net.ipv4.sessions[fgSysSesCount.0]"},
                              "output": ["itemid", "delay"]})[0]
    if ses["delay"] != "1m":
        z.call("item.update", {"itemid": ses["itemid"], "delay": "1m"})
    for key, name, params in (("fw.sessions", "Firewall: Active sessions", "last(//net.ipv4.sessions[fgSysSesCount.0])"),
                              ("fw.vpn.up", "Firewall: VPN tunnels up", "last(//vpn.tunnel.active[fgVpnTunnelUpCount.0])"),
                              ("fw.vpn.users", "Firewall: SSL VPN users", "last(//vpn.users.count[fgVpnSslStatsLoginUsers.0])")):
        item(z, tid, key, name, None, "1m", type=R.CALCULATED, params=params)
    # the stock template only has fgSysUpTime; device_uptime.py --setup turns this one into the trapper
    # 'Uptime (network)' used by the dashboard tiles (as on every other PIDC template)
    if not z.call("item.get", {"templateids": tid, "filter": {"key_": "system.net.uptime[sysUpTime.0]"},
                               "output": ["itemid"]}):
        item(z, tid, "system.net.uptime[sysUpTime.0]", "Uptime (network)", "1.3.6.1.2.1.1.3.0", "5m",
             units="uptime", trends="0", preprocessing=R.pp((base.MULTIPLIER, "0.01")),
             tags=[{"tag": "component", "value": "system"}])
    fab.HEALTH[FORTIGATE] = {"cpu": "last(//system.cpu.util[fgSysCpuUsage.0])",
                             "mem": "last(//vm.memory.util[memoryUsedPercentage.0])", "fan_ok": 1, "psu_ok": 1}
    fab.health_items(z, FORTIGATE)


# ---------------------------------------------------------------------------------------------------- hosts
def sync_address(z, hostid, host, ip, community):
    """Existing host: follow IP / community changes made in DEVICES or the credential file."""
    for i in z.call("hostinterface.get", {"hostids": hostid, "filter": {"type": 2, "main": 1},
                                          "output": ["interfaceid", "ip"]}):
        if i["ip"] != ip:
            z.call("hostinterface.update", {"interfaceid": i["interfaceid"], "ip": ip})
            print(f"{host}: SNMP interface IP {i['ip']} -> {ip}")
    for m in z.call("usermacro.get", {"hostids": hostid, "filter": {"macro": "{$SNMP_COMMUNITY}"},
                                      "output": ["hostmacroid", "value", "type"]}):
        if m["type"] == "1" or m["value"] != community:   # secret macros read back empty: always rewrite
            z.call("usermacro.update", {"hostmacroid": m["hostmacroid"], "value": community})


def ensure_host(z, gid, dev):
    host, name, ip, model, template, vendor, role, cfile = dev
    community = base.read(CRED + cfile)
    oid = snmp_answers(ip, community)
    if oid and template is None:   # the switch: vendor from sysObjectID 1.3.6.1.4.1.<enterprise>...
        template, vendor = SWITCH_VENDORS.get(oid.split(".")[6], (None, None))
        if template is None:
            print(f"{host}: SNMP answers (sysObjectID {oid}) but the vendor has no PIDC template - ICMP only")
            oid = None
    up = bool(oid) or pings(ip)
    want = template if oid else ICMP_ONLY
    tags = [{"tag": "role", "value": role}, {"tag": "fabric", "value": "firewall"},
            {"tag": "model", "value": model}, {"tag": "snmp", "value": "ok" if oid else "pending"}]
    if vendor:
        tags.append({"tag": "vendor", "value": vendor})
    found = z.call("host.get", {"filter": {"host": [host]}, "output": ["hostid", "status"],
                                "selectParentTemplates": ["host", "templateid"], "selectTags": ["tag", "value"]})
    if not found:
        bulk = 0 if vendor == "sonicwall" else 1   # SonicWall drops table columns in GETBULK replies
        z.call("host.create", {
            "host": host, "name": name, "groups": [{"groupid": gid}], "status": 0 if up else 1,
            "templates": [{"templateid": fab.template_id(z, want)}],
            "interfaces": [{"type": 2, "main": 1, "useip": 1, "ip": ip, "dns": "", "port": "161",
                            "details": {"version": 2, "bulk": bulk, "community": "{$SNMP_COMMUNITY}"}}],
            "macros": [{"macro": "{$SNMP_COMMUNITY}", "value": community, "type": 1, "description": "SNMP v2c community"},
                       {"macro": "{$NET.IF.IFNAME.NOT_MATCHES}", "value": fab.IFNAME_NOT_MATCHES}]
                      + add_switches.EXTRA_MACROS + fab.VENDOR_MACROS.get(vendor, []),
            "tags": tags, "inventory_mode": 1})
        state = "SNMP" if oid else "ICMP only (SNMP not answering)" if up else "DISABLED (no ping, no SNMP)"
        print(f"{host}: created - {state}")
        return
    h = found[0]
    sync_address(z, h["hostid"], host, ip, community)
    linked = {t["host"]: t["templateid"] for t in h["parentTemplates"]}
    if oid and template not in linked:   # SNMP answers now: upgrade from ICMP only (never the other way round)
        if ICMP_ONLY in linked:   # the full templates have their own ICMP items (same keys): unlink + clear first
            z.call("host.update", {"hostid": h["hostid"], "templates_clear": [{"templateid": linked[ICMP_ONLY]}]})
        z.call("host.update", {"hostid": h["hostid"], "status": 0, "tags": tags,
                               "templates": [{"templateid": fab.template_id(z, template)}]})
        print(f"{host}: SNMP answers - upgraded to {template}")
    elif up and h["status"] == "1":
        z.call("host.update", {"hostid": h["hostid"], "status": 0})
        print(f"{host}: answers ping now - enabled (ICMP only until SNMP answers)")
    add_switches.ensure_macros(z, h["hostid"])


def main():
    z = base.Zabbix()
    setup_sonicwall(z)
    setup_fortigate(z)
    import add_firewall_detail   # VPN / SSL VPN / FortiGuard / security / policy / HA / logging detail
    add_firewall_detail.main(z)
    t = add_full_coverage.Template(z, SONICWALL)
    for feat in add_full_coverage.FEATURES[SONICWALL]:   # per-port broadcast / multicast, link flaps, FCS errors
        feat(t)
    found = z.call("hostgroup.get", {"filter": {"name": [GROUP]}, "output": ["groupid"]})
    gid = found[0]["groupid"] if found else z.call("hostgroup.create", {"name": GROUP})["groupids"][0]
    for dev in DEVICES:
        ensure_host(z, gid, dev)
    rules = z.call("discoveryrule.get", {"groupids": gid, "templated": False, "output": ["itemid"],
                                         "filter": {"status": 0}})
    if rules:
        z.call("task.create", [{"type": 6, "request": {"itemid": r["itemid"]}} for r in rules])


if __name__ == "__main__":
    main()
