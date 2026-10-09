#!/usr/bin/env python3
"""Add the Arista switches (10G WAN pair, PiSB cloud spine/leaf fabric) to Zabbix.

Template "Arista by SNMP - PIDC" is a copy of the stock "Arista by SNMP" with faster interface polling
(traffic 10s, status 30s, errors/discards 1m; Arista counters refresh every ~2s); it includes ICMP checks.
SNMP v2c community is read from /root/.credentials/switch_snmp_community. Idempotent.
"""
import setup_isp_links as base

TEMPLATES = ["Arista by SNMP - PIDC"]   # includes ICMP ping, loss and response time
SWITCHES = [  # host, visible name, IP, host group, role
    ("10G-WAN-Switch01", "10G-WAN-Switch01 (PIDC-COLO-10G-SW1)", "10.128.17.27", "WAN Switches", "wan-switch"),
    ("10G-WAN-Switch02", "10G-WAN-Switch02 (PIDC-COLO-10G-SW2)", "10.128.17.28", "WAN Switches", "wan-switch"),
    ("GE17-PiSB-SP1", "GE17-PiSB-SP1 (PiSB spine 1)", "172.28.44.23", "PiSB Cloud Switches", "spine"),
    ("GE17-PiSB-SP2", "GE17-PiSB-SP2 (PiSB spine 2)", "172.28.44.22", "PiSB Cloud Switches", "spine"),
    ("GE18-PiSB-LF1", "GE18-PiSB-LF1 (PiSB leaf 1)", "172.28.44.25", "PiSB Cloud Switches", "leaf"),
    ("GE18-PiSB-LF2", "GE18-PiSB-LF2 (PiSB leaf 2)", "172.28.44.24", "PiSB Cloud Switches", "leaf"),
]


# Also monitor ports with no module fitted (ifOperStatus 6 = notPresent); the stock filter skips them.
EXTRA_MACROS = [{"macro": "{$NET.IF.IFOPERSTATUS.NOT_MATCHES}", "value": "CHANGE_IF_NEEDED",
                 "description": "Discover every port incl. notPresent (empty module slots / unused breakout lanes)"},
                {"macro": "{$NET.IF.IFADMINSTATUS.NOT_MATCHES}", "value": "CHANGE_IF_NEEDED",
                 "description": "Discover admin-shutdown ports too (shown as 'shutdown' via the Port state item)"}]


def ensure_macros(z, hostid):
    """Add EXTRA_MACROS to an existing host if missing (hosts created before they were introduced)."""
    have = {m["macro"]: m for m in z.call("usermacro.get", {"hostids": hostid, "output": ["hostmacroid", "macro", "value"]})}
    for mc in EXTRA_MACROS:
        if mc["macro"] not in have:
            z.call("usermacro.create", {"hostid": hostid, **mc})
        elif have[mc["macro"]]["value"] != mc["value"]:
            z.call("usermacro.update", {"hostmacroid": have[mc["macro"]]["hostmacroid"], "value": mc["value"]})


def main():
    z = base.Zabbix()
    community = base.read("/root/.credentials/switch_snmp_community")
    groupids = {}
    for name in {sw[3] for sw in SWITCHES}:
        found = z.call("hostgroup.get", {"filter": {"name": [name]}, "output": ["groupid"]})
        groupids[name] = found[0]["groupid"] if found else z.call("hostgroup.create", {"name": name})["groupids"][0]
    templates = [{"templateid": t["templateid"]} for t in
                 z.call("template.get", {"filter": {"host": TEMPLATES}, "output": ["templateid"]})]
    assert len(templates) == len(TEMPLATES), "template missing"
    created = []
    for host, name, ip, group, role in SWITCHES:
        existing = z.call("host.get", {"filter": {"host": [host]}, "output": ["hostid"]})
        if existing:
            ensure_macros(z, existing[0]["hostid"])
            continue
        z.call("host.create", {
            "host": host, "name": name, "groups": [{"groupid": groupids[group]}], "templates": templates,
            "interfaces": [{"type": 2, "main": 1, "useip": 1, "ip": ip, "dns": "", "port": "161",
                            "details": {"version": 2, "bulk": 1, "community": "{$SNMP_COMMUNITY}"}}],
            "macros": [{"macro": "{$SNMP_COMMUNITY}", "value": community, "type": 1,
                        "description": "Arista SNMP v2c community"},
                       # also skip loopbacks (stock filter only matches "lo0"-style names)
                       {"macro": "{$NET.IF.IFNAME.NOT_MATCHES}",
                        "value": r"(^Software Loopback Interface|^NULL[0-9.]*$|^[Ll]o[0-9.]*$|^[Ss]ystem$|^Nu[0-9.]*$|"
                                 r"^veth[0-9a-z]+$|docker[0-9]+|br-[a-z0-9]{12}|^Loopback[0-9]+$)"}] + EXTRA_MACROS,
            "tags": [{"tag": "role", "value": role}, {"tag": "vendor", "value": "arista"}],
            "inventory_mode": 1,
        })
        created.append(host)
    # run interface discovery on every switch now (and all rules on new ones) instead of waiting up to an hour
    all_ids = [h["hostid"] for h in z.call("host.get", {"filter": {"host": [sw[0] for sw in SWITCHES]}, "output": ["hostid"]})]
    new_ids = [h["hostid"] for h in z.call("host.get", {"filter": {"host": created}, "output": ["hostid"]})] if created else []
    rules = z.call("discoveryrule.get", {"hostids": new_ids, "output": ["itemid"]}) if new_ids else []
    rules += z.call("discoveryrule.get", {"hostids": all_ids, "output": ["itemid"],
                                          "filter": {"name": ["Network interfaces discovery"]}})
    if rules:
        z.call("task.create", [{"type": 6, "request": {"itemid": r["itemid"]}} for r in rules])
    print(f"created {created or 'nothing new'}; ran {len(rules)} discovery rules now")


if __name__ == "__main__":
    main()
