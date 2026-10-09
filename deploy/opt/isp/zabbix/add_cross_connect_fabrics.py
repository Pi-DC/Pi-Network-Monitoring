#!/usr/bin/env python3
"""Add the cross-connect switches (Cisco Catalyst 4500 / 2960 / 2960S / 2960X) to Zabbix, one host group per fabric:
"Pi MMR Cross Connect Fabric" (MMR-1), "Pi DH Cross Connect Fabric" (data hall 5) - Cisco Catalyst - and
"Pi 1G Colo Fabric" (Huawei S5720, template "Huawei VRP by SNMP - PIDC", see add_vmware_fabric.setup_huawei; plus
the Cisco Catalyst 3650 1G-COLO-DH4-SW1, which overrides template and vendor per switch), and the Catalyst 3650
stack 1G-WAN-SW and the Juniper EX3400 1G-WAN-Extension-SW (template "Juniper by SNMP - PIDC") in "WAN Switches"
(next to the Arista 10G pair from add_switches.py).

All use "Cisco Catalyst by SNMP - PIDC" (stock "Cisco IOS by SNMP" copy with 10s traffic walk, Admin status + Port
state, and the vendor-neutral "Health: ..." items; see add_vmware_fabric.py). VLAN SVIs, internal "VLAN-..." and
stack ports are not discovered. At setup the 2960 LAN Lite switches (MMR1_SW1, DH5_SW1) had no temperature sensor
and MMR1-SW5 (2960X) no CISCO-ENVMON fan/PSU entries. SNMP v2c community: /root/.credentials/vmware_fabric_snmp_community (same as the
VMware fabric). Idempotent; then run setup_email_alerts.py and build_fabric_dashboard.py.
Usage: add_cross_connect_fabrics.py [group name ...]   (default: every fabric in FABRICS)
"""
import sys

import add_switches
import add_vmware_fabric as fab
import setup_isp_links as base

FABRICS = {  # host group: ("fabric" tag, [(host, visible name, IP, model[, template, vendor tag])], template, vendor tag
            #              [, role tag - default "cross-connect"])
    "Pi MMR Cross Connect Fabric": ("mmr", [
        ("MMR1_SW1", "MMR1_SW1 (PIDC-MMR-1-Ext-SW1)", "10.128.4.221", "Catalyst 2960"),
        ("MMR1_SW2", "MMR1_SW2 (MMR1-Ext-SW2)", "10.128.4.220", "Catalyst 2960S"),
        ("MMR1_SW3", "MMR1_SW3 (MMR1-Ext-SW3)", "10.128.4.219", "Catalyst 2960S"),
        ("MMR1_SW4", "MMR1_SW4 (PIDC-MMR-1-SW-4)", "10.128.4.216", "Catalyst 4500"),
        ("MMR1-SW5", "MMR1-SW5 (MMR1-Ext-SW5)", "10.128.4.209", "Catalyst 2960X"),
    ], fab.CATALYST, "cisco"),
    "Pi DH Cross Connect Fabric": ("dh5", [
        ("DH5_SW1", "DH5_SW1 (DH5-SW1-100Mb)", "10.128.4.222", "Catalyst 2960"),
        ("DH5_SW2", "DH5_SW2 (DH5-SW2-1G)", "10.128.4.218", "Catalyst 2960S"),
        ("DH5_SW3", "DH5_SW3 (DH5-SW3-1G)", "10.128.4.217", "Catalyst 4500"),
        ("DH5_SW4", "DH5_SW4 (DH5-Ext-SW4)", "172.18.127.207", "Catalyst 4500"),
    ], fab.CATALYST, "cisco"),
    "Pi 1G Colo Fabric": ("1g-colo", [
        ("1G-COLO-DH5-SW1", "1G-COLO-DH5-SW1 (Huawei-1G-Colo-SW1)", "10.128.16.27", "Huawei S5720-28P-PWR-LI-AC"),
        ("1G-COLO-DH5-SW2", "1G-COLO-DH5-SW2 (Huawei-1G-Colo-SW2)", "172.16.132.4", "Huawei S5720-28P-PWR-LI-AC"),
        ("1G-COLO-DH5-SW3", "1G-COLO-DH5-SW3 (Huawei-1G-Colo-SW3)", "172.16.131.33", "Huawei S5720-28X-PWR-LI-AC"),
        ("1G-COLO-DH4-SW1", "1G-COLO-DH4-SW1 (DH4-AD39-Colo-SW1)", "10.128.79.50", "Catalyst 3650-24TS",
         fab.CATALYST, "cisco"),   # IOS-XE 16.12.7, 2x PWR-C2-250WAC
        ("1G-COLO-DH5-SW5", "1G-COLO-DH5-SW5 (1G-COLO-SW-5)", "172.18.127.209", "Catalyst 3650-48FQ",
         fab.CATALYST, "cisco"),   # IOS-XE 16.12.8, 2x PWR-C2-1025WAC
    ], fab.HUAWEI, "huawei"),
    # Joins the Arista 10G pair (add_switches.py); its dashboard page comes from build_switch_dashboard.py
    "WAN Switches": ("wan", [
        ("1G-WAN-SW", "1G-WAN-SW (AMRPiDC-WANSW001)", "10.128.16.21", "Catalyst 3650-24TS-S (3-member stack)"),
        ("1G-WAN-Extension-SW", "1G-WAN-Extension-SW (SNMP-JUN-Switch-Azure)", "10.128.4.197",
         "Juniper EX3400-24T (2-member Virtual Chassis)", fab.JUNIPER, "juniper"),   # Junos 15.1X53-D57.3
    ], fab.CATALYST, "cisco", "wan-switch"),
}


def add_fabric(z, group, fabric, switches, tid, vendor, community, role="cross-connect"):
    found = z.call("hostgroup.get", {"filter": {"name": [group]}, "output": ["groupid"]})
    gid = found[0]["groupid"] if found else z.call("hostgroup.create", {"name": group})["groupids"][0]
    created = []
    for host, name, ip, model, *override in switches:   # override = (template name, vendor tag)
        existing = z.call("host.get", {"filter": {"host": [host]}, "output": ["hostid"],
                                       "selectInterfaces": ["interfaceid", "ip"]})
        if existing:
            if existing[0]["interfaces"][0]["ip"] != ip:
                z.call("hostinterface.update", {"interfaceid": existing[0]["interfaces"][0]["interfaceid"], "ip": ip})
                print(f"{host}: IP -> {ip}")
            add_switches.ensure_macros(z, existing[0]["hostid"])
            continue
        z.call("host.create", {
            "host": host, "name": name, "groups": [{"groupid": gid}],
            "templates": [{"templateid": fab.template_id(z, override[0]) if override else tid}],
            "interfaces": [{"type": 2, "main": 1, "useip": 1, "ip": ip, "dns": "", "port": "161",
                            "details": {"version": 2, "bulk": 1, "community": "{$SNMP_COMMUNITY}"}}],
            "macros": [{"macro": "{$SNMP_COMMUNITY}", "value": community, "type": 1,
                        "description": "Cross-connect SNMP v2c community"},
                       {"macro": "{$NET.IF.IFNAME.NOT_MATCHES}", "value": fab.IFNAME_NOT_MATCHES}] + add_switches.EXTRA_MACROS
                      + fab.VENDOR_MACROS.get(override[1] if override else vendor, []),
            "tags": [{"tag": "role", "value": role}, {"tag": "vendor", "value": override[1] if override else vendor},
                     {"tag": "fabric", "value": fabric}, {"tag": "model", "value": model}],
            "inventory_mode": 1,
        })
        created.append(host)
    hostids = [h["hostid"] for h in z.call("host.get", {"groupids": gid, "output": ["hostid"], "filter": {"status": 0}})]
    rules = z.call("discoveryrule.get", {"hostids": hostids, "output": ["itemid"]}) if hostids else []
    if rules:   # discover now instead of within the hour
        z.call("task.create", [{"type": 6, "request": {"itemid": r["itemid"]}} for r in rules])
    print(f"{group}: created {created or 'nothing new'}; ran {len(rules)} discovery rules now")


def main():
    z = base.Zabbix()
    community = base.read(fab.COMMUNITY_FILE)
    fab.setup_catalyst(z)
    fab.setup_huawei(z)
    fab.setup_juniper(z)
    for template in (fab.CATALYST, fab.HUAWEI, fab.JUNIPER):
        fab.health_items(z, template)
    for group in sys.argv[1:] or FABRICS:
        fabric, switches, template, vendor, *role = FABRICS[group]
        add_fabric(z, group, fabric, switches, fab.template_id(z, template), vendor, community, *role)


if __name__ == "__main__":
    main()
