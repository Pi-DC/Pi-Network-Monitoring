#!/usr/bin/env python3
"""Add the Pi VMware fabric switches (100G spines and leaves, mixed vendors) to Zabbix, group "Pi VMware Fabric".

  Arista (spines DCS-7280CR-48, leaves 1/2 DCS-7050SX3-48YC12, leaves 5/6 DCS-7150S-24) -> "Arista by SNMP - PIDC"
  HPE 5820AF-24XG Comware (leaf 7&8)                     -> "HPE Comware by SNMP - PIDC" = copy of stock
        "HP Comware HH3C by SNMP": traffic 10s, status 30s, errors/discards 1m (counters refresh every 1s),
        per-interface Admin status + Port state (tune_arista_template.tune)
  Cisco Catalyst (none in the fabric now; kept for later) -> "Cisco Catalyst by SNMP - PIDC" = copy of stock
        "Cisco IOS by SNMP" with the ASR920 interface tuning (add_routers.tune_interfaces: 10s traffic walk,
        30s status walk, Admin status + Port state); CISCO-ENVMON-MIB temperature/fan/PSU is supported here
Switches that answer neither ping nor SNMP from this server (leaf 3&4 at setup) are created disabled
with only the ICMP template; set their template and enable them once they are reachable.
SNMP v2c community: /root/.credentials/vmware_fabric_snmp_community. Idempotent. Then run setup_email_alerts.py
(group is in its alert action) and build_switch_dashboard.py (dashboard "Pi VMware Fabric").
"""
import add_routers
import add_switches
import setup_isp_links as base
import tune_arista_template

GROUP = "Pi VMware Fabric"
COMMUNITY_FILE = "/root/.credentials/vmware_fabric_snmp_community"
ARISTA = "Arista by SNMP - PIDC"
COMWARE, COMWARE_SRC = "HPE Comware by SNMP - PIDC", "HP Comware HH3C by SNMP"
CATALYST, CATALYST_SRC = "Cisco Catalyst by SNMP - PIDC", "Cisco IOS by SNMP"
HUAWEI, HUAWEI_SRC = "Huawei VRP by SNMP - PIDC", "Huawei VRP by SNMP"   # S5720 (1G colo fabric)
ICMP_ONLY = "ICMP Ping"
SWITCHES = [  # host, visible name, IP, template, role, vendor, enabled
    ("100G_Spine_SW-1", "100G_Spine_SW-1 (GE35SS01)", "172.20.96.33", ARISTA, "spine", "arista", True),
    ("100G_Spine_SW-2", "100G_Spine_SW-2 (GE35SS02)", "172.20.96.34", ARISTA, "spine", "arista", True),
    ("100G_Leaf_SW-1", "100G_Leaf_SW-1 (GE33LS01)", "172.20.96.19", ARISTA, "leaf", "arista", True),   # DCS-7050SX3-48YC12
    ("100G_Leaf_SW-2", "100G_Leaf_SW-2 (GE33LS02)", "172.20.96.18", ARISTA, "leaf", "arista", True),   # DCS-7050SX3-48YC12
    ("100G_Leaf_SW-3-4", "100G_Leaf_SW-3&4", "172.20.96.16", ICMP_ONLY, "leaf", "unknown", False),
    ("100G_Leaf_SW-5", "100G_Leaf_SW-5 (PiAMRDC-100G-LFSW-05)", "172.20.96.35", ARISTA, "leaf", "arista", True),
    ("100G_Leaf_SW-6", "100G_Leaf_SW-6 (PiAMRDC-100G-LFSW-06)", "172.20.96.36", ARISTA, "leaf", "arista", True),
    ("100G_Leaf_SW-7-8", "100G-Leaf_SW-7&8 (100G-LF-7&8)", "172.20.97.212", COMWARE, "leaf", "hpe", True),
]
# Physical ports and port-channels only: also skip VLAN SVIs (318 on each spine), Cisco internal "VLAN-..." and
# stack ports (no counters).
# Per-host threshold overrides. Leaves 1/2 (7050SX3) run steadily at ~97% RAM (2026-10-09), so the default 90%
# alert fired permanently; 99% still catches real memory exhaustion.
HOST_MACROS = {
    "100G_Leaf_SW-1": {"{$MEMORY.UTIL.MAX}": ("99", "7050SX3 runs at ~97% RAM normally (default 90)")},
    "100G_Leaf_SW-2": {"{$MEMORY.UTIL.MAX}": ("99", "7050SX3 runs at ~97% RAM normally (default 90)")},
}
IFNAME_NOT_MATCHES = (r"(^Software Loopback Interface|^NULL[0-9.]*$|^[Ll]o[0-9.]*$|^[Ss]ystem$|^Nu[0-9.]*$|"
                      r"^veth[0-9a-z]+$|docker[0-9]+|br-[a-z0-9]{12}|^Loopback[0-9]+$|^InLoopBack[0-9]+$|^Vi[0-9]+$|"
                      r"^Vlan[0-9]+$|^Vl[0-9]+$|^VLAN-|^StackPort|^StackSub|^Vlan-interface[0-9]+$|"
                      r"^Vlanif[0-9]+$|^Console|^LoopBack[0-9]+$|^MEth)")   # last line: Huawei
PROTO_DELAYS = {"net.if.in[": "10s", "net.if.out[": "10s", "net.if.status[": "30s", "net.if.in.errors[": "1m",
                "net.if.out.errors[": "1m", "net.if.in.discards[": "1m", "net.if.out.discards[": "1m",
                "net.if.speed[": "5m", "net.if.type[": "1h"}


# Same-named calculated items on every vendor template, so one dashboard table / tile set fits all switches.
# (fan / PSU "OK" values: Arista entPhySensorOperStatus 1 / entStateOper 3, Cisco ENVMON 1 / 1, HPE HH3C 2 / 2)
HEALTH = {
    ARISTA: {"cpu": "last(//system.cpu.util)", "mem": "last(//vm.memory.util[memoryUsedPercentage.1])",
             "fan_ok": 1, "psu_ok": 3},
    CATALYST: {"cpu": "max(last_foreach(//system.cpu.util[*]))", "mem": "max(last_foreach(//vm.memory.util[*]))",
               "fan_ok": 1, "psu_ok": 1, "absent": 5},   # CISCO-ENVMON 5 = notPresent (empty slot): not a fault
    COMWARE: {"cpu": "max(last_foreach(//system.cpu.util[*]))", "mem": "max(last_foreach(//vm.memory.util[*]))",
              "fan_ok": 2, "psu_ok": 2},
    # hwEntityFanState 1 = normal; S5720-LI reports no PSU table (count stays 0)
    HUAWEI: {"cpu": "max(last_foreach(//system.cpu.util[*]))", "mem": "max(last_foreach(//vm.memory.util[*]))",
             "fan_ok": 1, "psu_ok": 1},
}


def not_ok(key, h, ok):
    """Calculated-item formula: number of `key` items not in the OK state (empty slots excluded where known)."""
    f = f'count(last_foreach(//{key}[*]),"ne",{ok})'
    return f + (f'-count(last_foreach(//{key}[*]),"eq",{h["absent"]})' if "absent" in h else "")


def health_items(z, template):
    h = HEALTH[template]
    tid = template_id(z, template)
    tags = [{"tag": "component", "value": "health"}]
    for key, name, params, units, value_type in (
            ("health.cpu", "Health: CPU utilization", h["cpu"], "%", 0),
            ("health.memory", "Health: Memory utilization", h["mem"], "%", 0),
            ("health.temp.max", "Health: Highest temperature", "max(last_foreach(//sensor.temp.value[*]))", "°C", 0),
            ("health.fans.bad", "Health: Fans not OK", not_ok("sensor.fan.status", h, h["fan_ok"]), "", 3),
            ("health.psu.bad", "Health: Power supplies not OK", not_ok("sensor.psu.status", h, h["psu_ok"]), "", 3),
            # all-port totals (a graph widget cannot sum more than ~100 items itself)
            ("health.if.in.errors", "Health: Inbound errors, all ports", "sum(last_foreach(//net.if.in.errors[*]))", "", 0),
            ("health.if.out.errors", "Health: Outbound errors, all ports", "sum(last_foreach(//net.if.out.errors[*]))", "", 0),
            ("health.if.in.discards", "Health: Inbound discards, all ports", "sum(last_foreach(//net.if.in.discards[*]))", "", 0),
            ("health.if.out.discards", "Health: Outbound discards, all ports", "sum(last_foreach(//net.if.out.discards[*]))", "", 0)):
        itemid = add_routers.ensure_item(z, tid, key, name=name, type=add_routers.CALCULATED, params=params, delay="1m",
                                         units=units, value_type=value_type, tags=tags,
                                         description="Common health figure for the fabric dashboards (add_vmware_fabric.py).")
        if z.call("item.get", {"itemids": itemid, "output": ["params"]})[0]["params"] != params:   # formula changed
            z.call("item.update", {"itemid": itemid, "params": params})


def ensure_host_macros(z, host, hostid):
    have = {m["macro"]: m for m in z.call("usermacro.get", {"hostids": hostid, "output": ["hostmacroid", "macro", "value"]})}
    for macro, (value, desc) in HOST_MACROS.get(host, {}).items():
        if macro not in have:
            z.call("usermacro.create", {"hostid": hostid, "macro": macro, "value": value, "description": desc})
        elif have[macro]["value"] != value:
            z.call("usermacro.update", {"hostmacroid": have[macro]["hostmacroid"], "value": value, "description": desc})


def template_id(z, name):
    return z.call("template.get", {"filter": {"host": [name]}, "output": ["templateid"]})[0]["templateid"]


def setup_snmp_get_template(z, source, template, description):
    """Copy a template whose interface items are plain SNMP gets (HPE Comware, Huawei VRP) and tune it:
    traffic 10s, status 30s, errors 1m (PROTO_DELAYS), Admin status + Port state."""
    add_routers.clone_template(z, source, template, description)
    tid = template_id(z, template)
    rule = z.call("discoveryrule.get", {"templateids": tid, "filter": {"key_": "net.if.discovery"},
                                        "output": ["itemid"]})[0]["itemid"]
    for p in z.call("itemprototype.get", {"discoveryids": rule, "output": ["key_", "delay"]}):
        want = next((d for k, d in PROTO_DELAYS.items() if p["key_"].startswith(k)), None)
        if want and p["delay"] != want:
            z.call("itemprototype.update", {"itemid": p["itemid"], "delay": want})
    tune_arista_template.tune(z, template)


def setup_comware(z):
    setup_snmp_get_template(z, COMWARE_SRC, COMWARE, (
        "PIDC copy of 'HP Comware HH3C by SNMP' for HPE 5820 (Comware 5): traffic 10s, status 30s, errors 1m, "
        "Admin status + Port state. Managed by /opt/isp/zabbix/add_vmware_fabric.py."))


def setup_huawei(z):
    setup_snmp_get_template(z, HUAWEI_SRC, HUAWEI, (
        "PIDC copy of 'Huawei VRP by SNMP' for S5720: traffic 10s, status 30s, errors 1m, Admin status + Port state. "
        "Managed by /opt/isp/zabbix/add_vmware_fabric.py / add_cross_connect_fabrics.py."))


def setup_catalyst(z):
    add_routers.clone_template(z, CATALYST_SRC, CATALYST, (
        "PIDC copy of 'Cisco IOS by SNMP' for Catalyst switches: 10s interface traffic walk, 30s status walk, "
        "Admin status + Port state. Managed by /opt/isp/zabbix/add_vmware_fabric.py."))
    add_routers.tune_interfaces(z, template_id(z, CATALYST))


def main():
    z = base.Zabbix()
    community = base.read(COMMUNITY_FILE)
    setup_comware(z)
    setup_catalyst(z)
    for template in HEALTH:
        health_items(z, template)
    found = z.call("hostgroup.get", {"filter": {"name": [GROUP]}, "output": ["groupid"]})
    gid = found[0]["groupid"] if found else z.call("hostgroup.create", {"name": GROUP})["groupids"][0]
    created = []
    for host, name, ip, template, role, vendor, enabled in SWITCHES:
        existing = z.call("host.get", {"filter": {"host": [host]}, "output": ["hostid"],
                                       "selectInterfaces": ["interfaceid", "ip"]})
        if existing and existing[0]["interfaces"] and existing[0]["interfaces"][0]["ip"] != ip:   # management IP changed
            z.call("hostinterface.update", {"interfaceid": existing[0]["interfaces"][0]["interfaceid"], "ip": ip})
            print(f"{host}: IP -> {ip}")
        if existing:
            add_switches.ensure_macros(z, existing[0]["hostid"])
            ifname = z.call("usermacro.get", {"hostids": existing[0]["hostid"], "output": ["hostmacroid", "value"],
                                              "filter": {"macro": "{$NET.IF.IFNAME.NOT_MATCHES}"}})
            if ifname and ifname[0]["value"] != IFNAME_NOT_MATCHES:
                z.call("usermacro.update", {"hostmacroid": ifname[0]["hostmacroid"], "value": IFNAME_NOT_MATCHES})
            continue
        z.call("host.create", {
            "host": host, "name": name, "groups": [{"groupid": gid}], "status": 0 if enabled else 1,
            "templates": [{"templateid": template_id(z, template)}],
            "interfaces": [{"type": 2, "main": 1, "useip": 1, "ip": ip, "dns": "", "port": "161",
                            "details": {"version": 2, "bulk": 1, "community": "{$SNMP_COMMUNITY}"}}],
            "macros": [{"macro": "{$SNMP_COMMUNITY}", "value": community, "type": 1,
                        "description": "Pi VMware fabric SNMP v2c community"},
                       {"macro": "{$NET.IF.IFNAME.NOT_MATCHES}", "value": IFNAME_NOT_MATCHES}] + add_switches.EXTRA_MACROS,
            "tags": [{"tag": "role", "value": role}, {"tag": "vendor", "value": vendor},
                     {"tag": "fabric", "value": "vmware"}],
            "inventory_mode": 1,
            "description": "" if enabled else "Not reachable by ping or SNMP from the monitoring server when added "
                                              "(2026-10-09): disabled. Link the right template and enable when reachable.",
        })
        created.append(host)
    for host, *_ in SWITCHES:
        found = z.call("host.get", {"filter": {"host": [host]}, "output": ["hostid"]})
        if found:
            ensure_host_macros(z, host, found[0]["hostid"])
    hostids = [h["hostid"] for h in z.call("host.get", {"groupids": gid, "output": ["hostid"],
                                                        "filter": {"status": 0}})]
    rules = z.call("discoveryrule.get", {"hostids": hostids, "output": ["itemid"]}) if hostids else []
    if rules:   # discover now instead of within the hour
        z.call("task.create", [{"type": 6, "request": {"itemid": r["itemid"]}} for r in rules])
    print(f"created {created or 'nothing new'}; ran {len(rules)} discovery rules now")


if __name__ == "__main__":
    main()
