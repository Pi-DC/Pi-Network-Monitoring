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
JUNIPER, JUNIPER_SRC = "Juniper by SNMP - PIDC", "Juniper by SNMP"   # EX3400 (1G-WAN-Extension-SW)
# Per-vendor host macros added at host creation. Junos lists many internal and logical interfaces (ge-0/0/0.0,
# irb, pfe-, vcp-, bme0 ...): discover physical ports, ae bundles and the me0 management port only.
VENDOR_MACROS = {
    "juniper": [{"macro": "{$NET.IF.IFNAME.MATCHES}", "value": r"^((ge|xe|et|mge)-[0-9]+/[0-9]+/[0-9]+|ae[0-9]+|me0)$",
                 "description": "Physical ports, ae bundles and me0 only (no logical units or internal interfaces)"}],
}
ICMP_ONLY = "ICMP Ping"
SWITCHES = [  # host, visible name, IP, template, role, vendor, enabled
    ("100G_Spine_SW-1", "100G_Spine_SW-1 (GE35SS01)", "172.20.96.33", ARISTA, "spine", "arista", True),
    ("100G_Spine_SW-2", "100G_Spine_SW-2 (GE35SS02)", "172.20.96.34", ARISTA, "spine", "arista", True),
    ("100G_Leaf_SW-1", "100G_Leaf_SW-1 (GE33LS01)", "172.20.96.19", ARISTA, "leaf", "arista", True),   # DCS-7050SX3-48YC12
    ("100G_Leaf_SW-2", "100G_Leaf_SW-2 (GE33LS02)", "172.20.96.18", ARISTA, "leaf", "arista", True),   # DCS-7050SX3-48YC12
    ("100G_Leaf_SW-3-4", "100G_Leaf_SW-3&4 (100G-Leaf-3 & Leaf-4)", "172.20.96.16", HUAWEI, "leaf", "huawei", True),
    # ^ Huawei S6720S-26Q-EI-24S-AC iStack (2 members); unreachable when first added, answered ping/SNMP 2026-10-09
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
    # hwEntityFanState 1 = normal, hwEntityPwrState 1 = supply (add_huawei_psu); S5720-LI reports no PSU table
    # (count stays 0)
    HUAWEI: {"cpu": "max(last_foreach(//system.cpu.util[*]))", "mem": "max(last_foreach(//vm.memory.util[*]))",
             "fan_ok": 1, "psu_ok": 1},
    # jnxOperatingState: 2 running, 3 ready, 5 runningAtFullSpeed, 7 standby are all fine - count 6 = down only
    JUNIPER: {"cpu": "max(last_foreach(//system.cpu.util[*]))", "mem": "max(last_foreach(//vm.memory.util[*]))",
              "fan_bad": 6, "psu_bad": 6},
}


def not_ok(key, h, ok, bad=None):
    """Calculated-item formula: number of `key` items not in the OK state (empty slots excluded where known),
    or - for vendors with several good states - the number in the `bad` state."""
    if bad is not None:
        return f'count(last_foreach(//{key}[*]),"eq",{bad})'
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
            ("health.fans.bad", "Health: Fans not OK", not_ok("sensor.fan.status", h, h.get("fan_ok"), h.get("fan_bad")), "", 3),
            ("health.psu.bad", "Health: Power supplies not OK", not_ok("sensor.psu.status", h, h.get("psu_ok"), h.get("psu_bad")), "", 3),
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
    add_huawei_psu(z, template_id(z, HUAWEI))


# hwPwrStatusTable (HUAWEI-ENTITY-EXTENT-MIB), index <stack member>.<power id>; column 6 = hwEntityPwrState.
# It also lists empty PSU slots (as notSupply), so discovery keeps a row only when ENTITY-MIB names the PSU:
# "POWER Card <member>/PWR<n>", n = rank of the power id within the member (S6720: ids 5, 6 -> PWR1, PWR2).
# If the switch names no PSUs at all, every row is kept.
HUAWEI_PWR_STATE, ENT_NAME = "1.3.6.1.4.1.2011.5.25.31.1.1.18.1.6", "1.3.6.1.2.1.47.1.1.1.1.7"
HUAWEI_PSU_JS = r"""
var rows = {}, named = {}, anyNamed = false, out = [];
value.split('\n').forEach(function (line) {
    var m = line.match(/^\.?1\.3\.6\.1\.4\.1\.2011\.5\.25\.31\.1\.1\.18\.1\.6\.(\d+)\.(\d+) = /);
    if (m) { (rows[m[1]] = rows[m[1]] || []).push(parseInt(m[2], 10)); return; }
    m = line.match(/^\.?1\.3\.6\.1\.2\.1\.47\.1\.1\.1\.1\.7\.\d+ = STRING: "(?:.*\D)?(\d+)\/PWR(\d+)"/);
    if (m) { named[m[1] + '/' + m[2]] = true; anyNamed = true; }
});
Object.keys(rows).forEach(function (slot) {
    rows[slot].sort(function (a, b) { return a - b; }).forEach(function (id, i) {
        if (!anyNamed || named[slot + '/' + (i + 1)])
            out.push({'{#SNMPINDEX}': slot + '.' + id, '{#PSU_NAME}': 'PSU ' + slot + '/PWR' + (i + 1)});
    });
});
return JSON.stringify(out);
"""


def add_huawei_psu(z, tid):
    """Power supply status for Huawei VRP switches with hwPwrStatusTable (e.g. S6720); none on S5720-LI."""
    R = add_routers
    master = R.ensure_item(z, tid, "sensor.psu.walk", name="Huawei VRP: SNMP walk power supply status", type=R.SNMP,
                           snmp_oid=R.walk(HUAWEI_PWR_STATE, ENT_NAME), delay="1m", value_type=R.TEXT, history="0",
                           trends="0", tags=[{"tag": "component", "value": "raw"}])
    vm = R.valuemap(z, tid, "HUAWEI-ENTITY-EXTENT-MIB::hwEntityPwrState",
                    [(1, "supply"), (2, "notSupply"), (3, "sleep"), (4, "unknown")])
    # lost PSUs stay enabled for 7 days, so a pulled PSU (its entity vanishes) still alerts instead of going quiet
    rule = R.ensure_rule(z, tid, "sensor.psu.discovery", name="Power supply discovery", type=R.DEPENDENT,
                         master_itemid=master, lifetime="7d", enabled_lifetime_type=1,
                         preprocessing=R.pp((R.JAVASCRIPT, HUAWEI_PSU_JS.strip()),
                                            (base.DISCARD_UNCHANGED_HEARTBEAT, "1h")))
    key = "sensor.psu.status[hwEntityPwrState.{#SNMPINDEX}]"
    R.ensure_proto(z, tid, rule, key, name="{#PSU_NAME}: Power supply status", type=R.DEPENDENT,
                   master_itemid=master, value_type=R.UINT, valuemapid=vm, history="90d", trends="0",
                   tags=[{"tag": "component", "value": "power"}],
                   preprocessing=R.pp((R.SNMP_WALK_VALUE, f"{HUAWEI_PWR_STATE}.{{#SNMPINDEX}}\n0"),
                                      (base.DISCARD_UNCHANGED_HEARTBEAT, "1h")))
    R.ensure_trigger(z, rule, "{#PSU_NAME}: power supply is not supplying power", priority=3,
                     expression=f"last(/{HUAWEI}/{key})<>1", tags=[{"tag": "scope", "value": "availability"}],
                     comments="hwEntityPwrState is not 'supply': no input power, failed, or removed.")


def setup_juniper(z):
    setup_snmp_get_template(z, JUNIPER_SRC, JUNIPER, (
        "PIDC copy of 'Juniper by SNMP' for EX switches: traffic 10s, status 30s, errors 1m, Admin status + "
        "Port state. Managed by /opt/isp/zabbix/add_vmware_fabric.py / add_cross_connect_fabrics.py."))


def setup_catalyst(z):
    add_routers.clone_template(z, CATALYST_SRC, CATALYST, (
        "PIDC copy of 'Cisco IOS by SNMP' for Catalyst switches: 10s interface traffic walk, 30s status walk, "
        "Admin status + Port state. Managed by /opt/isp/zabbix/add_vmware_fabric.py."))
    add_routers.tune_interfaces(z, template_id(z, CATALYST))


def sync_host(z, hostid, name, template, vendor, enabled):
    """Bring an existing host in line with SWITCHES (e.g. a switch added disabled with ICMP only that is now
    reachable): visible name, template (others cleared - vendor templates carry their own ICMP items), vendor tag,
    enabled state."""
    h = z.call("host.get", {"hostids": hostid, "output": ["name", "status", "description"],
                            "selectParentTemplates": ["templateid", "name"], "selectTags": ["tag", "value"]})[0]
    update = {}
    if h["name"] != name:
        update["name"] = name
    if [t["name"] for t in h["parentTemplates"]] != [template]:
        update["templates"] = [{"templateid": template_id(z, template)}]
        update["templates_clear"] = [{"templateid": t["templateid"]} for t in h["parentTemplates"]
                                     if t["name"] != template]
    tags = [t if t["tag"] != "vendor" else {"tag": "vendor", "value": vendor} for t in h["tags"]]
    if tags != h["tags"]:
        update["tags"] = tags
    if h["status"] != ("0" if enabled else "1"):
        update["status"] = 0 if enabled else 1
        if enabled and h["description"].startswith("Not reachable"):
            update["description"] = ""
    if update:
        z.call("host.update", {"hostid": hostid, **update})
        print(f"{h['name']}: updated {sorted(update)}")


def main():
    z = base.Zabbix()
    community = base.read(COMMUNITY_FILE)
    setup_comware(z)
    setup_catalyst(z)
    setup_huawei(z)
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
            sync_host(z, existing[0]["hostid"], name, template, vendor, enabled)
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
