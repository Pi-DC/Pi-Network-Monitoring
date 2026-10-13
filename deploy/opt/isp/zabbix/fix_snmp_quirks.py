#!/usr/bin/env python3
"""Device quirks found by the fleet audit of 2026-10-13 (idempotent; re-run after re-creating a host):

  - Hardware model / serial: the Catalyst 2960+ (DH5_CC_SW1, MMR1_CC_SW1) report the chassis at entPhysical index
    1001, not 1. The template OIDs use {$ENT.CHASSIS.INDEX} (default 1); those hosts set it to 1001.
  - SNMP timeout: entity / module / duplex discovery timed out at the default 3 s on the stacked 10G_Leaf_SW-3-4
    (Huawei) and 10G_Leaf_SW-7-8 (HPE). Those are old-style discovery[] rules, which take no per-item timeout, so
    the global SNMP agent timeout is 10 s; walk[] discovery rules of the PIDC templates get 15 s.
  - Items the device does not support are disabled on the host only (NOT_SUPPORTED below): broadcast / multicast
    counters of management ports, stack-ring state on standalone switches, BRIDGE-MIB STP on switches running
    per-VLAN STP, counters of the unused half of 2960X dual-purpose uplinks, Zabbix server self-monitoring of
    processes that are not configured (connector, IPMI, Java, VMware, SNMP trapper).
  - Discovery rules the device cannot answer are disabled on the host (RULES_NOT_SUPPORTED): the HPE agent of
    10G_Leaf_SW-7-8 stalls in entPhysicalDescr after 10 rows (>10 s); its temperatures come from the HPE
    entity-extension health items instead.
"""
import setup_isp_links as base

CHASSIS_MACRO = "{$ENT.CHASSIS.INDEX}"
CHASSIS_TEMPLATES = ["Cisco Catalyst by SNMP - PIDC"]
CHASSIS_HOSTS = {"DH5_CC_SW1": "1001", "MMR1_CC_SW1": "1001"}
DISCOVERY_TIMEOUT = "15s"
SNMP_TIMEOUT = "10s"   # global default (Administration > General > Timeouts > SNMP agent)
NOT_SUPPORTED = {   # host -> item keys to disable
    "ASR_RTR-1": ["pidc.if.in.bcast[17]", "pidc.if.in.mcast[17]"],
    "ASR_RTR-2": ["pidc.if.in.bcast[17]", "pidc.if.in.mcast[17]"],
    "1G-Prod-SW": ["pidc.if.in.bcast[1]", "pidc.if.in.mcast[1]"],
    "1G-WAN-SW": ["pidc.if.in.bcast[1]", "pidc.if.in.mcast[1]"],
    "MMR1_CC_SW1": ["pidc.stack.ring"],
    "MMR1_CC_SW4": ["pidc.if.in.bcast[1]", "pidc.if.in.mcast[1]", "pidc.stack.ring"],
    "MMR1_CC_SW5": [f"{k}[{p}{i}]" for i in (10149, 10202) for k, p in (
        ("net.if.in", "ifHCInOctets."), ("net.if.out", "ifHCOutOctets."), ("pidc.if.in.bcast", ""), ("pidc.if.in.mcast", ""))],
    "DH5_CC_SW1": ["pidc.stack.ring"],
    "DH5_CC_SW3": ["pidc.if.in.bcast[1]", "pidc.if.in.mcast[1]", "pidc.stack.ring"],
    "DH5_CC_SW4": ["pidc.if.in.bcast[1]", "pidc.if.in.mcast[1]", "pidc.stack.ring"],
    "1G-COLO-DH4-SW1": ["pidc.if.in.bcast[1]", "pidc.if.in.mcast[1]", "pidc.stp.root", "pidc.stp.rootport",
                        "pidc.stp.since", "pidc.stp.tc"],
    "1G-COLO-DH5-SW5": ["pidc.if.in.bcast[1]", "pidc.if.in.mcast[1]", "pidc.stp.root", "pidc.stp.rootport",
                        "pidc.stp.since", "pidc.stp.tc"],
    "Zabbix server": ["zabbix[connector_queue]", "zabbix[process,connector manager,avg,busy]",
                      "zabbix[process,connector worker,avg,busy]", "zabbix[process,ipmi manager,avg,busy]",
                      "zabbix[process,ipmi poller,avg,busy]", "zabbix[process,java poller,avg,busy]",
                      "zabbix[process,snmp trapper,avg,busy]", "zabbix[process,vmware collector,avg,busy]",
                      "zabbix[vmware,buffer,pused]"],
}


RULES_NOT_SUPPORTED = {"10G_Leaf_SW-7-8": ["temp.discovery"]}


def chassis_index(z):
    for name in CHASSIS_TEMPLATES:
        tid = z.call("template.get", {"filter": {"host": [name]}, "output": ["templateid"]})[0]["templateid"]
        if not z.call("usermacro.get", {"hostids": tid, "filter": {"macro": CHASSIS_MACRO}, "output": ["hostmacroid"]}):
            z.call("usermacro.create", {"hostid": tid, "macro": CHASSIS_MACRO, "value": "1",
                                        "description": "entPhysical index of the chassis (1001 on Catalyst 2960+)"})
        for i in z.call("item.get", {"templateids": tid, "filter": {"key_": ["system.hw.model", "system.hw.serialnumber"]},
                                     "output": ["itemid", "snmp_oid"]}):
            if i["snmp_oid"].endswith(".1]"):
                z.call("item.update", {"itemid": i["itemid"], "snmp_oid": i["snmp_oid"][:-3] + f".{CHASSIS_MACRO}]"})
    for host, idx in CHASSIS_HOSTS.items():
        hid = z.call("host.get", {"filter": {"host": [host]}, "output": ["hostid"]})[0]["hostid"]
        found = z.call("usermacro.get", {"hostids": hid, "filter": {"macro": CHASSIS_MACRO}, "output": ["hostmacroid", "value"]})
        if not found:
            z.call("usermacro.create", {"hostid": hid, "macro": CHASSIS_MACRO, "value": idx})
        elif found[0]["value"] != idx:
            z.call("usermacro.update", {"hostmacroid": found[0]["hostmacroid"], "value": idx})


def discovery_timeouts(z):
    n = 0
    for t in z.call("template.get", {"search": {"host": "- PIDC"}, "output": ["templateid"]}):
        for r in z.call("discoveryrule.get", {"templateids": t["templateid"], "filter": {"type": 20},
                                              "output": ["itemid", "timeout", "snmp_oid"]}):
            if r["snmp_oid"].startswith(("walk[", "get[")) and r["timeout"] != DISCOVERY_TIMEOUT:
                z.call("discoveryrule.update", {"itemid": r["itemid"], "timeout": DISCOVERY_TIMEOUT})
                n += 1
    return n


def disable_unsupported(z):
    n = 0
    for host, keys in NOT_SUPPORTED.items():
        found = z.call("host.get", {"filter": {"host": [host]}, "output": ["hostid"]})
        if not found:
            continue
        for i in z.call("item.get", {"hostids": found[0]["hostid"], "filter": {"key_": keys, "status": 0},
                                     "output": ["itemid"]}):
            z.call("item.update", {"itemid": i["itemid"], "status": 1})
            n += 1
    for host, keys in RULES_NOT_SUPPORTED.items():
        found = z.call("host.get", {"filter": {"host": [host]}, "output": ["hostid"]})
        for r in z.call("discoveryrule.get", {"hostids": found[0]["hostid"], "filter": {"key_": keys, "status": 0},
                                              "output": ["itemid"]}) if found else []:
            z.call("discoveryrule.update", {"itemid": r["itemid"], "status": 1})
            n += 1
    return n


def main():
    z = base.Zabbix()
    chassis_index(z)
    if z.call("settings.get", {"output": ["timeout_snmp_agent"]})["timeout_snmp_agent"] != SNMP_TIMEOUT:
        z.call("settings.update", {"timeout_snmp_agent": SNMP_TIMEOUT})
    print(f"discovery rules set to {DISCOVERY_TIMEOUT}: {discovery_timeouts(z)}; items disabled: {disable_unsupported(z)}")


if __name__ == "__main__":
    main()
