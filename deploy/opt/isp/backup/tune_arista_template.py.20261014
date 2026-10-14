#!/usr/bin/env python3
"""Add per-interface admin status and a combined "Port state" to the "Arista by SNMP - PIDC" template
(tune() also serves other templates whose interface items are plain SNMP gets, e.g. HPE Comware).

Port state = ifOperStatus, except 8 = shutdown when ifAdminStatus is down. A shut-down port reports
ifOperStatus "down" just like a broken link; this keeps the two apart on the dashboards.
Idempotent.
"""
import setup_isp_links as base

TEMPLATE = "Arista by SNMP - PIDC"
ADMIN_KEY = "net.if.adminstatus[ifAdminStatus.{#SNMPINDEX}]"
STATE_KEY = "net.if.portstate[{#SNMPINDEX}]"
OPER_KEY = "net.if.status[ifOperStatus.{#SNMPINDEX}]"
TAGS = [{"tag": "component", "value": "network"}, {"tag": "description", "value": "{#IFALIAS}"},
        {"tag": "interface", "value": "{#IFNAME}"}]


def tune(z, template=TEMPLATE):
    t = z.call("template.get", {"filter": {"host": [template]}, "output": ["templateid"],
                                "selectValueMaps": ["valuemapid", "name"]})[0]
    tid = t["templateid"]
    vmaps = {v["name"]: v["valuemapid"] for v in t["valuemaps"]}
    for name, mappings in (
            ("IF-MIB::ifAdminStatus", [("1", "enabled"), ("2", "shutdown"), ("3", "testing")]),
            ("Port state", [("1", "up"), ("2", "down"), ("3", "testing"), ("4", "unknown"), ("5", "dormant"),
                            ("6", "notPresent"), ("7", "lowerLayerDown"), ("8", "shutdown")])):
        if name not in vmaps:
            vmaps[name] = z.call("valuemap.create", {"hostid": tid, "name": name, "mappings": [
                {"value": v, "newvalue": n} for v, n in mappings]})["valuemapids"][0]

    rule = z.call("discoveryrule.get", {"templateids": tid, "filter": {"name": ["Network interfaces discovery"]},
                                        "output": ["itemid"]})[0]["itemid"]
    have = {p["key_"] for p in z.call("itemprototype.get", {"discoveryids": rule, "output": ["key_"]})}
    created = []
    if ADMIN_KEY not in have:
        z.call("itemprototype.create", {
            "hostid": tid, "ruleid": rule, "type": 20, "key_": ADMIN_KEY, "value_type": 3, "delay": "1m",
            "name": "Interface {#IFNAME}({#IFALIAS}): Admin status", "snmp_oid": "get[1.3.6.1.2.1.2.2.1.7.{#SNMPINDEX}]",
            "valuemapid": vmaps["IF-MIB::ifAdminStatus"], "history": "7d", "trends": "0", "tags": TAGS,
            "preprocessing": base.pp((base.DISCARD_UNCHANGED_HEARTBEAT, "1h"))})
        created.append("Admin status")
    if STATE_KEY not in have:
        z.call("itemprototype.create", {
            "hostid": tid, "ruleid": rule, "type": 15, "key_": STATE_KEY, "value_type": 3, "delay": "30s",
            "name": "Interface {#IFNAME}({#IFALIAS}): Port state",
            # oper status, or 8 when administratively shut down (comparison yields 1/0)
            "params": f"last(//{OPER_KEY})+(last(//{ADMIN_KEY})=2)*(8-last(//{OPER_KEY}))",
            "valuemapid": vmaps["Port state"], "history": "90d", "trends": "0", "tags": TAGS,
            "description": "Operational status, except 8 = shutdown (ifAdminStatus down)."})
        created.append("Port state")
    print(f"{template}: added {created or 'nothing new'}")


def main():
    tune(base.Zabbix())


if __name__ == "__main__":
    main()
