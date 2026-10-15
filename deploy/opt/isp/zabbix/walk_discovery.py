#!/usr/bin/env python3
"""Convert old-style discovery[] SNMP LLD rules to walk[] + 'SNMP walk to JSON' (idempotent).

discovery[] rules take no per-item timeout, so they are bound to the global SNMP timeout (10 s). On the weak
Huawei S5720-LI CPUs and the HPE 5820 IRF stack every LLD rule of a host fires in the same second and about every
other hour one timed out (log: 'became not supported: Timeout ...'), so new ports / sensors went undiscovered for
hours (fleet audit 2026-10-15). walk[] rules use GETBULK and take a TIMEOUT. The rule keys stay the same, so every
discovered item, trigger and its history is kept; the macros ({#SNMPINDEX} + the named columns) are identical.
Backup of the templates before the change: /opt/isp/backup/templates-huawei-hpe-before-walk-20261015.json
"""
import re

import setup_isp_links as base

TEMPLATES = ["Huawei VRP by SNMP - PIDC", "HPE Comware by SNMP - PIDC"]
TIMEOUT = "15s"
TEXT_COLUMNS = {"1.3.6.1.2.1.31.1.1.1.18", "1.3.6.1.2.1.31.1.1.1.1", "1.3.6.1.2.1.2.2.1.2",   # ifAlias/ifName/ifDescr
                "1.3.6.1.2.1.47.1.1.1.1.2", "1.3.6.1.2.1.47.1.1.1.1.7"}                     # entPhysicalDescr/Name
WALK_TO_JSON = "29"


def convert(z, rule):
    args = [a.strip() for a in re.fullmatch(r"discovery\[(.*)\]", rule["snmp_oid"])[1].split(",")]
    pairs = list(zip(args[::2], args[1::2]))
    params = "\n".join(f"{m}\n{oid}\n{1 if oid in TEXT_COLUMNS else 0}" for m, oid in pairs)
    steps = [{"type": WALK_TO_JSON, "params": params, "error_handler": "0", "error_handler_params": ""}]
    steps += [{k: p[k] for k in ("type", "params", "error_handler", "error_handler_params")} for p in rule["preprocessing"]]
    z.call("discoveryrule.update", {"itemid": rule["itemid"], "snmp_oid": "walk[" + ",".join(o for _, o in pairs) + "]",
                                    "timeout": TIMEOUT, "preprocessing": steps})


ENT = "1.3.6.1.2.1.47.1.1.1.1"
MODULE_RULE = ("HPE Comware by SNMP - PIDC", "module.discovery")
MODULE_OID = f"walk[{ENT}.2,{ENT}.7,{ENT}.4,{ENT}.5,{ENT}.6]"
# Both IRF members of 10G_Leaf_SW-7-8 call their main board just "Board", so the CPU / memory items, triggers and
# graphs had the same name and LLD refused the second graph ("graph with the same name already exists").
# Names that occur more than once get the IRF member = position of the chassis (entPhysicalClass 3) they sit in.
MODULE_JS = r"""
var rows = JSON.parse(value), byIdx = {}, count = {};
rows.forEach(function (r) { byIdx[r['{#SNMPINDEX}']] = r; count[r['{#MODULE_NAME}']] = (count[r['{#MODULE_NAME}']] || 0) + 1; });
rows.forEach(function (r) {
    if (count[r['{#MODULE_NAME}']] < 2) return;
    for (var p = byIdx[r['{#ENT_PARENT}']], n = 0; p && n < 10; p = byIdx[p['{#ENT_PARENT}']], n++) {
        if (p['{#ENT_CLASS}'] === '3') { r['{#MODULE_NAME}'] += ' (member ' + p['{#ENT_RELPOS}'] + ')'; return; }
    }
    r['{#MODULE_NAME}'] += ' (' + r['{#SNMPINDEX}'] + ')';
});
return JSON.stringify(rows);
"""


def module_names(z):
    tid = z.call("template.get", {"filter": {"host": [MODULE_RULE[0]]}, "output": ["templateid"]})[0]["templateid"]
    r = z.call("discoveryrule.get", {"hostids": tid, "filter": {"key_": MODULE_RULE[1]}, "output": ["itemid", "snmp_oid"]})[0]
    if r["snmp_oid"] == MODULE_OID:
        return
    params = (f"{{#SNMPVALUE}}\n{ENT}.2\n1\n{{#MODULE_NAME}}\n{ENT}.7\n1\n{{#ENT_PARENT}}\n{ENT}.4\n0\n"
              f"{{#ENT_CLASS}}\n{ENT}.5\n0\n{{#ENT_RELPOS}}\n{ENT}.6\n0")
    z.call("discoveryrule.update", {"itemid": r["itemid"], "snmp_oid": MODULE_OID, "timeout": TIMEOUT, "preprocessing": [
        {"type": WALK_TO_JSON, "params": params, "error_handler": "0", "error_handler_params": ""},
        {"type": "21", "params": MODULE_JS.strip(), "error_handler": "0", "error_handler_params": ""}]})
    print(f"{MODULE_RULE[0]}: {MODULE_RULE[1]} names duplicate modules by IRF member")


def main():
    z = base.Zabbix()
    for name in TEMPLATES:
        tid = z.call("template.get", {"filter": {"host": [name]}, "output": ["templateid"]})[0]["templateid"]
        rules = z.call("discoveryrule.get", {"hostids": tid, "output": ["itemid", "key_", "snmp_oid", "templateid"],
                                             "selectPreprocessing": "extend"})
        for r in rules:
            if r["templateid"] == "0" and r["snmp_oid"].startswith("discovery["):
                convert(z, r)
                print(f"{name}: {r['key_']} -> walk[] ({TIMEOUT})")
    module_names(z)


if __name__ == "__main__":
    main()
