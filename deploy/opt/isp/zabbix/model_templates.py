#!/usr/bin/env python3
"""One template per device model ("<vendor> <model> by SNMP - PIDC"). Idempotent; cron runs it hourly with --apply.

  python3 model_templates.py            show each device's model and the template it would get (changes nothing)
  python3 model_templates.py --apply    create missing model templates, move hosts onto them

Each model template has the vendor template nested in it (the vendor template stays the one place for what all
models of a vendor share) and carries what is particular to the model: {$DEVICE.MODEL} and model-only items
(add_model_items.py). A host is linked to its model template only. The model comes from what the device reports
over SNMP (entPhysicalModelName "Hardware model name" and sysDescr), so a new model gets its own template the first
time a device of that model is added. A device whose model is not recognised stays on its vendor template and is
listed here.

Moving a host keeps every item, discovered item, trigger and their history: Zabbix links the host's existing items
to the new template's (inherited) items by key (tested 2026-10-14 on a copy of a 2960X: 998 items, 929 discovered,
21 rules, 528 triggers - same ids before and after, history kept, rediscovery clean).
"""
import re
import sys

import setup_isp_links as base

SUFFIX = " by SNMP - PIDC"
# vendor template -> [(regex on "chassis model || hardware model || sysDescr", template model name)], first match wins.
# The exact model number the device reports, so e.g. a 7150S-24 and a 7150S-52-CL, or a 2960-Plus LAN Lite and a
# 2960S, never share a template. Only power-supply / airflow suffixes (-AC, -DC) are left out.
RULES = {
    "Arista by SNMP - PIDC": [(r"\b(DCS-[\w-]+)", r"Arista \1")],
    "Cisco Catalyst by SNMP - PIDC": [(r"\b(WS-C[\w+-]+)", r"Cisco Catalyst \1")],
    "Cisco Nexus by SNMP - PIDC": [(r"\b(N\dK-C[\w-]+)", r"Cisco Nexus \1")],
    "FortiGate by SNMP - PIDC": [(r"FortiGate-(\w+)", r"FortiGate \1")],
    "SonicWall by SNMP - PIDC": [(r"\b(NSA|TZ|NSa|SuperMassive) ?(\d{3,5})", r"SonicWall \1 \2")],
    "Huawei VRP by SNMP - PIDC": [(r"\b(S\d{4}S?-[\w-]+?)(?:-AC|-DC)?\s", r"Huawei \1")],
    "HPE Comware by SNMP - PIDC": [(r"HPE? (\d{4}\w*-\w+)", r"HPE \1")],
    "Juniper by SNMP - PIDC": [(r"\b(ex|qfx|mx|srx|acx)(\d{3,4}(?:-\w+)?)", lambda m: f"Juniper {m[1].upper()}{m[2].upper()}")],
    "Generic by SNMP": [(r"Thunder Series", "A10 Thunder")],
    # "Cisco ASR920 by SNMP - PIDC" is already one model (ASR-920-12SZ-IM)
}
# entPhysicalModelName (first non-empty entry = chassis); vendors whose agent has no ENTITY-MIB model names
# (Huawei: empty, Juniper / SonicWall: no such object) are identified from sysDescr instead
CHASSIS_KEY = "pidc.chassis.model"
CHASSIS_TEMPLATES = ["Arista by SNMP - PIDC", "Cisco Catalyst by SNMP - PIDC", "Cisco Nexus by SNMP - PIDC",
                     "HPE Comware by SNMP - PIDC", "Cisco ASR920 by SNMP - PIDC"]
CHASSIS_JS = """var cls = {}, model = {}, order = [];
value.split('\\n').forEach(function (l) {
    var m = l.match(/^\\.?1\\.3\\.6\\.1\\.2\\.1\\.47\\.1\\.1\\.1\\.1\\.(5|13)\\.(\\d+) = \\w+: "?([^"]*)"?$/);
    if (!m) return;
    if (m[1] === '5') cls[m[2]] = m[3]; else { model[m[2]] = m[3].trim(); order.push(m[2]); }
});
// the chassis (class 3); its model can be empty (Catalyst 4948: on the supervisor module, class 9); never a
// power supply (6), fan (7), sensor (8) or port (10)
var by = function (c) { return order.filter(function (i) { return model[i] && c(cls[i]); })[0]; };
var pick = by(function (c) { return c === '3'; }) || by(function (c) { return c === '9'; })
    || by(function (c) { return ['6', '7', '8', '10'].indexOf(c) < 0; });
if (!pick) throw 'no entPhysicalModelName';
return model[pick];"""
CHASSIS_OID = "walk[1.3.6.1.2.1.47.1.1.1.1.5,1.3.6.1.2.1.47.1.1.1.1.13]"   # class (3 = chassis) + model name
MODEL_ITEMS = ["Chassis model", "Hardware model name", "System description"]


def device_model_text(z, hostid):
    its = z.call("item.get", {"hostids": hostid, "output": ["name", "lastvalue"], "filter": {"status": 0},
                              "search": {"name": MODEL_ITEMS}, "searchByAny": True})
    chassis = [i["lastvalue"] for i in its if i["name"] == "Chassis model" and i["lastvalue"]]
    model = [i["lastvalue"] for i in its if i["name"].endswith("Hardware model name") and i["lastvalue"]]
    descr = [i["lastvalue"] for i in its if i["name"] == "System description" and i["lastvalue"]]
    return " || ".join(chassis + model[:3] + descr[:1]) + " "


def ensure_chassis_items(z):
    """"Chassis model" item on the vendor templates whose devices report entPhysicalModelName; returns new item ids
    on hosts (polled at once, so the model is known without waiting an hour)."""
    new = []
    for t in z.call("template.get", {"filter": {"host": CHASSIS_TEMPLATES}, "output": ["templateid", "host"]}):
        have = z.call("item.get", {"templateids": t["templateid"], "filter": {"key_": CHASSIS_KEY},
                                   "output": ["itemid", "snmp_oid"], "inherited": False})
        if have:   # keep the definition current (2026-10-14: the chassis entry, not the first one - a 4948 lists
            if have[0]["snmp_oid"] != CHASSIS_OID:   # its power supply first)
                z.call("item.update", {"itemid": have[0]["itemid"], "snmp_oid": CHASSIS_OID, "preprocessing": [
                    {"type": 21, "params": CHASSIS_JS, "error_handler": 0, "error_handler_params": ""}]})
                print(f"{t['host']}: Chassis model now from the chassis entry")
                new += [i["itemid"] for i in z.call("item.get", {"filter": {"key_": CHASSIS_KEY}, "output": ["itemid"],
                                                                 "templated": False})]
            continue
        z.call("item.create", {"hostid": t["templateid"], "key_": CHASSIS_KEY, "name": "Chassis model", "type": 20,
                               "snmp_oid": CHASSIS_OID, "value_type": 1, "delay": "1h",
                               "history": "90d", "trends": "0", "tags": [{"tag": "component", "value": "system"}],
                               "preprocessing": [{"type": 21, "params": CHASSIS_JS, "error_handler": 0,
                                                  "error_handler_params": ""}],
                               "description": "Chassis model number (ENTITY-MIB entPhysicalModelName of the chassis "
                                              "entry). Picks the model template (model_templates.py)."})
        print(f"{t['host']}: + Chassis model")
        new += [i["itemid"] for i in z.call("item.get", {"filter": {"key_": CHASSIS_KEY}, "output": ["itemid"],
                                                         "templated": False})]
    return new


def model_name(vendor_template, text):
    for rx, name in RULES.get(vendor_template, []):
        m = re.search(rx, text, re.I)
        if m:
            return name(m) if callable(name) else m.expand(name)
    return None


def uses_template(z, parent_templates, name):
    """True if `name` is linked directly or nested in one of the host's templates (for the provisioning scripts)."""
    if name in [t.get("host", t.get("name")) for t in parent_templates]:
        return True
    ids = [t["templateid"] for t in parent_templates]
    return bool(ids) and any(p["host"] == name for t in z.call("template.get", {
        "templateids": ids, "output": ["templateid"], "selectParentTemplates": ["host"]}) for p in t["parentTemplates"])


def technical(name):   # template technical names allow letters, digits, space, '.', '_' and '-' only
    return re.sub(r"[^0-9A-Za-z _.-]", "-", name.replace("+", "-Plus-")).replace("--", "-")


def ensure_template(z, vendor, model):
    name = model + SUFFIX
    found = z.call("template.get", {"filter": {"host": [technical(name)]}, "output": ["templateid"]})
    if found:
        return found[0]["templateid"], False
    v = z.call("template.get", {"filter": {"host": [vendor]}, "output": ["templateid"],
                                "selectTemplateGroups": ["groupid"]})[0]
    tid = z.call("template.create", {
        "host": technical(name), "name": name, "groups": [{"groupid": g["groupid"]} for g in v["templategroups"]],
        "templates": [{"templateid": v["templateid"]}],
        "description": f"Model template for {model} (model_templates.py). Shared {vendor.replace(SUFFIX, '')} "
                       f"monitoring comes from the nested template \"{vendor}\"; model-only items live here.",
        "macros": [{"macro": "{$DEVICE.MODEL}", "value": model, "description": "set by model_templates.py"}],
        "tags": [{"tag": "class", "value": "model"}]})["templateids"][0]
    return tid, True


KEEP_LOST = "30d"   # lost discovered entities: never disabled, deleted after 30 days


def keep_lost_resources(z):
    """Discovery must never silence an alert (user, 2026-10-14: 'do not mute any alerts'). With Zabbix's default
    "disable lost resources: immediately", a dynamic BGP peer that drops or an LLDP neighbour that goes away vanishes
    from the device's table and its alert is disabled at that very moment. So on every discovery rule that applies
    to a monitored device (its templates, nested ones, and host-level rules): never disable lost resources, keep them
    KEEP_LOST (rules that already keep them longer, or forever, are left alone). Returns the number changed."""
    used = {t["templateid"] for h in z.call("host.get", {"output": ["hostid"], "selectParentTemplates": ["templateid"]})
            for t in h["parentTemplates"]}
    while True:   # nested templates, any depth
        more = {p["templateid"] for t in z.call("template.get", {"templateids": list(used), "output": ["templateid"],
                                                                 "selectParentTemplates": ["templateid"]})
                for p in t["parentTemplates"]} - used
        if not more:
            break
        used |= more
    rules = z.call("discoveryrule.get", {"templateids": list(used), "output": ["itemid", "lifetime", "lifetime_type",
                                                                                "enabled_lifetime_type", "templateid"]})
    rules += z.call("discoveryrule.get", {"templated": False, "inherited": False, "output": [
        "itemid", "lifetime", "lifetime_type", "enabled_lifetime_type", "templateid"]})
    days = lambda v: {"s": 1 / 86400, "m": 1 / 1440, "h": 1 / 24, "d": 1, "w": 7}.get(v[-1:], 1 / 86400) * int(v.rstrip("smhdw") or 0)
    n = 0
    for r in {r["itemid"]: r for r in rules if r["templateid"] == "0"}.values():   # own rules; inherited follow
        upd = {}
        if r["enabled_lifetime_type"] != "1":
            upd["enabled_lifetime_type"] = 1
        if r["lifetime_type"] == "0" and days(r["lifetime"]) < days(KEEP_LOST):
            upd["lifetime"] = KEEP_LOST
        if upd:
            z.call("discoveryrule.update", {"itemid": r["itemid"], **upd})
            n += 1
    return n


def main():
    apply = "--apply" in sys.argv
    z = base.Zabbix()
    if apply:
        n = keep_lost_resources(z)
        if n:
            print(f"{n} discovery rules: lost resources now kept enabled ({KEEP_LOST})")
    if apply:
        new = ensure_chassis_items(z)
        if new:   # poll the new items now; hosts without a value yet are moved on a later (hourly) run
            z.call("task.create", [{"type": 6, "request": {"itemid": i}} for i in new])
            print("Chassis model items created - run again in a few minutes to move the hosts")
            return
    unknown = []
    for h in sorted(z.call("host.get", {"output": ["hostid", "host"], "selectParentTemplates": ["templateid", "host"]}),
                    key=lambda h: h["host"]):
        linked = {t["host"]: t["templateid"] for t in h["parentTemplates"]}
        vendors = [v for v in RULES if v in linked]
        if not vendors:
            continue   # already on a model template, or not a network device
        vendor = vendors[0]
        text = device_model_text(z, h["hostid"])
        model = model_name(vendor, text)
        if not model:
            unknown.append((h["host"], vendor, text[:90]))
            continue
        print(f"{h['host']:28} {vendor:30} -> {model + SUFFIX}")
        if apply:
            tid, created = ensure_template(z, vendor, model)
            if created:
                print(f"  + template {model + SUFFIX}")
            keep = [{"templateid": t} for n, t in linked.items() if n != vendor]
            z.call("host.update", {"hostid": h["hostid"], "templates": keep + [{"templateid": tid}]})   # unlink, not clear
    for host, vendor, text in unknown:
        print(f"! {host}: model not recognised for {vendor} ({text or 'no model / sysDescr value yet'}) - stays on it")


if __name__ == "__main__":
    main()
