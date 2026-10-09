#!/usr/bin/env python3
"""Default CPU / memory alert thresholds for every device: CPU 75 %, memory 85 % (user request 2026-10-09).

- Global macros {$CPU.UTIL.CRIT} / {$MEMORY.UTIL.MAX} (used by templates that do not set their own).
- Every template linked to a host, plus every "... - PIDC" template, that sets either macro itself (stock
  templates ship 90) is set to the same value - template macros override global ones.
- The A10's own macros {$A10.CPU.HIGH} / {$A10.MEM.HIGH} (add_health_and_drop_alerts.py).
Host-level macros are left alone: they are deliberate per-device exceptions (e.g. 100G_Leaf_SW-1/2 memory 99 %).
Run hourly from /etc/cron.d/zabbix-default-thresholds so new devices and templates pick it up. Prints only changes.
"""
import setup_isp_links as base

CPU, MEMORY = "75", "85"
TEMPLATE_MACROS = {"{$CPU.UTIL.CRIT}": CPU, "{$MEMORY.UTIL.MAX}": MEMORY}
A10_MACROS = {"{$A10.CPU.HIGH}": CPU, "{$A10.MEM.HIGH}": MEMORY}
DESC = "Default alert threshold (set_default_thresholds.py)"


def main():
    z = base.Zabbix()
    have = {m["macro"]: m for m in z.call("usermacro.get", {"globalmacro": True, "output": ["globalmacroid", "macro", "value"]})}
    for macro, value in TEMPLATE_MACROS.items():
        if macro not in have:
            z.call("usermacro.createglobal", {"macro": macro, "value": value, "description": DESC})
            print(f"global {macro} = {value} (new)")
        elif have[macro]["value"] != value:
            z.call("usermacro.updateglobal", {"globalmacroid": have[macro]["globalmacroid"], "value": value})
            print(f"global {macro}: {have[macro]['value']} -> {value}")

    templates = {t["templateid"]: t["host"] for h in z.call("host.get", {"output": ["hostid"],
                                                                       "selectParentTemplates": ["templateid", "host"]})
                 for t in h["parentTemplates"]}
    templates |= {t["templateid"]: t["host"] for t in z.call("template.get", {"output": ["host"],
                                                                            "search": {"host": "- PIDC"}})}
    # "hostids" = macros defined on the templates themselves ("templateids" would also return host macros of
    # every host linked to them, i.e. the per-device exceptions)
    for m in z.call("usermacro.get", {"hostids": list(templates), "output": ["hostmacroid", "hostid", "macro", "value"],
                                      "filter": {"macro": list(TEMPLATE_MACROS)}}):
        want = TEMPLATE_MACROS[m["macro"]]
        if m["value"] != want:
            z.call("usermacro.update", {"hostmacroid": m["hostmacroid"], "value": want})
            print(f"template {templates[m['hostid']]}: {m['macro']} {m['value']} -> {want}")

    for m in z.call("usermacro.get", {"output": ["hostmacroid", "macro", "value"], "selectHosts": ["host"],
                                      "filter": {"macro": list(A10_MACROS)}}):
        want = A10_MACROS[m["macro"]]
        if m["hosts"] and m["value"] != want:
            z.call("usermacro.update", {"hostmacroid": m["hostmacroid"], "value": want})
            print(f"host {m['hosts'][0]['host']}: {m['macro']} {m['value']} -> {want}")


if __name__ == "__main__":
    main()
