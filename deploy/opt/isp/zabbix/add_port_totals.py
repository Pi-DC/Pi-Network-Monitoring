#!/usr/bin/env python3
"""Per-device "Ports total: ..." calculated items (sum over every port). Idempotent; re-run after adding a template.

Zabbix SVG graphs plot at most 50 items (SVG_GRAPH_MAX_NUMBER_OF_METRICS) in total, and drop the rest silently:
an "all ports" graph that sums ~50+ port items in the graph itself (aggregation) or draws one line per port lost
ports, and its second / later data sets came out empty (found 2026-10-14: 49 graphs, e.g. 120-port PiSB spines).
These items do the sum on the server instead, so the dashboard graphs use one item per line.

Each total is added to every template that has the matching per-port item prototype (by key), so there are no
totals without data: <key> = sum(last_foreach(//<port key>[*])). Existing items are left as they are.
"""
import setup_isp_links as base

# item key, port item key, item name, units, tag. Errors / discards reuse the "Health: ..., all ports" items that
# add_vmware_fabric.health_items() puts on the fabric templates (same formula); here they are only added where missing.
TOTALS = [("pidc.if.total.in", "net.if.in", "Ports total: bits received", "bps", "network"),
          ("pidc.if.total.out", "net.if.out", "Ports total: bits sent", "bps", "network"),
          ("health.if.in.errors", "net.if.in.errors", "Health: Inbound errors, all ports", "", "health"),
          ("health.if.out.errors", "net.if.out.errors", "Health: Outbound errors, all ports", "", "health"),
          ("health.if.in.discards", "net.if.in.discards", "Health: Inbound discards, all ports", "", "health"),
          ("health.if.out.discards", "net.if.out.discards", "Health: Outbound discards, all ports", "", "health"),
          ("pidc.if.total.bcast", "pidc.if.in.bcast", "Ports total: broadcast received", "", "network"),
          ("pidc.if.total.fcs", "pidc.if.ether.fcs", "Ports total: FCS/CRC errors", "", "network")]
DESCRIPTION = ("Sum of the latest value of every monitored port ({key}[*]), calculated by the Zabbix server "
               "(add_port_totals.py). Dashboard graphs use it because one graph plots at most 50 items.")


def main():
    z = base.Zabbix()
    linked = {t["templateid"] for h in z.call("host.get", {"monitored_hosts": True, "output": ["hostid"],
                                                          "selectParentTemplates": ["templateid"]})
              for t in h["parentTemplates"]}
    # only our own templates: stock ones (e.g. "Linux by Zabbix agent") are replaced on Zabbix upgrades
    templates = [t for t in z.call("template.get", {"templateids": list(linked), "output": ["templateid", "host"]})
                 if t["host"].endswith(" - PIDC")]
    for t in sorted(templates, key=lambda t: t["host"]):
        protos = {p["key_"].split("[")[0] for p in z.call("itemprototype.get", {"templateids": t["templateid"],
                                                                                 "output": ["key_"]})}
        have = {i["key_"] for i in z.call("item.get", {"templateids": t["templateid"], "output": ["key_"],
                                                       "filter": {"key_": [k[0] for k in TOTALS]}})}
        for key, port_key, name, units, tag in TOTALS:
            if port_key not in protos or key in have:
                continue
            z.call("item.create", {"hostid": t["templateid"], "key_": key, "name": name, "type": 15, "value_type": 0,
                                   "delay": "1m", "history": "180d", "trends": "730d", "units": units,
                                   "params": f"sum(last_foreach(//{port_key}[*]))",
                                   "description": DESCRIPTION.format(key=port_key),
                                   "tags": [{"tag": "component", "value": tag}]})
            print(f"{t['host']}: + {name}")


if __name__ == "__main__":
    main()
