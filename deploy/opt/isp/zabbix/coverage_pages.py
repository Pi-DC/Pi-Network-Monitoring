#!/usr/bin/env python3
"""Dashboard pages for the data add_full_coverage.py collects, shared by every switch / router dashboard builder.

  links_page()   "Links, optics & stack": LACP members, optics Rx power, stack / IRF / VC / iStack members and ports,
                 LLDP / CDP neighbours, STP, config / NTP / flash / PoE - maps + click-to-graph lists, related problems
  routing_page() "BGP, VRRP, QoS & IP SLA" (ASR routers): IPv4 + IPv6 BGP sessions, VRRP groups, IP SLA probes,
                 QoS drops per class, IP statistics

Sections are only drawn when one of the dashboard's hosts has that data, so the same call works for every vendor.
"""
import build_dashboard as d
import build_switch_dashboard as sw
import click_to_graph

f, INT, STR, HOSTREF = d.f, d.INT, d.STR, d.HOSTREF
GREEN, AMBER, RED, GREY, SLATE = d.GREEN, d.AMBER, d.RED, sw.GREY, sw.SLATE
TAG_EQUAL, EVAL_OR = 1, 2

LACP_TH = ((0, RED), (1, GREEN))
# Rough colour guide only (dark port ~-40 dBm); alerts use each module's own thresholds and only while the port is up.
RX_TH = ((-100, SLATE), (-30, RED), (-14, AMBER), (-10, GREEN))
STACK_TH = ((1, GREEN), (2, RED), (3, AMBER))          # stack / IRF / VC / iStack port and member: 1 = up
CISCO_STACK_TH = ((1, AMBER), (4, GREEN), (5, RED))    # cswSwitchState: 4 = ready
VRRP_TH = ((1, RED), (2, "7FB0EB"), (3, GREEN))        # initialize / backup / master
SLA_TH = ((0, AMBER), (1, GREEN), (2, RED))            # rttMonLatestRttOperSense: 1 = ok
BGP_TH = ((0, SLATE), (1, RED), (2, AMBER), (6, GREEN))
# Item navigators feed a follow graph, which graphs the first item on load: a text item there (LLDP neighbour name,
# BGP last error ...) can never be drawn and the dashboard PDF print view then times out. So list numeric items only.
NEIGHBOUR_NUMERIC = ["LLDP neighbours", "LACP *", "STP: topology changes*", "STP: time since*", "STP: root port",
                     "Stack *", "IRF *", "Virtual Chassis *", "iStack *"]
OTHER_NUMERIC = ["Optics *", "Config: running config*", "Config: startup config*", "Config: change counter",
                 "Config: commit counter", "NTP: *", "Flash *", "Storage *", "PoE *", "Hardware alarms*"]
BGP_NUMERIC = ["BGP * peer *: " + s for s in ("Session state", "State", "Admin status", "Flaps*", "Hold time*",
                                              "Messages*", "Prefixes*", "Time*", "UPDATEs*")]
LINK_COMPONENTS = ["lacp", "optics", "stack", "neighbours", "stp", "config", "ntp", "storage", "poe", "hardware"]
ROUTING_COMPONENTS = ["bgp", "vrrp", "ipsla", "qos", "ip", "routing"]
PALETTE = ["2563EB", "E5484D", "2E9E5B", "F59E0B", "7C3AED", "0EA5E9", "DB2777", "65A30D", "EA580C", "475569"] * 3


def label(regex, out):
    return '{{ITEM.NAME}.regsub("' + regex + '", "' + out + '")}'


def hosts_fields(hostids):
    return [f(HOSTREF, f"hostids.{i}", h) for i, h in enumerate(hostids)]


def hmap(name, x, y, w, h, hostids, patterns, primary, th, ref, multi):
    """Honeycomb over several hosts: primary label = port / peer, secondary = switch name when there are several."""
    fields = hosts_fields(hostids) + [f(STR, f"items.{i}", p) for i, p in enumerate(patterns)]
    fields += [f(INT, "show.0", 1), f(INT, "show.1", 2), f(INT, "primary_label_type", 0), f(STR, "primary_label", primary),
               f(INT, "primary_label_size_type", 0), f(INT, "primary_label_bold", 1), f(INT, "rf_rate", 30),
               f(STR, "reference", ref)]
    fields += ([f(INT, "secondary_label_type", 0), f(STR, "secondary_label", "{HOST.NAME}")] if multi else
               [f(INT, "secondary_label_type", 1), f(INT, "secondary_label_decimal_places", 0)])
    return d.widget("honeycomb", name, x, y, w, h, fields + d.thresholds(*th))


def nav(name, x, y, w, h, hostids, patterns, components, ref, lines=1000):
    """Item navigator grouped by host, then by component tag; `components` limits it to those tag values."""
    fields = hosts_fields(hostids) + [f(STR, f"items.{i}", p) for i, p in enumerate(patterns)]
    for i, c in enumerate(components):
        fields += [f(STR, f"item_tags.{i}.tag", "component"), f(INT, f"item_tags.{i}.operator", TAG_EQUAL),
                   f(STR, f"item_tags.{i}.value", c)]
    fields += [f(INT, "item_tags_evaltype", EVAL_OR), f(INT, "group_by.0.attribute", 1),
               f(INT, "group_by.1.attribute", 3), f(STR, "group_by.1.tag_name", "component"),
               f(INT, "show_lines", lines), f(INT, "rf_rate", 60), f(STR, "reference", ref)]
    return d.widget("itemnavigator", name, x, y, w, h, fields)


def problems(name, x, y, w, h, hostids, components):
    fields = hosts_fields(hostids)
    for i, c in enumerate(components):
        fields += [f(STR, f"tags.{i}.tag", "component"), f(INT, f"tags.{i}.operator", TAG_EQUAL), f(STR, f"tags.{i}.value", c)]
    fields += [f(INT, "evaltype", EVAL_OR), f(INT, "show", 1), f(INT, "show_lines", 25), f(INT, "sort_triggers", 4),
               f(INT, "show_timeline", 0), f(INT, "rf_rate", 30)]
    return d.widget("problems", name, x, y, w, h, fields)


def count(z, hostids, pattern):
    return int(z.call("item.get", {"hostids": hostids, "search": {"name": pattern}, "searchWildcardsEnabled": True,
                                   "filter": {"status": 0}, "countOutput": True}))


def map_height(cells, w, lo=4, hi=8):
    return sw.map_rows(cells, w, lo, hi)


def links_page(z, hosts, page_no, title="Links, optics & stack"):
    """LACP / optics / stack / neighbours / STP page for switches (host dicts with hostid + name), or None when they
    have none of it."""
    hostids, names = [h["hostid"] for h in hosts], [h["name"] for h in hosts]
    multi = len(hostids) > 1
    ref = lambda p: sw.page_ref(p, page_no)
    w, y = [], 0
    pairs = []   # (map widget, its follow graph title)
    n_lacp = count(z, hostids, "LACP *: Bundled")
    if n_lacp:
        pairs.append((["LACP *: Bundled"], label("^LACP ([^ ]+) in ([^:]+):.*", "\\1 > \\2"), LACP_TH, n_lacp,
                      "LACP members (green bundled / red configured but not bundled) - click one", "XLA"))
    n_rx = count(z, hostids, "Optics * rx power") + count(z, hostids, "Optics *Receive Power Sensor")
    if n_rx:
        pairs.append((["Optics * rx power", "Optics *Receive Power Sensor"], label("^Optics ([^ ]+) .*", "\\1"), RX_TH, n_rx,
                      "Optics receive power, dBm (grey no light, red < -30, amber < -14) - click one", "XOP"))
    stack_pats = ["Stack port *: status", "IRF member *: status", "Virtual Chassis port *: status", "iStack port *: status"]
    n_stack = sum(count(z, hostids, p) for p in stack_pats)
    if n_stack:
        pairs.append((stack_pats, label("^(Stack port|IRF member|Virtual Chassis port|iStack port) ([^:]+):.*", "\\2"),
                      STACK_TH, n_stack, "Stack / IRF / Virtual Chassis ports (green up / red down) - click one", "XSP"))
    n_cstack = count(z, hostids, "Stack member *: state")
    if n_cstack:
        pairs.append((["Stack member *: state"], label("^Stack member ([^:]+):.*", "member \\1"), CISCO_STACK_TH, n_cstack,
                      "Stack members (green ready) - click one", "XSM"))
    if not pairs and not count(z, hostids, "LLDP neighbours"):
        return None

    # maps two per row (full width when alone, or when half width cannot keep the labels readable - Zabbix then
    # draws colours only, e.g. 180 optics on the VMware fabric), each with the graph of its clicked cell below
    rows, half = [], [p for p in pairs if sw.label_room(p[3], 36, 8) >= sw.LABEL_PX]
    for p in pairs:
        if p not in half:
            rows.append([p])
    rows += [half[i:i + 2] for i in range(0, len(half), 2)]
    for row in rows:
        width = 72 // len(row)
        mh = max(map_height(p[3], width, hi=8 if width < 72 else 12) for p in row)
        for j, (pats, lab, th, n, name, prefix) in enumerate(row):
            r = ref(prefix)
            w.append(hmap(name, j * width, y, width, mh, hostids, pats, lab, th, r, multi))
            w.append(sw.follow_graph("History of the cell clicked above", j * width, y + mh, width, 4, r))
        y += mh + 4

    w.append(problems("Link, optics, stack, STP, neighbour, config problems", 0, y, 72, 4, hostids, LINK_COMPONENTS))
    y += 4
    nr = ref("XNB")
    w.append(nav("Neighbour count (LLDP), LACP, STP, stack - click an item to graph it", 0, y, 36, 12, hostids,
                 NEIGHBOUR_NUMERIC, ["neighbours", "lacp", "stp", "stack"], nr))
    w.append(sw.follow_graph("Graph of the item selected on the left", 36, y, 36, 12, nr))
    y += 12
    orf = ref("XOT")
    w.append(nav("Optics (power + port link), config, NTP, flash / storage, PoE, alarms - click an item to graph it",
                 0, y, 36, 12, hostids, OTHER_NUMERIC, ["optics", "config", "ntp", "storage", "poe", "hardware"], orf))
    w.append(sw.follow_graph("Graph of the item selected on the left", 36, y, 36, 12, orf))
    y += 12
    if count(z, hostids, "Interface *: Broadcast received*"):
        w.append(sw.svg("Broadcast packets received per second, all ports (one line per switch)", 0, y, 36, 5, names, [
            {"items": ["Ports total: broadcast received"], "hosts": [n], "color": c, "label": n}
            for n, c in zip(names, PALETTE)], legend_lines=min(10, len(names))))
        w.append(sw.svg("FCS / CRC errors per 5 min, all ports (one line per switch)", 36, y, 36, 5, names, [
            {"items": ["Ports total: FCS/CRC errors"], "hosts": [n], "color": c, "label": n}
            for n, c in zip(names, PALETTE)], legend_lines=min(10, len(names))))
        y += 5
    if y > 64:   # dashboard grid limit: drop the lowest widgets rather than fail
        w = [x for x in w if x["y"] + x["height"] <= 64]
    return {"name": title, "widgets": w}


def routing_page(z, host, short, page_no):
    """BGP (IPv4 + IPv6), VRRP, IP SLA, QoS, IP statistics for one router (host dict with hostid + name)."""
    ref = lambda p: sw.page_ref(p, page_no)
    me, ids = [host["name"]], [host["hostid"]]
    w = [
        hmap("BGP sessions IPv4 + IPv6 (green established / amber connecting / red down / grey shut down) - click one",
             0, 0, 36, 5, ids, ["BGP * peer *: Session state"],
             label("^BGP (.+) (IPv.) peer ([^ ]+) .*", "\\1 \\2 \\3"), BGP_TH, ref("XBS"), False),
        sw.follow_graph("Session state of the peer clicked on the left (6 established, 0 shut down)", 36, 0, 36, 5,
                        ref("XBS")),
        nav("BGP per peer: state, last error, prefixes accepted / denied / advertised, UPDATEs, flaps - click to graph",
            0, 5, 36, 14, ids, BGP_NUMERIC, ["bgp"], ref("XBN")),
        sw.follow_graph("Graph of the BGP item selected on the left", 36, 5, 36, 7, ref("XBN")),
        sw.svg("Prefixes accepted per peer", 36, 12, 36, 7, me, [
            {"items": ["BGP * peer *: Prefixes accepted"], "color": "2563EB", "label": "accepted"}],
            legend_lines=10),
    ]
    y = 19
    if count(z, ids, "VRRP group *: state"):
        w += [hmap("VRRP groups (green master / blue backup / red initialize) - click one", 0, y, 36, 4, ids,
                   ["VRRP group *: state"], label("^VRRP group ([^:]+):.*", "\\1"), VRRP_TH, ref("XVR"), False),
              sw.follow_graph("State of the VRRP group clicked on the left (3 master, 2 backup, 1 init)", 36, y, 36, 4,
                              ref("XVR"))]
        y += 4
    if count(z, ids, "IP SLA *: result"):
        w += [hmap("IP SLA probes (green ok / red timeout or failure) - click one", 0, y, 36, 4, ids,
                   ["IP SLA *: result"], label("^IP SLA ([0-9]+) [^ ]+ to ([^:]+):.*", "\\1 > \\2"), SLA_TH,
                   ref("XSL"), False),
              sw.svg("IP SLA round-trip time", 36, y, 36, 4, me, [
                  {"items": ["IP SLA *: round-trip time"], "color": "0EA5E9", "label": "RTT"}])]
        y += 4
    if count(z, ids, "QoS *: dropped"):   # ~1000 class counters: too many for one graph, so list + click-to-graph
        w += [nav("QoS per interface / class: offered, delivered, dropped (bits/s) - click to graph", 0, y, 36, 10, ids,
                  ["QoS *"], ["qos"], ref("XQS"), lines=1000),
              sw.follow_graph("Graph of the QoS item selected on the left", 36, y, 36, 10, ref("XQS"))]
        y += 10
    w.append(sw.svg("IPv4 / IPv6 packets forwarded per second", 0, y, 36, 5, me, [
        {"items": ["IPv4: packets forwarded per second"], "color": "2E9E5B", "label": "IPv4"},
        {"items": ["IPv6: packets forwarded per second"], "color": "7C3AED", "label": "IPv6"}]))
    w.append(sw.svg("Dropped: no route / header errors / discards per second", 36, y, 36, 5, me, [
        {"items": ["IPv*: dropped, no route per second"], "color": RED, "label": "no route", "agg": 5},
        {"items": ["IPv*: header errors per second"], "color": AMBER, "label": "header errors", "agg": 5},
        {"items": ["IPv*: input discards per second"], "color": "7C3AED", "label": "in discards", "agg": 5},
        {"items": ["IPv*: output discards per second"], "color": "0EA5E9", "label": "out discards", "agg": 5}]))
    y += 5
    w.append(problems(f"{short}: BGP, VRRP, IP SLA, QoS problems", 0, y, 72, min(6, 64 - y), ids, ROUTING_COMPONENTS))
    return {"name": f"{short}: BGP, VRRP, QoS & IP SLA", "widgets": w}
