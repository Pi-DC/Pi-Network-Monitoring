#!/usr/bin/env python3
"""Build the "A10 LLB & ISP Links" Zabbix dashboard (NOC overview + one page per ISP).

Pages for BGP, ports + trunk, SLB and sessions + drops are added when add_a10_full.py has run.
Re-runnable: replaces the pages of the existing "A10 LLB & ISP Links" dashboard in place, so its URL
stays the same. Also creates the "Total" bandwidth calculated items if they are missing.
Run after setup_isp_links.py.
"""
import click_to_graph
import setup_isp_links as base

DASHBOARD = "A10 LLB & ISP Links"
HOST = base.HOST
HOST_VISIBLE = base.HOST_NAME  # svggraph host patterns match the visible name
ISP_COLORS = {"Airtel": "E5484D", "Jio": "2563EB", "PowerGrid": "F59E0B"}
DOWN_COLOR, UP_COLOR = "0EA5E9", "8B5CF6"
GREEN, AMBER, RED = "2E9E5B", "F2A900", "D64545"

# Zabbix widget field types
INT, STR, HOSTREF, ITEM = 0, 1, 3, 4


def f(ftype, name, value):
    return {"type": ftype, "name": name, "value": value}


def thresholds(*pairs):
    out = []
    for n, (value, color) in enumerate(pairs):
        out += [f(STR, f"thresholds.{n}.color", color), f(STR, f"thresholds.{n}.threshold", str(value))]
    return out


def widget(wtype, name, x, y, w, h, fields, view_mode=0):
    return {"type": wtype, "name": name, "x": x, "y": y, "width": w, "height": h,
            "view_mode": view_mode, "fields": fields}


def item_tile(name, itemid, x, y, w, h, desc, decimals=2, th=(), show_time=False, change=False, value_size=30, units_size=24):
    shows = [1, 2] + ([3] if show_time else []) + ([4] if change else [])
    fields = [f(ITEM, "itemid.0", itemid), f(STR, "description", desc), f(INT, "desc_size", 13),
              f(INT, "desc_bold", 1), f(INT, "desc_v_pos", 0), f(INT, "decimal_places", decimals), f(INT, "value_size", value_size),
              f(INT, "value_bold", 1), f(INT, "units_size", units_size)]
    fields += [f(INT, f"show.{n}", s) for n, s in enumerate(shows)]
    if show_time:  # description sits on top, so put the timestamp at the bottom
        fields += [f(INT, "time_v_pos", 2), f(INT, "time_h_pos", 1), f(INT, "time_size", 10)]
    return widget("item", name, x, y, w, h, fields + thresholds(*th), view_mode=1)


def gauge(name, itemid, x, y, w, h, desc):
    fields = [f(ITEM, "itemid.0", itemid), f(STR, "description", desc), f(INT, "desc_size", 9),
              f(INT, "desc_bold", 1), f(INT, "decimal_places", 1), f(INT, "value_size", 20),
              f(INT, "value_bold", 1), f(INT, "min", 0), f(INT, "max", 100), f(INT, "th_show_arc", 1),
              f(INT, "th_arc_size", 8), f(INT, "value_arc_size", 18)]
    fields += [f(INT, f"show.{n}", s) for n, s in enumerate([1, 2, 4, 5])]
    return widget("gauge", name, x, y, w, h, fields + thresholds((0, GREEN), (70, AMBER), (90, RED)), view_mode=1)


def svggraph(name, x, y, w, h, datasets, right=False, legend_lines=3, zero_base=True, extra=()):
    fields = []
    for n, ds in enumerate(datasets):
        p = f"ds.{n}."
        fields += [f(INT, p + "dataset_type", 1), f(STR, p + "hosts.0", HOST_VISIBLE), f(STR, p + "items.0", ds["item"]),
                   f(STR, p + "color", ds["color"]), f(INT, p + "type", ds.get("type", 0)),
                   f(INT, p + "width", ds.get("width", 2)), f(INT, p + "fill", ds.get("fill", 0)),
                   f(INT, p + "transparency", ds.get("transparency", 5)), f(INT, p + "stacked", ds.get("stacked", 0)),
                   f(INT, p + "axisy", ds.get("axisy", 0)), f(INT, p + "missingdatafunc", 1),
                   f(STR, p + "data_set_label", ds.get("label", ""))]
    fields += [f(INT, "legend", 1), f(INT, "legend_statistic", 1), f(INT, "legend_lines", legend_lines),
               f(INT, "righty", 1 if right else 0)]
    if zero_base:
        fields.append(f(INT, "lefty_min", 0))
    return widget("svggraph", name, x, y, w, h, fields + list(extra))


def ensure_totals(z, hostid):
    have = {i["key_"]: i["itemid"] for i in z.call("item.get", {"hostids": hostid, "search": {"key_": "isp.total."},
                                                                "output": ["key_"]})}
    for d, word in (("in", "download"), ("out", "upload")):
        key = f"isp.total.{d}"
        if key not in have:
            formula = "+".join(f"last(//isp.net.if.{d}[{n}])" for n, *_ in base.ISPS)
            have[key] = z.call("item.create", {
                "hostid": hostid, "name": f"All ISPs: Total {word}", "type": 15, "key_": key, "value_type": 0,
                "units": "bps", "delay": base.TRAFFIC_POLL, "params": formula, "history": base.HISTORY, "trends": base.TRENDS,
                "tags": [{"tag": "component", "value": "traffic"}, {"tag": "isp", "value": "All"}]})["itemids"][0]
    return have


# ---------- Full A10 coverage pages (items from add_a10_full.py) ----------
SLATE = "475569"
TRAFFIC_TH = ((0, "E5EDF7"), (1000000, "BFD7F5"), (100000000, "7FB0EB"), (1000000000, "2563EB"))
BGP_TH = ((0, SLATE), (1, RED), (2, AMBER), (6, GREEN))   # session state: 0 shutdown, 1 idle, 2-5 connecting, 6 established
PORT_TH = ((0, GREEN), (1, RED), (2, SLATE))              # A10 port: 0 up, 1 down, 2 disabled
SERVER_TH = ((0, SLATE), (1, GREEN), (2, RED))            # A10 server / member: 0 disabled, 1 up, 2 down
GROUP_TH = ((0, SLATE), (1, GREEN), (2, AMBER), (4, RED))  # group: 1 all up, 2/3 some members down, 4 stopped
VS_TH = ((1, GREEN), (2, RED), (3, SLATE))                # virtual server / port: 1 up, 2 down, 3 disabled
LACP_TH = ((0, RED), (1, GREEN))
ISP_ORDER = {n: i for i, (n, *_) in enumerate(base.ISPS)}


def label(pattern, out):
    return '{{ITEM.NAME}.regsub("%s", "%s")}' % (pattern, out)


def honeycomb(name, x, y, w, h, hostid, patterns, lab, th, ref):
    fields = [f(HOSTREF, "hostids.0", hostid)] + [f(STR, f"items.{i}", p) for i, p in enumerate(patterns)]
    fields += [f(INT, "show.0", 1), f(INT, "show.1", 2), f(INT, "primary_label_type", 0), f(STR, "primary_label", lab),
               f(INT, "primary_label_size_type", 0), f(INT, "primary_label_bold", 1),
               f(INT, "secondary_label_type", 1), f(INT, "secondary_label_decimal_places", 0),
               f(INT, "rf_rate", 30), f(STR, "reference", ref)]
    return widget("honeycomb", name, x, y, w, h, fields + thresholds(*th))


def navigator(name, x, y, w, h, hostid, patterns, tag, ref):
    fields = [f(HOSTREF, "hostids.0", hostid)] + [f(STR, f"items.{i}", p) for i, p in enumerate(patterns)]
    fields += [f(INT, "group_by.0.attribute", 3), f(STR, "group_by.0.tag_name", tag), f(INT, "show_lines", 300),
               f(INT, "rf_rate", 30), f(STR, "reference", ref)]
    return widget("itemnavigator", name, x, y, w, h, fields)


def follow(name, x, y, w, h, ref):
    return click_to_graph.follow_graph(name, x, y, w, h, ref)


def problems_tagged(name, x, y, w, h, hostid, component, lines=8):
    return widget("problems", name, x, y, w, h,
                  [f(HOSTREF, "hostids.0", hostid), f(INT, "show", 1), f(INT, "show_lines", lines),
                   f(STR, "tags.0.tag", "component"), f(INT, "tags.0.operator", 1), f(STR, "tags.0.value", component),
                   f(INT, "show_timeline", 0), f(INT, "sort_triggers", 4)])


def full_pages(z, hostid, items, pages, ov):
    """BGP, ports + trunk, SLB, sessions + drops pages; BGP / port maps on the overview; system tiles on A10 Health."""
    if "a10.bgp.walk" not in items:
        return
    names = {i["name"]: i["itemid"] for i in z.call("item.get", {"hostids": hostid, "output": ["name"]})}

    def ds(pattern, color, lab="", **kw):
        return {"item": pattern, "color": color, "label": lab, **kw}

    # sessions in ISP order, IPv4 before IPv6
    sessions = sorted({n.split(": ")[0] for n in names if n.startswith("BGP ") and n.endswith(": Session state")},
                      key=lambda s: (ISP_ORDER.get(s.split()[1], 99), s.split()[2]))
    bgp_lab = label("^BGP ([^ ]+) (IPv.) peer.*", "\\1 \\2")

    # ---------- Overview: BGP sessions + A10 ports under the existing widgets ----------
    ov.append(honeycomb("BGP sessions (green established / red down / grey shut down) - click one", 0, 26, 36, 4,
                        hostid, ["BGP *: Session state"], bgp_lab, BGP_TH, "OVBGP"))
    ov.append(honeycomb("A10 ports (green up / red down / grey disabled) - click one", 36, 26, 36, 4, hostid,
                        ["A10 port *: Status"], label("^A10 port ([^ ]+) .*", "\\1"), PORT_TH, "OVPRT"))
    ov.append(follow("BGP session selected above", 0, 30, 36, 5, "OVBGP"))
    ov.append(follow("A10 port selected above", 36, 30, 36, 5, "OVPRT"))

    # ---------- BGP ----------
    bgp = [item_tile("Local AS", items["a10.bgp.local.as"], 0, 0, 12, 3, "A10 local AS", decimals=0, value_size=22),
           item_tile("Router ID", items["a10.bgp.router.id"], 12, 0, 12, 3, "BGP router ID", value_size=18),
           item_tile("Our networks", items["a10.bgp.local.networks"], 24, 0, 12, 3, "Networks we advertise",
                     decimals=0, th=((0, RED), (1, GREEN)), value_size=22),
           item_tile("BGP routes", items["a10.bgp.routes.total"], 36, 0, 12, 3, "Routes in BGP table", decimals=0,
                     value_size=22),
           problems_tagged("BGP events", 48, 0, 24, 3, hostid, "bgp", lines=5),
           honeycomb("BGP sessions (green established / amber connecting / red down / grey shut down) - click one",
                     0, 3, 36, 5, hostid, ["BGP *: Session state"], bgp_lab, BGP_TH, "BGPMP"),
           follow("BGP session selected on the left", 36, 3, 36, 5, "BGPMP")]
    for i, s in enumerate(sessions[:6]):
        short = " ".join(s.split()[1:3])
        bgp.append(item_tile(f"{short} up for", names[f"{s}: Time in current state"], i * 12, 8, 12, 3,
                             f"{short} · time in state", decimals=0, value_size=16, units_size=12))
        bgp.append(item_tile(f"{short} last error", names[f"{s}: Last error (NOTIFICATION code/subcode)"], i * 12, 11,
                             12, 3, f"{short} · last error", value_size=12))
        bgp.append(item_tile(f"{short} prefixes", names[f"{s}: Received prefixes"], i * 12, 14, 12, 3,
                             f"{short} · prefixes received", decimals=0, th=((0, RED), (1, GREEN)), value_size=20))
    bgp += [navigator("BGP details per session - click an item to graph it", 0, 17, 24, 12, hostid, ["BGP *"],
                      "bgp_peer", "BGPNV"),
            follow("Graph of the BGP item selected on the left", 24, 17, 48, 12, "BGPNV"),
            svggraph("Time in current state per session", 0, 29, 36, 6,
                     [ds(f"{s}: Time in current state", c, " ".join(s.split()[1:3]))
                      for s, c in zip(sessions, ("E5484D", "F87171", "2563EB", "60A5FA", "F59E0B", "FCD34D"))],
                     legend_lines=6),
            svggraph("Flaps per session (each step up = session went down and came back)", 36, 29, 36, 6,
                     [ds(f"{s}: Flaps (times Established since A10 boot)", c, " ".join(s.split()[1:3]), type=2)
                      for s, c in zip(sessions, ("E5484D", "F87171", "2563EB", "60A5FA", "F59E0B", "FCD34D"))],
                     legend_lines=6),
            svggraph("BGP messages received per minute (keepalives + updates)", 0, 35, 36, 6,
                     [ds(f"{s}: Messages received per minute", c, " ".join(s.split()[1:3]))
                      for s, c in zip(sessions, ("E5484D", "F87171", "2563EB", "60A5FA", "F59E0B", "FCD34D"))],
                     legend_lines=6),
            svggraph("Prefixes received per session", 36, 35, 36, 6,
                     [ds(f"{s}: Received prefixes", c, " ".join(s.split()[1:3]))
                      for s, c in zip(sessions, ("E5484D", "F87171", "2563EB", "60A5FA", "F59E0B", "FCD34D"))],
                     legend_lines=6)]

    # ---------- Ports & trunk ----------
    port_lab = label("^A10 port ([^ ]+) .*", "\\1")
    trunk = sorted(n for n in names if n.startswith("A10 trunk ") and ": " in n)
    tr_status = next(n for n in trunk if n.endswith(": Status") and " member " not in n)
    tr_name = tr_status.split(": ")[0]
    members = [n for n in trunk if n.endswith(": LACP member status (bundled)")]
    ports = [item_tile("Trunk", names[tr_status], 0, 9, 12, 3, tr_name.replace("A10 ", ""), decimals=0,
                       th=LACP_TH, value_size=20)]
    for i, m in enumerate(members[:2]):
        mem = m.split(" member ")[1].split(":")[0]
        ports.append(item_tile(f"LACP {mem}", names[m], 12 + i * 12, 9, 12, 3, f"LACP member {mem}", decimals=0,
                               th=LACP_TH, value_size=20))
    ports += [item_tile("Trunk in", names[f"{tr_name}: Bits received"], 36, 9, 12, 3, "Trunk in", value_size=20),
              item_tile("Trunk out", names[f"{tr_name}: Bits sent"], 48, 9, 12, 3, "Trunk out", value_size=20),
              item_tile("Mgmt port", items["a10.mgmt.status"], 60, 9, 12, 3, "Management port", decimals=0,
                        th=((1, GREEN), (2, RED)), value_size=20),
              honeycomb("Port status (green up / red down / grey disabled) - click a port", 0, 0, 36, 4, hostid,
                        ["A10 port *: Status"], port_lab, PORT_TH, "PRTST"),
              honeycomb("Traffic in now, per port - click a port", 36, 0, 36, 4, hostid,
                        ["A10 port *: Bits received"], port_lab, TRAFFIC_TH, "PRTTR"),
              follow("Port selected in the status map", 0, 4, 36, 5, "PRTST"),
              follow("Port selected in the traffic map", 36, 4, 36, 5, "PRTTR"),
              svggraph("Traffic in per port", 0, 12, 36, 6, [ds("A10 port *: Bits received", DOWN_COLOR)], legend_lines=4),
              svggraph("Traffic out per port", 36, 12, 36, 6, [ds("A10 port *: Bits sent", UP_COLOR)], legend_lines=4),
              svggraph("Errors per port (in / out)", 0, 18, 36, 6,
                       [ds("A10 port *: Inbound errors", RED), ds("A10 port *: Outbound errors", AMBER)], legend_lines=4),
              svggraph("Drops per port (in / out)", 36, 18, 36, 6,
                       [ds("A10 port *: Inbound drops", RED), ds("A10 port *: Outbound drops", AMBER)], legend_lines=4),
              navigator("Every port item (status, speed, duplex, MTU, traffic, packets, errors, drops) - click to graph",
                        0, 24, 24, 12, hostid, ["A10 port *", "A10 trunk *", "A10 management port*"], "interface", "PRTNV"),
              follow("Graph of the port item selected on the left", 24, 24, 48, 12, "PRTNV"),
              problems_tagged("Port and trunk events", 0, 36, 36, 5, hostid, "port"),
              problems_tagged("Trunk events", 36, 36, 36, 5, hostid, "trunk")]

    # ---------- SLB (gateways incl. IPv6, service groups, members, virtual servers) ----------
    slb = [honeycomb("ISP gateways, A10 health check (green up / red down) - click one", 0, 0, 24, 4, hostid,
                     ["A10 gateway *: Health status"], label("^A10 gateway ([^ ]+) .*", "\\1"), SERVER_TH, "SLBGW"),
           honeycomb("Service groups (green all up / amber some members down / red stopped)", 24, 0, 24, 4, hostid,
                     ["A10 service group *: Status"], label("^A10 service group ([^ ]+): .*", "\\1"), GROUP_TH, "SLBSG"),
           honeycomb("Virtual servers and ports (green up / red down)", 48, 0, 24, 4, hostid,
                     ["A10 virtual server *: Status"],
                     label("^A10 virtual server ([^ ]+)( port ([^ ]+))?: .*", "\\1 \\3"), VS_TH, "SLBVS"),
           follow("Gateway selected above", 0, 4, 24, 5, "SLBGW"),
           follow("Service group selected above", 24, 4, 24, 5, "SLBSG"),
           follow("Virtual server selected above", 48, 4, 24, 5, "SLBVS"),
           honeycomb("Service-group members (green up / red down / grey disabled) - click one", 0, 9, 36, 5, hostid,
                     ["A10 service group * member *: Member status"],
                     label("^A10 service group ([^ ]+) member ([^ ]+): .*", "\\1 > \\2"), SERVER_TH, "SLBMB"),
           follow("Member selected on the left", 36, 9, 36, 5, "SLBMB"),
           svggraph("Current connections per gateway (IPv4 + IPv6)", 0, 14, 36, 6,
                    [ds("A10 gateway *: Current connections", "2563EB")], legend_lines=6),
           svggraph("New connections per second per gateway", 36, 14, 36, 6,
                    [ds("A10 gateway *: New connections per second", "8B5CF6")], legend_lines=6),
           svggraph("Download per gateway (IPv4 + IPv6)", 0, 20, 36, 6,
                    [ds("A10 gateway *: Download (ISP to users)", DOWN_COLOR)], legend_lines=6),
           svggraph("Upload per gateway (IPv4 + IPv6)", 36, 20, 36, 6,
                    [ds("A10 gateway *: Upload (users to ISP)", UP_COLOR)], legend_lines=6),
           svggraph("Member response time", 0, 26, 36, 6,
                    [ds("A10 service group * member *: Response time", AMBER)], legend_lines=6),
           svggraph("Current connections per virtual server", 36, 26, 36, 6,
                    [ds("A10 virtual server *: Current connections", "0D9488")], legend_lines=6),
           problems_tagged("SLB events", 0, 32, 72, 5, hostid, "slb")]

    # ---------- Sessions & drops ----------
    sess = []
    for i, (key, desc, dec) in enumerate((("a10.sess.total", "Sessions total", 0), ("a10.sess.tcp.est", "TCP established", 0),
                                          ("a10.sess.tcp.halfopen", "TCP half-open", 0),
                                          ("a10.sess.tcp.synhalfopen", "TCP SYN half-open", 0),
                                          ("a10.sess.udp", "UDP sessions", 0), ("a10.conn.new", "New connections/s", 0))):
        sess.append(item_tile(desc, items[key], i * 12, 0, 12, 3, desc, decimals=dec, value_size=22))
    for i, (key, desc, dec, th) in enumerate((("a10.throughput", "Total throughput", 2, ()),
                                              ("a10.cpu.data", "Data-plane CPU", 0, ((0, GREEN), (70, AMBER), (90, RED))),
                                              ("a10.cpu.control", "Control-plane CPU", 0, ((0, GREEN), (70, AMBER), (90, RED))),
                                              ("a10.disk.pused", "Disk used", 1, ((0, GREEN), (75, AMBER), (85, RED))),
                                              ("a10.arp.entries", "ARP entries", 0, ()), ("a10.routes", "IPv4 routes", 0, ()))):
        sess.append(item_tile(desc, items[key], i * 12, 3, 12, 3, desc, decimals=dec, th=th, value_size=22))
    sess += [svggraph("Session table by type", 0, 6, 36, 6,
                      [ds("A10: Sessions: TCP established", "2563EB", "TCP established", fill=3, stacked=1),
                       ds("A10: Sessions: TCP half-open", AMBER, "TCP half-open", fill=3, stacked=1),
                       ds("A10: Sessions: UDP", "8B5CF6", "UDP", fill=3, stacked=1),
                       ds("A10: Sessions: other IP (not TCP/UDP)", "0D9488", "other IP", fill=3, stacked=1)],
                      legend_lines=4),
             svggraph("New connections per second", 0 + 36, 6, 36, 6,
                      [ds("A10: New connections per second", "2563EB", "all"),
                       ds("A10: New L4 connections per second", "0D9488", "L4"),
                       ds("A10: New L7 connections per second", AMBER, "L7"),
                       ds("A10: New IP-NAT connections per second", "8B5CF6", "IP-NAT"),
                       ds("A10: New SSL connections per second", RED, "SSL")], legend_lines=5),
             svggraph("Routing / forwarding drops per second", 0, 12, 36, 6,
                      [ds("A10: Drops: IPv4 no route per second", RED, "IPv4 no route"),
                       ds("A10: Drops: IPv6 no route per second", "F97316", "IPv6 no route"),
                       ds("A10: Drops: outgoing link down per second", AMBER, "link down"),
                       ds("A10: Drops: TTL exceeded per second", "8B5CF6", "TTL"),
                       ds("A10: Buffer (application packet) drops per second", "DB2777", "buffer"),
                       ds("A10: DDoS drops: total (hardware DDoS protection) per second", "475569", "DDoS")],
                      legend_lines=6),
             svggraph("Load-balancing failures and limit drops per second", 36, 12, 36, 6,
                      [ds("A10: Source NAT failures per second", RED, "source NAT fail"),
                       ds("A10: Real-server selection failures per second", "F97316", "server select fail"),
                       ds("A10: Drops: no resource per second", AMBER, "no resource"),
                       ds("A10: Drops: server connection limit per second", "8B5CF6", "conn limit"),
                       ds("A10: Drops: connection rate limit per second", "DB2777", "conn rate limit"),
                       ds("A10: Drops: no matching virtual port per second", "475569", "no vport")], legend_lines=6),
             svggraph("TCP resets sent by reason per second", 0, 18, 36, 6,
                      [ds("A10: TCP RST sent: *", RED)], legend_lines=6),
             svggraph("Sessions aged out per second", 36, 18, 36, 6,
                      [ds("A10: TCP sessions aged out per second", "2563EB", "TCP"),
                       ds("A10: UDP sessions aged out per second", "8B5CF6", "UDP"),
                       ds("A10: Other sessions aged out per second", "0D9488", "other"),
                       ds("A10: TCP not-established sessions aged out per second", AMBER, "TCP never established")],
                      legend_lines=4),
             svggraph("Packets forwarded per second", 0, 24, 36, 6,
                      [ds("A10: IPv4 routed packets per second", "2563EB", "IPv4 routed"),
                       ds("A10: IPv6 routed packets per second", "8B5CF6", "IPv6 routed"),
                       ds("A10: L2 switched packets per second", "0D9488", "L2 switched"),
                       ds("A10: Packets to VIP/NAT (L4 processing) per second", AMBER, "L4 processing")],
                      legend_lines=4),
             svggraph("TCP anomalies and invalid packets per second", 36, 24, 36, 6,
                      [ds("A10: Drops: TCP packet without session (no SYN) per second", RED, "no session"),
                       ds("A10: Drops: invalid TCP per second", AMBER, "invalid TCP"),
                       ds("A10: Drops: out-of-sequence ACK per second", "8B5CF6", "out-of-seq ACK"),
                       ds("A10: Anomaly: *", "475569")], legend_lines=6),
             navigator("Every session / drop / switching counter - click to graph", 0, 30, 24, 12, hostid,
                       ["A10: Sessions*", "A10: New*", "A10: Current*", "A10: Drops*", "A10: TCP*", "A10: UDP*",
                        "A10: Source NAT*", "A10: L4*", "A10: L2*", "A10: IPv*", "A10: DDoS*", "A10: Anomaly*",
                        "A10: Fragment*", "A10: ARP*", "A10: VLAN*", "A10: Packets*", "A10: Real-server*",
                        "A10: Resets*", "A10: Buffer*", "A10: Total throughput*", "A10: Sessions aged*",
                        "A10: In-band*", "A10: NAT*", "A10: Auto*", "A10: Fast*", "A10: Not-established*",
                        "A10: Other*", "A10: IP *", "A10: Overlapping*", "A10: Fragments*"], "component", "SESNV"),
             follow("Graph of the counter selected on the left", 24, 30, 48, 12, "SESNV"),
             problems_tagged("Drop alerts", 0, 42, 72, 4, hostid, "drops", lines=5)]

    # ---------- A10 Health: system information ----------
    health = next((p for p in pages if p["name"] == "A10 Health"), None)
    if health:
        for i, (key, desc, dec, th) in enumerate((("a10.serial", "Serial number", 0, ()),
                                                  ("a10.sw.primary", "Software (primary disk)", 0, ()),
                                                  ("a10.sw.secondary", "Software (secondary disk)", 0, ()),
                                                  ("a10.startup", "Booted from", 0, ()),
                                                  ("a10.ha.enabled", "HA (VRRP-A)", 0, ()),
                                                  ("a10.disk.pused", "Disk used", 1, ((0, GREEN), (75, AMBER), (85, RED))))):
            health["widgets"].append(item_tile(desc, items[key], i * 12, 16, 12, 3, desc, decimals=dec, th=th,
                                               value_size=14))
        health["widgets"] += [
            svggraph("Data-plane vs control-plane CPU", 0, 19, 36, 5,
                     [ds("A10: CPU data plane (5 s average)", "2563EB", "data plane"),
                      ds("A10: CPU control plane (5 s average)", RED, "control plane")],
                     extra=[f(INT, "lefty_max", 100)]),
            svggraph("Total throughput (all interfaces)", 36, 19, 36, 5,
                     [ds("A10: Total throughput, all interfaces", DOWN_COLOR, "throughput", fill=3)])]

    at = next(i for i, p in enumerate(pages) if p["name"] == "A10 LLB") + 1
    pages[at:at] = [{"name": "BGP", "widgets": bgp}, {"name": "A10 Ports & Trunk", "widgets": ports},
                    {"name": "A10 SLB", "widgets": slb}, {"name": "A10 Sessions & Drops", "widgets": sess}]


def main():
    z = base.Zabbix()
    hostid = z.call("host.get", {"filter": {"host": [HOST]}})[0]["hostid"]
    totals = ensure_totals(z, hostid)
    items = {i["key_"]: i["itemid"] for i in z.call("item.get", {"hostids": hostid, "output": ["key_"]})}

    def key(name, what):
        gw = next(g for n, _, g, *_ in base.ISPS if n == name)
        ping = f"{gw},3,200,,500"
        return items[{"in": f"isp.net.if.in[{name}]", "out": f"isp.net.if.out[{name}]",
                      "uin": f"isp.util.in[{name}]", "uout": f"isp.util.out[{name}]",
                      "status": f"isp.net.if.status[{name}]", "ping": f"icmpping[{ping}]",
                      "loss": f"icmppingloss[{ping}]", "rtt": f"icmppingsec[{ping},avg]"}[what]]

    names = [n for n, *_ in base.ISPS]
    up_down = ((0, RED), (1, GREEN))

    # ---------- Overview ----------
    ov = []
    for n_i, n in enumerate(names):
        ov.append(item_tile(f"{n} link", key(n, "ping"), n_i * 8, 0, 8, 3, n,
                            decimals=0, th=up_down, value_size=22))
    ov.append(item_tile("Total download", totals["isp.total.in"], 24, 0, 12, 3, "Total download", value_size=26))
    ov.append(item_tile("Total upload", totals["isp.total.out"], 36, 0, 12, 3, "Total upload", value_size=26))
    ov.append(widget("problemsbysv", "Active problems", 48, 0, 24, 3,
                     [f(HOSTREF, "hostids.0", hostid), f(INT, "show_type", 1), f(INT, "layout", 0)]))
    for n_i, n in enumerate(names):
        ov.append(gauge(f"{n} download %", key(n, "uin"), n_i * 24, 3, 12, 4, f"{n} download"))
        ov.append(gauge(f"{n} upload %", key(n, "uout"), n_i * 24 + 12, 3, 12, 4, f"{n} upload"))
    ov.append(svggraph("Download by ISP (stacked)", 0, 7, 36, 6,
                       [{"item": f"{n}: Bits received", "color": ISP_COLORS[n], "fill": 4, "stacked": 1, "width": 1,
                         "label": n} for n in names], legend_lines=3))
    ov.append(svggraph("Upload by ISP (stacked)", 36, 7, 36, 6,
                       [{"item": f"{n}: Bits sent", "color": ISP_COLORS[n], "fill": 4, "stacked": 1, "width": 1,
                         "label": n} for n in names], legend_lines=3))
    ov.append(svggraph("Gateway latency", 0, 13, 36, 5,
                       [{"item": f"{n}: Gateway latency", "color": ISP_COLORS[n], "width": 2, "label": n}
                        for n in names]))
    ov.append(svggraph("Gateway packet loss", 36, 13, 36, 5,
                       [{"item": f"{n}: Gateway packet loss", "color": ISP_COLORS[n], "width": 2, "label": n}
                        for n in names]))
    ov.append(widget("problems", "ISP problems (current and recent)", 0, 18, 72, 5,
                     [f(HOSTREF, "hostids.0", hostid), f(INT, "show", 1), f(INT, "show_lines", 8),
                      f(INT, "sort_triggers", 4), f(INT, "show_timeline", 0)]))
    pages = [{"name": "NOC Overview", "widgets": ov}]

    # ---------- One page per ISP ----------
    for n in names:
        w = [
            item_tile("Link", key(n, "ping"), 0, 0, 12, 3, f"{n} gateway", decimals=0, th=up_down, change=False),
            item_tile("Port", key(n, "status"), 12, 0, 12, 3, "A10 port", decimals=0,
                      th=((0, RED), (1, GREEN), (2, RED)), change=False),
            item_tile("Download", key(n, "in"), 24, 0, 12, 3, "Download", decimals=1, value_size=26),
            item_tile("Upload", key(n, "out"), 36, 0, 12, 3, "Upload", decimals=1, value_size=26),
            item_tile("Latency", key(n, "rtt"), 48, 0, 12, 3, "Gateway latency", decimals=1,
                      th=((0, GREEN), (0.05, AMBER), (0.15, RED))),
            item_tile("Loss", key(n, "loss"), 60, 0, 12, 3, "Packet loss", decimals=1,
                      th=((0, GREEN), (1, AMBER), (5, RED))),
            gauge("Download utilisation", key(n, "uin"), 0, 3, 12, 5, "Download utilisation"),
            gauge("Upload utilisation", key(n, "uout"), 12, 3, 12, 5, "Upload utilisation"),
            svggraph("Utilisation %", 24, 3, 48, 5,
                     [{"item": f"{n}: Utilisation download", "color": DOWN_COLOR, "fill": 2, "label": "Download %"},
                      {"item": f"{n}: Utilisation upload", "color": UP_COLOR, "fill": 0, "label": "Upload %"}],
                     extra=[f(INT, "lefty_max", 100), f(INT, "simple_triggers", 1)]),
            svggraph("Traffic", 0, 8, 72, 6,
                     [{"item": f"{n}: Bits received", "color": DOWN_COLOR, "fill": 3, "label": "Download"},
                      {"item": f"{n}: Bits sent", "color": UP_COLOR, "fill": 0, "width": 2, "label": "Upload"}]),
            svggraph("Gateway latency & packet loss", 0, 14, 72, 5,
                     [{"item": f"{n}: Gateway latency", "color": ISP_COLORS[n], "width": 2, "label": "Latency"},
                      {"item": f"{n}: Gateway packet loss", "color": RED, "type": 3, "axisy": 1, "label": "Loss %"}],
                     right=True),
        ]
        pages.append({"name": n, "widgets": w})

    # ---------- A10 LLB (items from add_llb_stats.py, if present) ----------
    if all(f"a10.llb.status[{n}]" in items for n in names):
        llb_up = ((0, AMBER), (1, GREEN), (2, RED))   # 0 disabled / 1 up / 2 down

        def pie(name, x, y, w, h, item_fmt, label):
            fields = []
            for i, n in enumerate(names):
                p = f"ds.{i}."
                fields += [f(INT, p + "dataset_type", 1), f(STR, p + "hosts.0", HOST_VISIBLE),
                           f(STR, p + "items.0", item_fmt.format(n)), f(STR, p + "color", ISP_COLORS[n]),
                           f(INT, p + "aggregate_function", 7), f(INT, p + "dataset_aggregation", 0),
                           f(STR, p + "data_set_label", n)]
            fields += [f(INT, "draw_type", 1), f(INT, "width", 40), f(INT, "total_show", 1), f(INT, "legend", 1),
                       f(INT, "legend_value", 1), f(INT, "legend_lines", 3), f(STR, "units", label),
                       f(INT, "units_show", 1)]
            return widget("piechart", name, x, y, w, h, fields)

        llb = []
        for i, n in enumerate(names):
            llb.append(item_tile(f"{n} A10 status", items[f"a10.llb.status[{n}]"], i * 8, 0, 8, 3,
                                 f"{n} · A10 LLB", decimals=0, th=llb_up, value_size=22))
            llb.append(item_tile(f"{n} health flaps", items[f"a10.llb.flaps[{n}]"], 24 + i * 8, 0, 8, 3,
                                 f"{n} flaps", decimals=0, value_size=22))
        llb.append(widget("problems", "A10 LLB events", 48, 0, 24, 3,
                          [f(HOSTREF, "hostids.0", hostid), f(INT, "show", 1), f(INT, "show_lines", 6),
                           f(STR, "tags.0.tag", "component"), f(INT, "tags.0.operator", 1),
                           f(STR, "tags.0.value", "llb"), f(INT, "show_timeline", 0), f(INT, "sort_triggers", 4)]))
        llb.append(pie("Share of A10 session-table entries", 0, 3, 24, 6, "{}: A10 LLB session-table entries", "sessions"))
        llb.append(svggraph("A10 session-table entries per gateway (idle entries linger after a link goes down)", 24, 3, 48, 6,
                            [{"item": f"{n}: A10 LLB session-table entries", "color": ISP_COLORS[n], "width": 2,
                              "label": n} for n in names]))
        llb.append(svggraph("New connections per second per gateway", 0, 9, 36, 5,
                            [{"item": f"{n}: A10 LLB new connections per second", "color": ISP_COLORS[n],
                              "width": 2, "label": n} for n in names]))
        llb.append(svggraph("Health flaps (each step up = A10 removed the link briefly)", 36, 9, 36, 5,
                            [{"item": f"{n}: A10 LLB health flaps (since A10 boot)", "color": ISP_COLORS[n],
                              "type": 2, "width": 2, "label": n} for n in names], zero_base=False))
        llb.append(svggraph("LLB download per gateway (stacked)", 0, 14, 36, 6,
                            [{"item": f"{n}: A10 LLB download", "color": ISP_COLORS[n], "fill": 4, "stacked": 1,
                              "width": 1, "label": n} for n in names]))
        llb.append(svggraph("LLB upload per gateway (stacked)", 36, 14, 36, 6,
                            [{"item": f"{n}: A10 LLB upload", "color": ISP_COLORS[n], "fill": 4, "stacked": 1,
                              "width": 1, "label": n} for n in names]))
        if all(f"a10.llb.syn[{n}]" in items for n in names) and "a10.tcp.syn.drop" in items:
            for i, n in enumerate(names):
                llb.append(item_tile(f"{n} SYN/s", items[f"a10.llb.syn[{n}]"], i * 8, 20, 8, 3,
                                     f"{n} · SYN sent/s", decimals=0, value_size=24))
            llb.append(item_tile("A10 SYN received", items["a10.tcp.syn.rcv"], 24, 20, 12, 3,
                                 "SYN received/s", decimals=0, value_size=26))
            llb.append(item_tile("A10 SYN sent", items["a10.tcp.syn.sent"], 36, 20, 12, 3,
                                 "SYN sent/s", decimals=0, value_size=26))
            llb.append(item_tile("A10 SYN dropped", items["a10.tcp.syn.drop"], 48, 20, 12, 3,
                                 "SYN dropped/s", decimals=0, value_size=26))
            llb.append(item_tile("SYN cookies", items["a10.tcp.syncookie.sent"], 60, 20, 12, 3,
                                 "SYN cookies/s (flood guard)", decimals=0, value_size=26,
                                 th=((0, GREEN), (1, RED))))
            llb.append(svggraph("New TCP connections (SYNs sent) per second per ISP", 0, 23, 36, 6,
                                [{"item": f"{n}: New TCP connections (SYNs) per second", "color": ISP_COLORS[n],
                                  "width": 2, "label": n} for n in names]))
            llb.append(svggraph("New UDP flows per second per ISP", 36, 23, 36, 6,
                                [{"item": f"{n}: New UDP flows per second", "color": ISP_COLORS[n],
                                  "width": 2, "label": n} for n in names]))
            llb.append(svggraph("A10 SYN received vs SYN sent vs SYN dropped", 0, 29, 36, 6,
                                [{"item": "A10: TCP SYN received per second", "color": "0EA5E9", "width": 2},
                                 {"item": "A10: TCP SYN sent to ISPs per second", "color": "2E9E5B", "width": 2},
                                 {"item": "A10: SYN dropped per second (total)", "color": RED, "width": 2}]))
            llb.append(svggraph("SYN drops by reason, SYN cookies and TCP resets", 36, 29, 36, 6,
                                [{"item": "A10: L4 SYN attack per second", "color": RED, "width": 2},
                                 {"item": "A10: SYN dropped by throttling per second", "color": AMBER, "width": 2},
                                 {"item": "A10: SYN cookie send failures per second", "color": "F97316", "width": 1},
                                 {"item": "A10: SYN cookies sent per second*", "color": "DB2777", "width": 1},
                                 {"item": "A10: TCP resets sent per second", "color": "8B5CF6", "width": 1}],
                                legend_lines=5))
        pages.insert(len(names) + 1, {"name": "A10 LLB", "widgets": llb})
        # Overview: LLB verdict per gateway under the existing widgets.
        for i, n in enumerate(names):
            ov.append(item_tile(f"{n} A10 LLB", items[f"a10.llb.status[{n}]"], i * 12, 23, 12, 3,
                                f"{n} · A10 LLB", decimals=0, th=llb_up, value_size=26))
            ov.append(item_tile(f"{n} session share", items[f"a10.llb.conn.share[{n}]"], 36 + i * 12, 23, 12, 3,
                                f"{n} · session share", decimals=1, value_size=26))

    # ---------- A10 health (items from add_health_and_drop_alerts.py, if present) ----------
    if "a10.cpu.util.max" in items:
        pages.append({"name": "A10 Health", "widgets": [
            gauge("CPU busiest core", items["a10.cpu.util.max"], 0, 0, 12, 5, "CPU · busiest core"),
            gauge("CPU average", items["a10.cpu.util.avg"], 12, 0, 12, 5, "CPU · average"),
            gauge("Memory", items["a10.mem.pused"], 24, 0, 12, 5, "Memory used"),
            svggraph("Traffic vs A10 CPU", 36, 0, 36, 5,
                     [{"item": "All ISPs: Total download", "color": DOWN_COLOR, "fill": 3, "label": "Total download"},
                      {"item": "A10: CPU usage (busiest core)", "color": RED, "axisy": 1, "label": "CPU %"}],
                     right=True, extra=[f(INT, "righty_min", 0), f(INT, "righty_max", 100)]),
            svggraph("CPU per core", 0, 5, 72, 6,
                     [{"item": "A10: CPU * usage", "color": "8B5CF6", "width": 1, "label": "Cores"}],
                     extra=[f(INT, "lefty_max", 100)]),
            widget("problems", "Traffic-drop and A10 alerts", 0, 11, 72, 5,
                   [f(HOSTREF, "hostids.0", hostid), f(INT, "show", 1), f(INT, "show_lines", 8),
                    f(INT, "sort_triggers", 4), f(INT, "show_timeline", 0)]),
        ]})

    full_pages(z, hostid, items, pages, ov)

    # Data arrives every 5s; 10s is the fastest widget refresh Zabbix offers.
    for page in pages:
        for wdg in page["widgets"]:
            if not any(fl["name"] == "rf_rate" for fl in wdg["fields"]):
                wdg["fields"].append(f(INT, "rf_rate", 10 if wdg["type"] in ("item", "gauge") else 30))

    click_to_graph.link_pages(pages, DASHBOARD, z=z)   # "Items on this page" list + graph of the clicked item
    dash = z.call("dashboard.get", {"filter": {"name": [DASHBOARD]}, "output": ["dashboardid"]})
    params = {"name": DASHBOARD, "display_period": 60, "auto_start": 0, "pages": pages}
    if dash:
        z.call("dashboard.update", {"dashboardid": dash[0]["dashboardid"], **params})
        print("Updated dashboard", dash[0]["dashboardid"])
    else:
        print("Created dashboard", z.call("dashboard.create", params)["dashboardids"][0])


if __name__ == "__main__":
    main()
