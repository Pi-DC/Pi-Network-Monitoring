#!/usr/bin/env python3
"""Build the Arista switch dashboards.

  "WAN Switches"        - the 10G WAN pair (Overview with both side by side + a page per switch)
  "PiSB Cloud Fabric"   - spine/leaf fabric (Overview health table + fabric graphs + a page per switch)

Re-runnable: each dashboard is rebuilt in place. Run after add_switches.py.
"""
import build_dashboard as d
import click_to_graph
import setup_isp_links as base

f, INT, STR, HOSTREF, ITEM = d.f, d.INT, d.STR, d.HOSTREF, d.ITEM
GROUPREF = 2
GREEN, AMBER, RED = d.GREEN, d.AMBER, d.RED

UPLINKS = {  # per switch role: (interface, label, colour) shown on the switch page
    "wan": [("Port-Channel51", "Airtel uplinks", "E5484D"), ("Port-Channel52", "Jio uplinks", "2563EB"),
            ("Port-Channel41", "Peer link SW1-SW2", "7C3AED"), ("Port-Channel117", "Forti-120G WAN", "F59E0B")],
    "spine": [("Port-Channel201", "Leaf downlinks", "2E9E5B"), ("Port-Channel203", "VMware 100G spine", "2563EB"),
              ("Port-Channel100", "Peer link SP1-SP2", "7C3AED"), ("Port-Channel133", "Forti-120G LAN", "F59E0B")],
    "leaf": [("Port-Channel101", "Spine uplinks", "2E9E5B"), ("Port-Channel41", "Peer link LF1-LF2", "7C3AED"),
             ("Port-Channel301", "PiSBN01-A", "2563EB"), ("Port-Channel303", "PiSBM01", "F59E0B"),
             ("Port-Channel304", "PiSBM02", "E5484D"), ("Port-Channel305", "PiSBM03", "0D9488")],
}
DASHBOARDS = [
    {"name": "WAN Switches", "group": "WAN Switches", "overview": "pair",
     "switches": [("10G-WAN-Switch01", "SW1", "wan"), ("10G-WAN-Switch02", "SW2", "wan")]},
    {"name": "PiSB Cloud Fabric", "group": "PiSB Cloud Switches", "overview": "fabric",
     "switches": [("GE17-PiSB-SP1", "SP1", "spine"), ("GE17-PiSB-SP2", "SP2", "spine"),
                  ("GE18-PiSB-LF1", "LF1", "leaf"), ("GE18-PiSB-LF2", "LF2", "leaf")]},
]

SHORT_IF = '{{ITEM.NAME}.regsub("^Interface (..)[A-Za-z-]*([0-9/.]+)", "\\1\\2")}'   # Ethernet1/1 -> Et1/1
GREY, SLATE = "9AA4B2", "475569"
# "Port state" (tune_arista_template.py): ifOperStatus 1 up, 2 down, 3 testing, 5 dormant, 6 notPresent,
# 7 lowerLayerDown - or 8 when the port is administratively shut down
IF_STATUS_TH = ((1, GREEN), (2, RED), (3, AMBER), (6, GREY), (7, AMBER), (8, SLATE))
IF_STATE_ITEMS = "Interface *: Port state"
MAP_LEGEND = "green up / red down / grey no module / dark grey shutdown"
UP_DOWN = ((0, RED), (1, GREEN))
HEALTH_HW_ITEMS = [  # switch page "Health and hardware" list: the health tiles' items, then fans, PSUs, temperatures
    "ICMP ping", "ICMP response time", "CPU utilization", "RAM: Memory utilization", "Flash: Space utilization",
    "Uptime (network)", "*Fan*", "*Power supply*", "Board*", "Cpu temp*", "Inlet*", "Front-panel*", "Hotspot*"]
PSU_TH = ((1, AMBER), (2, RED), (3, GREEN), (4, AMBER))   # entStateOper: 3 = enabled
PCT_TH = ((0, GREEN), (70, AMBER), (90, RED))
TEMP_TH = ((0, GREEN), (65, AMBER), (80, RED))
TRAFFIC_TH = ((0, "E5EDF7"), (1000000, "BFD7F5"), (100000000, "7FB0EB"), (1000000000, "2563EB"))


def svg(name, x, y, w, h, hosts, datasets, legend_lines=4, extra=()):
    """SVG graph; each dataset dict: items (pattern list), color, label, optional hosts/type/fill/width/agg.
    Note: one graph plots at most ~100 items in total."""
    fields = []
    for n, ds in enumerate(datasets):
        p = f"ds.{n}."
        fields += [f(INT, p + "dataset_type", 1), f(STR, p + "color", ds["color"]),
                   f(INT, p + "type", ds.get("type", 0)), f(INT, p + "width", ds.get("width", 2)),
                   f(INT, p + "fill", ds.get("fill", 0)), f(INT, p + "transparency", 5), f(INT, p + "stacked", 0),
                   f(INT, p + "axisy", ds.get("axisy", 0)), f(INT, p + "missingdatafunc", 1),
                   f(STR, p + "data_set_label", ds.get("label", ""))]
        fields += [f(STR, p + f"hosts.{i}", hn) for i, hn in enumerate(ds.get("hosts", hosts))]
        fields += [f(STR, p + f"items.{i}", it) for i, it in enumerate(ds["items"])]
        if ds.get("agg"):   # aggregate all matched items into one line per dataset
            fields += [f(INT, p + "aggregate_function", ds["agg"]), f(STR, p + "aggregate_interval", "1m"),
                       f(INT, p + "aggregate_grouping", 1)]
    fields += [f(INT, "legend", 1), f(INT, "legend_statistic", 1), f(INT, "legend_lines", legend_lines),
               f(INT, "lefty_min", 0), f(INT, "rf_rate", 30)]
    return d.widget("svggraph", name, x, y, w, h, fields + list(extra))


def follow_graph(name, x, y, w, h, ref):
    """Classic simple graph of whatever item is selected in the item navigator with reference `ref`."""
    return click_to_graph.follow_graph(name, x, y, w, h, ref)


def page_ref(prefix, page_no):
    """Widget reference: 5 upper-case letters, unique on the dashboard."""
    return prefix + chr(65 + page_no // 26) + chr(65 + page_no % 26)


def honeycomb(name, x, y, w, h, hostid, item_pattern, th, ref=None):
    """Honeycomb map; with `ref`, a follow_graph() can graph the cell clicked in it."""
    fields = [f(HOSTREF, "hostids.0", hostid), f(STR, "items.0", item_pattern),
              f(INT, "show.0", 1), f(INT, "show.1", 2),
              f(INT, "primary_label_type", 0), f(STR, "primary_label", SHORT_IF),
              f(INT, "primary_label_size_type", 0), f(INT, "primary_label_bold", 1),
              f(INT, "secondary_label_type", 1), f(INT, "secondary_label_decimal_places", 0), f(INT, "rf_rate", 30)]
    if ref:
        fields.append(f(STR, "reference", ref))
    return d.widget("honeycomb", name, x, y, w, h, fields + d.thresholds(*th))


def tile(name, itemid, x, y, desc, w=12, h=3, decimals=1, th=(), value_size=26):
    wd = d.item_tile(name, itemid, x, y, w, h, desc, decimals=decimals, th=th, value_size=value_size)
    wd["fields"].append(f(INT, "rf_rate", 10))
    return wd


def problems(name, x, y, w, h, groupid=None, hostid=None):
    target = f(GROUPREF, "groupids.0", groupid) if groupid else f(HOSTREF, "hostids.0", hostid)
    return d.widget("problems", name, x, y, w, h, [target, f(INT, "show", 1), f(INT, "show_lines", 10),
                                                   f(INT, "sort_triggers", 4), f(INT, "show_timeline", 0),
                                                   f(INT, "rf_rate", 30)])


def health_table(name, x, y, w, h, groupid):
    """Top hosts widget: one row per switch, one column per health metric."""
    cols = [  # name, data (1 item / 2 host name), item name, display (1 as is / 2 bar), decimals, thresholds
        ("Switch", 2, "", 1, 0, ()),
        ("Reachable", 1, "ICMP ping", 1, 0, UP_DOWN),
        ("CPU %", 1, "CPU utilization", 2, 1, PCT_TH),
        ("RAM %", 1, "RAM: Memory utilization", 2, 1, PCT_TH),
        ("Flash %", 1, "Flash: Space utilization", 2, 1, ((0, GREEN), (80, AMBER), (90, RED))),
        ("CPU temp", 1, "Cpu temp sensor: Temperature", 1, 1, TEMP_TH),
        ("Uptime", 1, "Uptime (network)", 1, 0, ()),
        ("Latency", 1, "ICMP response time", 1, 2, ()),
    ]
    fields = [f(GROUPREF, "groupids.0", groupid), f(INT, "column", 0), f(INT, "order", 2),
              f(INT, "show_lines", 20), f(INT, "rf_rate", 30)]
    for n, (cname, data, item, display, dec, th) in enumerate(cols):
        p = f"columns.{n}."
        fields += [f(STR, p + "name", cname), f(INT, p + "data", data), f(INT, p + "aggregate_function", 0),
                   f(INT, p + "decimal_places", dec), f(INT, p + "display", display), f(INT, p + "history", 1),   # 1 = auto
                   f(STR, p + "base_color", ""), f(STR, p + "text", "")]
        if data == 1:
            fields.append(f(STR, p + "item", item))
        if display == 2:
            fields += [f(STR, p + "min", "0"), f(STR, p + "max", "100")]
        for t, (thr, col) in enumerate(th):
            fields += [f(STR, f"columnsthresholds.{n}.color.{t}", col),
                       f(STR, f"columnsthresholds.{n}.threshold.{t}", str(thr))]
    return d.widget("tophosts", name, x, y, w, h, fields)


def build(z, cfg):
    gid = z.call("hostgroup.get", {"filter": {"name": [cfg["group"]]}, "output": ["groupid"]})[0]["groupid"]
    hosts = {h["host"]: h for h in z.call("host.get", {"groupids": gid, "output": ["hostid", "host", "name"]})}
    switches = cfg["switches"]
    vis = {host: hosts[host]["name"] for host, _, _ in switches}

    def items_of(host):
        its = z.call("item.get", {"hostids": hosts[host]["hostid"], "output": ["name", "key_"]})
        return {i["name"]: i["itemid"] for i in its} | {i["key_"]: i["itemid"] for i in its}

    def health_tiles(short, x0, y0, items, per_row):
        """Nine health tiles: 3 per row (overview halves) or 9 in one row (switch pages)."""
        width = 12 if per_row == 3 else 8
        pre = f"{short} · " if per_row == 3 else ""
        specs = [("ICMP ping", "reachable", 0, UP_DOWN), ("CPU utilization", "CPU", 1, PCT_TH),
                 ("RAM: Memory utilization", "RAM", 1, PCT_TH), ("Uptime (network)", "uptime", 0, ()),
                 ("Cpu temp sensor: Temperature", "CPU temp", 1, TEMP_TH),
                 ("Flash: Space utilization", "flash", 1, ((0, GREEN), (80, AMBER), (90, RED))),
                 ("sensor.psu.status[entStateOper.100711000]", "PSU 1", 0, PSU_TH),
                 ("sensor.psu.status[entStateOper.100721000]", "PSU 2", 0, PSU_TH),
                 ("ICMP response time", "latency", 1, ())]
        out = []
        for n, (key, label, dec, th) in enumerate(specs):
            col, row = n % per_row, n // per_row
            small = label in ("uptime", "PSU 1", "PSU 2", "latency")   # long values, e.g. "384 days, 01:02"
            out.append(tile(pre + label, items[key], x0 + col * width, y0 + row * 3, pre + label, w=width,
                            decimals=dec, th=th, value_size=16 if small else (22 if per_row == 9 else 26)))
        return out

    # ---------- Overview ----------
    ov = []
    if cfg["overview"] == "pair":
        for n, (host, short, _) in enumerate(switches):
            ov += health_tiles(short, n * 36, 0, items_of(host), per_row=3)
            ov.append(honeycomb(f"{short} interfaces ({MAP_LEGEND})", n * 36, 9, 36, 7,
                                hosts[host]["hostid"], IF_STATE_ITEMS, IF_STATUS_TH))
        ov.append(svg("Airtel and Jio uplinks on both switches (in = from ISP side)", 0, 16, 72, 6, list(vis.values()), [
            {"items": ["Interface Port-Channel51(*): Bits received"], "color": "E5484D", "label": "Airtel in", "fill": 2},
            {"items": ["Interface Port-Channel51(*): Bits sent"], "color": "F59E0B", "label": "Airtel out"},
            {"items": ["Interface Port-Channel52(*): Bits received"], "color": "2563EB", "label": "Jio in", "fill": 2},
            {"items": ["Interface Port-Channel52(*): Bits sent"], "color": "0EA5E9", "label": "Jio out"},
        ], legend_lines=8))
        ov.append(problems(f"{cfg['name']} problems (current and recent)", 0, 22, 72, 5, groupid=gid))
    else:   # spine/leaf fabric
        spines = [vis[h] for h, _, r in switches if r == "spine"]
        leaves = [vis[h] for h, _, r in switches if r == "leaf"]
        ov.append(health_table("Fabric health (one row per switch)", 0, 0, 72, 4, gid))
        for n, (host, short, role) in enumerate(switches):
            ov.append(honeycomb(f"{short} ({role}) interfaces ({MAP_LEGEND})", (n % 2) * 36, 4 + (n // 2) * 11,
                                36, 11, hosts[host]["hostid"], IF_STATE_ITEMS, IF_STATUS_TH))
        ov.append(svg("Spine <-> leaf fabric links", 0, 26, 36, 6, [], [
            {"hosts": spines, "items": ["Interface Port-Channel201(*): Bits sent"], "color": "2E9E5B",
             "label": "Spines -> leaves", "fill": 2},
            {"hosts": spines, "items": ["Interface Port-Channel201(*): Bits received"], "color": "2563EB",
             "label": "Leaves -> spines"},
            {"hosts": leaves, "items": ["Interface Port-Channel101(*): Bits received"], "color": "F59E0B",
             "label": "Leaf uplinks in", "width": 1},
            {"hosts": leaves, "items": ["Interface Port-Channel101(*): Bits sent"], "color": "E5484D",
             "label": "Leaf uplinks out", "width": 1}], legend_lines=8))
        ov.append(svg("Spines to VMware 100G spine and Forti-120G LAN", 36, 26, 36, 6, spines, [
            {"items": ["Interface Port-Channel203(*): Bits sent"], "color": "2563EB", "label": "To VMware", "fill": 2},
            {"items": ["Interface Port-Channel203(*): Bits received"], "color": "0EA5E9", "label": "From VMware"},
            {"items": ["Interface Port-Channel133(*): Bits sent"], "color": "F59E0B", "label": "To Forti LAN"},
            {"items": ["Interface Port-Channel133(*): Bits received"], "color": "E5484D", "label": "From Forti LAN"}],
            legend_lines=8))
        ov.append(svg("Peer links (MLAG)", 0, 32, 36, 5, [], [
            {"hosts": spines, "items": ["Interface Port-Channel100(*): Bits sent"], "color": "7C3AED", "label": "Spine peer"},
            {"hosts": leaves, "items": ["Interface Port-Channel41(*): Bits sent"], "color": "0D9488", "label": "Leaf peer"}]))
        ov.append(problems(f"{cfg['name']} problems (current and recent)", 36, 32, 36, 5, groupid=gid))
    pages = [{"name": "Overview", "widgets": ov}]

    # ---------- One page per switch ----------
    for page_no, (host, short, role) in enumerate(switches):
        hid, items = hosts[host]["hostid"], items_of(host)
        if_ref, hw_ref, st_ref, tr_ref = (page_ref(p, page_no) for p in ("SWI", "SWH", "SWS", "SWT"))
        me = [vis[host]]
        uplinks = UPLINKS[role]
        w = health_tiles(short, 0, 0, items, per_row=9)   # CPU / RAM as tiles; the grid is at most 64 rows high
        w += [
            honeycomb(f"Interface status ({MAP_LEGEND}) - click a port to graph it", 0, 3, 72, 10, hid,
                      IF_STATE_ITEMS, IF_STATUS_TH, ref=st_ref),
            follow_graph("Port state of the port clicked above (1 up, 2 down, 6 no module, 8 shutdown)",
                         0, 13, 72, 5, st_ref),
            honeycomb("Traffic in now, per interface - click a port to graph it", 0, 18, 72, 8, hid,
                      "Interface *: Bits received", TRAFFIC_TH, ref=tr_ref),
            follow_graph("Traffic in of the port clicked above", 0, 26, 72, 5, tr_ref),
            svg("Key uplinks: traffic in / out", 0, 31, 72, 6, me,
                [{"items": [f"Interface {ifn}(*): Bits received"], "color": col, "label": f"{lab} in", "fill": 2}
                 for ifn, lab, col in uplinks] +
                [{"items": [f"Interface {ifn}(*): Bits sent"], "color": col, "label": f"{lab} out", "width": 1}
                 for ifn, lab, col in uplinks], legend_lines=min(10, 2 * len(uplinks))),   # widget allows 1-10
            d.widget("itemnavigator", "Interfaces (status, traffic, errors) by port - click an item to graph it",
                     0, 37, 36, 9,
                     [f(HOSTREF, "hostids.0", hid), f(STR, "items.0", "Interface *"),
                      f(INT, "group_by.0.attribute", 3), f(STR, "group_by.0.tag_name", "interface"),
                      f(INT, "show_lines", 500), f(INT, "rf_rate", 30), f(STR, "reference", if_ref)]),
            follow_graph("Graph of the interface item selected on the left", 36, 37, 36, 9, if_ref),
            d.widget("itemnavigator",
                     "Health and hardware (tiles above, fans, power, temperatures) - click an item to graph it",
                     0, 46, 36, 7,
                     [f(HOSTREF, "hostids.0", hid)] + [f(STR, f"items.{n}", pat) for n, pat in enumerate(HEALTH_HW_ITEMS)] +
                     [f(INT, "group_by.0.attribute", 3), f(STR, "group_by.0.tag_name", "component"),
                      f(INT, "show_lines", 100), f(INT, "rf_rate", 60), f(STR, "reference", hw_ref)]),
            follow_graph("Graph of the health / hardware item selected on the left", 36, 46, 36, 7, hw_ref),
            svg("CPU and memory", 0, 53, 24, 5, me, [
                {"items": ["CPU utilization"], "color": "2563EB", "label": "CPU %"},
                {"items": ["RAM: Memory utilization"], "color": "7C3AED", "label": "RAM %"},
                {"items": ["Flash: Space utilization"], "color": "F59E0B", "label": "Flash %"}],
                extra=[f(INT, "lefty_max", 100)]),
            svg("Temperatures", 24, 53, 24, 5, me, [
                {"items": ["Cpu temp sensor: Temperature"], "color": RED, "label": "CPU"},
                {"items": ["Board*: Temperature"], "color": "0EA5E9", "label": "Board"},
                {"items": ["Inlet: Temperature", "Front-panel temp sensor: Temperature"], "color": "2E9E5B",
                 "label": "Inlet / front"},
                {"items": ["Hotspot: Temperature"], "color": "F59E0B", "label": "Hotspot"}], legend_lines=6),
            svg("Fan speeds", 48, 53, 24, 5, me, [
                {"items": ["Fan Tray * Fan *: Fan speed"], "color": "2E9E5B", "label": "Fan trays"},
                {"items": ["PowerSupply* Fan *: Fan speed"], "color": "F59E0B", "label": "PSU fans"}], legend_lines=6),
            # one graph plots at most ~100 items and each line sums every interface: one line per graph
            svg("In errors/s (all ports)", 0, 58, 12, 6, me, [
                {"items": ["Interface *: Inbound packets with errors"], "color": RED, "label": "In errors", "agg": 5}]),
            svg("Out errors/s (all ports)", 12, 58, 12, 6, me, [
                {"items": ["Interface *: Outbound packets with errors"], "color": "F97316", "label": "Out errors", "agg": 5}]),
            svg("In discards/s (all ports)", 24, 58, 12, 6, me, [
                {"items": ["Interface *: Inbound packets discarded"], "color": "7C3AED", "label": "In discards", "agg": 5}]),
            svg("Out discards/s (all ports)", 36, 58, 12, 6, me, [
                {"items": ["Interface *: Outbound packets discarded"], "color": "0EA5E9", "label": "Out discards", "agg": 5}]),
            problems(f"{short} problems", 48, 58, 24, 6, hostid=hid),
        ]
        pages.append({"name": f"{host} ({short})", "widgets": w})

    dash = z.call("dashboard.get", {"filter": {"name": [cfg["name"]]}, "output": ["dashboardid"]})
    click_to_graph.link_pages(pages, cfg["name"], z=z)   # page item list + graphs where there is room
    params = {"name": cfg["name"], "display_period": 60, "auto_start": 0, "pages": pages}
    if dash:
        z.call("dashboard.update", {"dashboardid": dash[0]["dashboardid"], **params})
        print(f'Updated dashboard "{cfg["name"]}" ({dash[0]["dashboardid"]})')
    else:
        print(f'Created dashboard "{cfg["name"]}" ({z.call("dashboard.create", params)["dashboardids"][0]})')


def main():
    z = base.Zabbix()
    for cfg in DASHBOARDS:
        build(z, cfg)


if __name__ == "__main__":
    main()
