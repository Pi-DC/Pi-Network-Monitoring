#!/usr/bin/env python3
"""Build the fabric dashboards: "Pi VMware Fabric" (add_vmware_fabric.py; Arista, Cisco Catalyst, HPE Comware) and
"Pi MMR Cross Connect Fabric" (add_mmr_fabric.py; Cisco Catalyst). Each is built from the host group of the same name.
Usage: build_fabric_dashboard.py [dashboard name ...]   (default: all of FABRICS)

  Overview            - fabric health table (one row per switch), interface map per switch, problems
  One page per switch - health tiles, interface status + traffic maps, port-channel traffic, interface list,
                        health and hardware list (each with a graph of the clicked item), CPU / memory,
                        temperature, fans / PSUs (each only on switches that report it), errors and discards, problems

Switches come from the host group (enabled hosts only, ordered spines first) and their "vendor" tag picks the
vendor-specific item patterns; the health figures are the vendor-neutral "Health: ..." items that
add_vmware_fabric.py adds to every template. Re-runnable: the dashboard is rebuilt in place, so re-run it after
adding or enabling a switch.
"""
import re
import sys

import build_dashboard as d
import build_switch_dashboard as sw
import click_to_graph
import setup_isp_links as base

f, INT, STR, HOSTREF = d.f, d.INT, d.STR, d.HOSTREF
GREEN, AMBER, RED = d.GREEN, d.AMBER, d.RED
FABRICS = ["Pi VMware Fabric", "Pi MMR Cross Connect Fabric", "Pi DH Cross Connect Fabric", "Pi 1G Colo Fabric"]   # dashboard name = host group name
GROUPREF = 2
VENDOR = {   # port-channel names and extra hardware patterns per vendor tag
    "arista": {"lag": "Interface Port-Channel*", "hw": ["*Fan*", "*: Power supply status", "*: Voltage"]},
    "cisco": {"lag": "Interface Po*", "hw": ["*: Fan status", "*: Power supply status"]},
    "hpe": {"lag": "Interface Bridge-Aggregation*", "hw": ["*: Fan status", "*: Power supply status"]},
    "huawei": {"lag": "Interface Eth-Trunk*", "hw": ["*Fan*"]},
    "juniper": {"lag": "Interface ae*", "hw": ["*: Fan status", "*: Power supply status", "Overall system health status"]},
}
HEALTH_ITEMS = ["Health: *", "ICMP ping", "ICMP loss", "ICMP response time", "Uptime (network)", "*CPU utilization",
                "*Memory utilization", "*: Temperature"]
TEMP_TH = ((0, GREEN), (85, AMBER), (95, RED))   # spine fabric/Jericho ASICs run at 75-87 °C normally
BAD_TH = ((0, GREEN), (1, RED))


def health_table(name, x, y, w, h, groupid):
    cols = [  # name, data (1 item / 2 host name), item name, display (1 as is / 2 bar), decimals, thresholds
        ("Switch", 2, "", 1, 0, ()),
        ("Reachable", 1, "ICMP ping", 1, 0, sw.UP_DOWN),
        ("CPU %", 1, "Health: CPU utilization", 2, 1, sw.PCT_TH),
        ("Memory %", 1, "Health: Memory utilization", 2, 1, sw.PCT_TH),
        ("Hottest sensor °C", 1, "Health: Highest temperature", 1, 1, TEMP_TH),
        ("Fans not OK", 1, "Health: Fans not OK", 1, 0, BAD_TH),
        ("PSUs not OK", 1, "Health: Power supplies not OK", 1, 0, BAD_TH),
        ("Uptime", 1, "Uptime (network)", 1, 0, ()),
        ("Latency", 1, "ICMP response time", 1, 2, ()),
    ]
    fields = [f(GROUPREF, "groupids.0", groupid), f(INT, "column", 0), f(INT, "order", 2),
              f(INT, "show_lines", 20), f(INT, "rf_rate", 30)]
    for n, (cname, data, item, display, dec, th) in enumerate(cols):
        p = f"columns.{n}."
        fields += [f(STR, p + "name", cname), f(INT, p + "data", data), f(INT, p + "aggregate_function", 0),
                   f(INT, p + "decimal_places", dec), f(INT, p + "display", display), f(INT, p + "history", 1),
                   f(STR, p + "base_color", ""), f(STR, p + "text", "")]
        if data == 1:
            fields.append(f(STR, p + "item", item))
        if display == 2:
            fields += [f(STR, p + "min", "0"), f(STR, p + "max", "100")]
        for t, (thr, col) in enumerate(th):
            fields += [f(STR, f"columnsthresholds.{n}.color.{t}", col),
                       f(STR, f"columnsthresholds.{n}.threshold.{t}", str(thr))]
    return d.widget("tophosts", name, x, y, w, h, fields)


def navigator(name, x, y, w, h, hostid, patterns, tag, ref, lines=500, rate=30):
    fields = [f(HOSTREF, "hostids.0", hostid)] + [f(STR, f"items.{i}", p) for i, p in enumerate(patterns)]
    fields += [f(INT, "group_by.0.attribute", 3), f(STR, "group_by.0.tag_name", tag),
               f(INT, "show_lines", lines), f(INT, "rf_rate", rate), f(STR, "reference", ref)]
    return d.widget("itemnavigator", name, x, y, w, h, fields)


def tag(h, t):
    return next((x["value"] for x in h["tags"] if x["tag"] == t), "")


def port_count(z, h):
    return len(z.call("item.get", {"hostids": h["hostid"], "output": ["itemid"], "search": {"key_": "net.if.portstate["}}))


def has_sensor(z, h, sensor_key, health_key, health_name):
    """True if the switch reports any `sensor_key` item (temperature, fan or PSU sensors). Its matching health
    item is enabled or disabled to match (it is empty or always 0 without sensors - e.g. no temperature on a
    Catalyst 2960 LAN Lite, no PSU status on a Huawei S5720-LI), so it does not show up in the item lists, and
    the page leaves out that tile and graph."""
    sensors = z.call("item.get", {"hostids": h["hostid"], "search": {"key_": sensor_key + "["},
                                  "filter": {"status": 0}, "output": ["itemid"], "limit": 1})
    item = z.call("item.get", {"hostids": h["hostid"], "filter": {"key_": health_key},
                               "output": ["itemid", "status"]})
    want = "0" if sensors else "1"
    if item and item[0]["status"] != want:
        z.call("item.update", {"itemid": item[0]["itemid"], "status": int(want)})
        print(f'  {h["host"]}: "{health_name}" {"enabled" if sensors else "disabled (no sensors)"}')
    return bool(sensors)


def health_item(z, h, name):
    return z.call("item.get", {"hostids": h["hostid"], "filter": {"name": name}, "output": ["itemid"]})[0]["itemid"]


def short(h):
    return re.sub(r"^(100G_|MMR1[-_]|DH5[-_]|1G-COLO-)", "", h["host"]).replace("_SW-", " ")   # Spine 1, Leaf 7-8, SW5


def switch_page(z, h, page_no, ports, page_name=None):
    """One switch page (vendor-neutral "Health: ..." items; the vendor tag picks port-channel / hardware patterns).
    `h` = host with tags, `ports` = its number of ports, `page_no` keeps the widget references unique."""
    hid, me, vendor = h["hostid"], [h["name"]], VENDOR.get(tag(h, "vendor"), VENDOR["arista"])
    st_ref, tr_ref, if_ref, hw_ref = (sw.page_ref(p, page_no) for p in ("FBS", "FBT", "FBI", "FBH"))
    big = ports > 80
    temp = has_sensor(z, h, "sensor.temp.value", "health.temp.max", "Health: Highest temperature")
    fans = has_sensor(z, h, "sensor.fan.status", "health.fans.bad", "Health: Fans not OK")
    psus = has_sensor(z, h, "sensor.psu.status", "health.psu.bad", "Health: Power supplies not OK")
    tiles = [("ICMP ping", "reachable", 0, sw.UP_DOWN), ("Health: CPU utilization", "CPU", 1, sw.PCT_TH),
             ("Health: Memory utilization", "memory", 1, sw.PCT_TH),
             ("Health: Highest temperature", "hottest sensor", 1, TEMP_TH),
             ("Health: Fans not OK", "fans not OK", 0, BAD_TH),
             ("Health: Power supplies not OK", "PSUs not OK", 0, BAD_TH),
             ("Uptime (network)", "uptime", 0, ()), ("ICMP response time", "latency", 1, ()),
             ("ICMP loss", "packet loss", 1, ((0, GREEN), (1, AMBER), (20, RED)))]
    missing = {name for name, present in (("Health: Highest temperature", temp), ("Health: Fans not OK", fans),
                                          ("Health: Power supplies not OK", psus)) if not present}
    tiles = [t for t in tiles if t[0] not in missing]
    # share the 72 columns: e.g. 9 tiles x 8, 7 tiles as 10/10/10/10/10/11/11
    widths = [72 // len(tiles) + (n >= len(tiles) - 72 % len(tiles)) for n in range(len(tiles))]
    w = [sw.tile(label, health_item(z, h, item), sum(widths[:n]), 0, label, w=widths[n], decimals=dec, th=th,
                 value_size=16 if label in ("uptime", "latency") else 22)
         for n, (item, label, dec, th) in enumerate(tiles)]
    sm, tm = (9, 7) if big else (6, 5)   # map heights: larger switches need bigger cells for readable labels
    y = 3
    w += [sw.honeycomb(f"Interface status ({sw.MAP_LEGEND}) - click a port to graph it", 0, y, 72, sm, hid,
                       sw.IF_STATE_ITEMS, sw.IF_STATUS_TH, ref=st_ref),
          sw.follow_graph("Port state of the port clicked above (1 up, 2 down, 6 no module, 8 shutdown)",
                          0, y + sm, 72, 5, st_ref)]
    y += sm + 5
    w += [sw.honeycomb("Traffic in now, per interface - click a port to graph it", 0, y, 72, tm, hid,
                       "Interface *: Bits received", sw.TRAFFIC_TH, ref=tr_ref),
          sw.follow_graph("Traffic in of the port clicked above", 0, y + tm, 72, 5, tr_ref)]
    y += tm + 5
    w.append(sw.svg("Port-channel traffic (in filled, out lines)", 0, y, 72, 6, me, [
        {"items": [vendor["lag"] + ": Bits received"], "color": "2563EB", "label": "in", "fill": 2},
        {"items": [vendor["lag"] + ": Bits sent"], "color": "F59E0B", "label": "out", "width": 1}],
        legend_lines=10))
    y += 6
    w += [navigator("Interfaces (status, traffic, errors) by port - click an item to graph it", 0, y, 36, 9, hid,
                    ["Interface *"], "interface", if_ref),
          sw.follow_graph("Graph of the interface item selected on the left", 36, y, 36, 9, if_ref)]
    y += 9
    w += [navigator("Health and hardware (tiles above, CPU, memory, temperatures, fans, power) - click an item "
                    "to graph it", 0, y, 36, 8, hid, HEALTH_ITEMS + vendor["hw"], "component", hw_ref,
                    lines=300, rate=60),
          sw.follow_graph("Graph of the health / hardware item selected on the left", 36, y, 36, 8, hw_ref)]
    y += 8
    rest = 64 - y   # the grid is at most 64 rows high; split what is left between two rows
    r1 = max(4, rest // 2)
    graphs = [("CPU and memory", [
                  {"items": ["Health: CPU utilization"], "color": "2563EB", "label": "CPU %"},
                  {"items": ["Health: Memory utilization"], "color": "7C3AED", "label": "Memory %"}],
               [f(INT, "lefty_max", 100)])]
    if temp:
        graphs.append(("Hottest temperature sensor", [
            {"items": ["Health: Highest temperature"], "color": RED, "label": "°C"}], []))
    hw = ([{"items": ["Health: Fans not OK"], "color": "F59E0B", "label": "fans"}] if fans else []) + \
         ([{"items": ["Health: Power supplies not OK"], "color": RED, "label": "PSUs"}] if psus else [])
    if hw:
        graphs.append((" and ".join(x for x, ok in (("Fans", fans), ("power supplies", psus)) if ok).capitalize()
                       + " not OK", hw, []))
    gx = 0
    for n, (title, datasets, extra) in enumerate(graphs):   # share the row between the graphs that apply
        gw = 72 // len(graphs) + (n >= len(graphs) - 72 % len(graphs))
        w.append(sw.svg(title, gx, y, gw, r1, me, datasets, extra=extra))
        gx += gw
    y += r1
    w += [sw.svg("Errors and discards per second, all ports", 0, y, 36, 64 - y, me, [
              {"items": ["Health: Inbound errors, all ports"], "color": RED, "label": "in errors"},
              {"items": ["Health: Outbound errors, all ports"], "color": "F97316", "label": "out errors"},
              {"items": ["Health: Inbound discards, all ports"], "color": "7C3AED", "label": "in discards"},
              {"items": ["Health: Outbound discards, all ports"], "color": "0EA5E9", "label": "out discards"}],
              legend_lines=4),
          sw.problems(f"{short(h)} problems", 36, y, 36, 64 - y, hostid=hid)]
    return {"name": page_name or f"{short(h)} – {h['name']}", "widgets": w}


def build(z, NAME):
    gid = z.call("hostgroup.get", {"filter": {"name": [NAME]}, "output": ["groupid"]})[0]["groupid"]
    hosts = z.call("host.get", {"groupids": gid, "filter": {"status": 0}, "output": ["hostid", "host", "name"],
                                "selectTags": ["tag", "value"]})
    hosts.sort(key=lambda h: (tag(h, "role") != "spine", h["host"].replace("-", "_")))   # MMR1-SW5 after MMR1_SW4
    ports = {h["hostid"]: port_count(z, h) for h in hosts}

    # ---------- Overview ----------
    table_h = 2 + (len(hosts) + 1) // 2   # rows are compact: about two switches per grid row
    ov = [health_table("Fabric health (one row per switch)", 0, 0, 72, table_h, gid)]
    # port maps sized so the port names stay readable (sw.overview_map_size): switches with many ports get a
    # full-width row, the others are paired side by side (the pair shares the taller of the two heights)
    y, half = table_h, []

    def place(h, x, y, mw, mh):
        ov.append(sw.honeycomb(f"{short(h)} – {h['name']} ({sw.MAP_LEGEND})", x, y, mw, mh,
                               h["hostid"], sw.IF_STATE_ITEMS, sw.IF_STATUS_TH))

    def flush(y):
        if half:
            row_h = max(mh for _, mh in half)
            for n, (h, _) in enumerate(half):
                place(h, n * 36, y, 36, row_h)
            half.clear()
            y += row_h
        return y

    for h in hosts:
        mw, mh = sw.overview_map_size(ports[h["hostid"]])
        if mw == 72:
            y = flush(y)
            place(h, 0, y, 72, mh)
            y += mh
        else:
            half.append((h, mh))
            if len(half) == 2:
                y = flush(y)
    y = flush(y)
    ov.append(sw.problems(f"{NAME} problems (current and recent)", 0, y, 72, 4, groupid=gid))
    pages = [{"name": "Overview", "widgets": ov}]

    # ---------- One page per switch ----------
    pages += [switch_page(z, h, page_no, ports[h["hostid"]]) for page_no, h in enumerate(hosts)]

    click_to_graph.link_pages(pages, NAME, z=z)   # graphs under the overview maps, page item lists
    dash = z.call("dashboard.get", {"filter": {"name": [NAME]}, "output": ["dashboardid"]})
    params = {"name": NAME, "display_period": 60, "auto_start": 0, "pages": pages}
    if dash:
        z.call("dashboard.update", {"dashboardid": dash[0]["dashboardid"], **params})
        print(f'Updated dashboard "{NAME}" ({dash[0]["dashboardid"]})')
    else:
        print(f'Created dashboard "{NAME}" ({z.call("dashboard.create", params)["dashboardids"][0]})')


def main():
    z = base.Zabbix()
    for name in sys.argv[1:] or FABRICS:
        build(z, name)


if __name__ == "__main__":
    main()
