#!/usr/bin/env python3
"""Build the "ASR Routers" dashboard for the Cisco ASR920 edge routers (add_routers.py).

  Overview  - both routers side by side: health tiles, BGP session map, interface map, key-link traffic, problems
  One page per router - health, CPU/memory, interface status + traffic maps, key links, BGP peers (state,
                        prefixes, details), optics, temperatures, errors/discards, problems

Re-runnable: the dashboard is rebuilt in place.
"""
import build_dashboard as d
import build_switch_dashboard as sw
import click_to_graph
import setup_isp_links as base

f, INT, STR, HOSTREF = d.f, d.INT, d.STR, d.HOSTREF
GREEN, AMBER, RED = d.GREEN, d.AMBER, d.RED

NAME = "ASR Routers"
GROUP = "WAN Routers"
ROUTERS = [("ASR_RTR-1", "RTR-1 Airtel"), ("ASR_RTR-2", "RTR-2 Jio")]
KEY_LINKS = {  # (interface, label, colour)
    "ASR_RTR-1": [("Po40", "A10-LLB", "E5484D"), ("Po30", "10G colo switches", "2563EB"),
                  ("Po20", "Colo WAN-SW", "2E9E5B"), ("Po10", "WAN-SW-2", "F59E0B"),
                  ("Te0/0/15", "Airtel uplink", "7C3AED")],
    "ASR_RTR-2": [("Po40", "A10-LLB", "E5484D"), ("Po30", "10G colo switches", "2563EB"),
                  ("Po20", "Colo WAN-SW", "2E9E5B"), ("Po10", "WAN-SW-1", "F59E0B"),
                  ("Te0/0/15", "Jio uplink", "7C3AED"), ("Gi0/0/8", "PowerGrid ILL", "0D9488")],
}
# BGP session state (add_routers.py): 0 shutdown, 1 idle, 2 connect, 3 active, 4/5 opensent/openconfirm, 6 established
BGP_TH = ((0, sw.SLATE), (1, RED), (2, AMBER), (6, GREEN))
BGP_LABEL = '{{ITEM.NAME}.regsub("^BGP peer ([0-9.]+) [(]AS([0-9]+)[)]", "\\1 AS\\2")}'
FRU_TH = ((1, AMBER), (2, GREEN), (3, RED), (4, AMBER), (5, RED), (8, RED))   # PSU 2 = on, fan 2 = up
ASIC_TH = ((0, GREEN), (80, AMBER), (88, RED))
MAP_LEGEND = "green up / red down / grey no module / dark grey shutdown"


def bgp_map(name, x, y, w, h, hostid, ref=None):
    fields = [f(HOSTREF, "hostids.0", hostid), f(STR, "items.0", "BGP peer *: Session state"),
              f(INT, "show.0", 1), f(INT, "show.1", 2),
              f(INT, "primary_label_type", 0), f(STR, "primary_label", BGP_LABEL),
              f(INT, "primary_label_size_type", 0), f(INT, "primary_label_bold", 1),
              f(INT, "secondary_label_type", 1), f(INT, "secondary_label_decimal_places", 0), f(INT, "rf_rate", 30)]
    if ref:
        fields.append(f(STR, "reference", ref))
    return d.widget("honeycomb", name, x, y, w, h, fields + d.thresholds(*BGP_TH))


def negative_axis(widget, minimum):
    """sw.svg pins the left Y axis at 0; dBm values are negative. (A duplicate field breaks the dashboard.)"""
    widget["fields"] = [x for x in widget["fields"] if x["name"] != "lefty_min"] + [f(STR, "lefty_min", minimum)]
    return widget


def navigator(name, x, y, w, h, hostid, patterns, tag, lines=200, rate=30, ref=None):
    """Item navigator; with `ref`, a sw.follow_graph() can graph the item clicked in it."""
    fields = [f(HOSTREF, "hostids.0", hostid)] + [f(STR, f"items.{i}", p) for i, p in enumerate(patterns)]
    fields += [f(INT, "group_by.0.attribute", 3), f(STR, "group_by.0.tag_name", tag),
               f(INT, "show_lines", lines), f(INT, "rf_rate", rate)]
    if ref:
        fields.append(f(STR, "reference", ref))
    return d.widget("itemnavigator", name, x, y, w, h, fields)


def main():
    z = base.Zabbix()
    gid = z.call("hostgroup.get", {"filter": {"name": [GROUP]}, "output": ["groupid"]})[0]["groupid"]
    hosts = {h["host"]: h for h in z.call("host.get", {"groupids": gid, "output": ["hostid", "host", "name"]})}
    vis = {host: hosts[host]["name"] for host, _ in ROUTERS}

    def items_of(host):
        its = z.call("item.get", {"hostids": hosts[host]["hostid"], "output": ["name", "key_"]})
        out = {i["name"]: i["itemid"] for i in its} | {i["key_"]: i["itemid"] for i in its}
        out["cpu"] = next(i["itemid"] for i in its if i["key_"].startswith("system.cpu.util[cpmCPUTotal5minRev"))
        out["mem"] = next(i["itemid"] for i in its if i["name"] == "Processor: Memory utilization")
        return out

    def health_tiles(short, x0, y0, items, per_row):
        width = 12 if per_row == 3 else 8
        pre = f"{short} · " if per_row == 3 else ""
        specs = [("ICMP ping", "reachable", 0, sw.UP_DOWN), ("cpu", "CPU", 1, sw.PCT_TH),
                 ("mem", "memory", 1, sw.PCT_TH), ("Uptime (network)", "uptime", 0, ()),
                 ("Temp: Cylon R0/18: Temperature", "ASIC temp", 0, ASIC_TH),
                 ("Temp: Inlet R0/16: Temperature", "inlet temp", 0, sw.TEMP_TH),
                 ("Power Supply Module 0: Power supply status", "PSU 0", 0, FRU_TH),
                 ("Power Supply Module 1: Power supply status", "PSU 1", 0, FRU_TH),
                 ("Fan Tray: Fan tray status", "fans", 0, FRU_TH)]
        out = []
        for n, (key, label, dec, th) in enumerate(specs):
            col, row = n % per_row, n // per_row
            small = label in ("uptime", "PSU 0", "PSU 1", "fans")
            out.append(sw.tile(pre + label, items[key], x0 + col * width, y0 + row * 3, pre + label, w=width,
                               decimals=dec, th=th, value_size=16 if small else (22 if per_row == 9 else 26)))
        return out

    def link_graph(title, x, y, w, h, host, legend=10):
        links = KEY_LINKS[host]
        return sw.svg(title, x, y, w, h, [vis[host]],
                      [{"items": [f"Interface {ifn}(*): Bits received"], "color": col, "label": f"{lab} in", "fill": 2}
                       for ifn, lab, col in links] +
                      [{"items": [f"Interface {ifn}(*): Bits sent"], "color": col, "label": f"{lab} out", "width": 1}
                       for ifn, lab, col in links], legend_lines=min(legend, 2 * len(links)))

    # ---------- Overview ----------
    ov = []
    for n, (host, short) in enumerate(ROUTERS):
        x, hid = n * 36, hosts[host]["hostid"]
        ov += health_tiles(short, x, 0, items_of(host), per_row=3)
        ov.append(bgp_map(f"{short} BGP peers (green established / red down / grey shutdown)", x, 9, 36, 4, hid))
        ov.append(sw.honeycomb(f"{short} interfaces ({MAP_LEGEND})", x, 13, 36, 5, hid,
                               sw.IF_STATE_ITEMS, sw.IF_STATUS_TH))
        ov.append(link_graph(f"{short} key links (in = into the router)", x, 18, 36, 7, host, legend=8))
    ov.append(sw.problems(f"{NAME} problems (current and recent)", 0, 25, 72, 5, groupid=gid))
    pages = [{"name": "Overview", "widgets": ov}]

    # ---------- One page per router ----------
    for page_no, (host, short) in enumerate(ROUTERS):
        hid, items = hosts[host]["hostid"], items_of(host)
        bgp_ref, if_ref, hw_ref, st_ref, tr_ref, bm_ref = (sw.page_ref(p, page_no)
                                                          for p in ("RTB", "RTI", "RTH", "RTS", "RTT", "RTM"))
        me = [vis[host]]
        w = health_tiles(short, 0, 0, items, per_row=9)   # CPU / memory as tiles
        w += [   # the grid is at most 64 rows high; ~22 ports, so half-width maps keep readable labels
            sw.honeycomb(f"Interface status ({MAP_LEGEND}) - click a port", 0, 3, 36, 5, hid,
                         sw.IF_STATE_ITEMS, sw.IF_STATUS_TH, ref=st_ref),
            sw.honeycomb("Traffic in now, per interface - click a port", 36, 3, 36, 5, hid,
                         "Interface *: Bits received", sw.TRAFFIC_TH, ref=tr_ref),
            sw.follow_graph("Port state of the port clicked above (1 up, 2 down, 6 no module, 8 shutdown)",
                            0, 8, 36, 5, st_ref),
            sw.follow_graph("Traffic in of the port clicked above", 36, 8, 36, 5, tr_ref),
            link_graph("Key links: traffic in / out", 0, 13, 72, 6, host),
            bgp_map("BGP peers (green established / amber connecting / red idle / grey shutdown) - click a peer",
                    0, 19, 36, 5, hid, ref=bm_ref),
            sw.follow_graph("Session state of the peer clicked on the left (6 established, 0 shutdown)",
                            36, 19, 36, 5, bm_ref),
            navigator("BGP peers: state, admin, prefixes, time in state - click an item to graph it", 0, 24, 24, 8,
                      hid, ["BGP peer *"], "peer", ref=bgp_ref),
            sw.follow_graph("Graph of the BGP item selected on the left", 24, 24, 24, 8, bgp_ref),
            sw.svg("BGP accepted IPv4 prefixes", 48, 24, 24, 8, me, [
                {"items": ["BGP peer *: Accepted IPv4 prefixes"], "color": "2563EB", "label": "prefixes"}],
                legend_lines=10),
            navigator("Interfaces (status, traffic, errors) by port - click an item to graph it", 0, 32, 36, 8, hid,
                      ["Interface *"], "interface", lines=500, ref=if_ref),
            sw.follow_graph("Graph of the interface item selected on the left", 36, 32, 36, 8, if_ref),
            navigator("Health and hardware (tiles above, power, fans, temperatures, optics) - click an item to graph it",
                      0, 40, 36, 8, hid,
                      ["ICMP ping", "ICMP response time", "*: CPU utilization", "Processor: Memory utilization",
                       "Uptime (network)", "*Power supply status", "*Fan tray status", "*: Temperature", "*: Voltage", "*: Current",
                       "*: Optical power"], "component", lines=150, rate=60, ref=hw_ref),
            sw.follow_graph("Graph of the health / hardware item selected on the left", 36, 40, 36, 8, hw_ref),
            sw.svg("CPU and memory", 0, 48, 24, 5, me, [
                {"items": ["*: CPU utilization"], "color": "2563EB", "label": "CPU %"},
                {"items": ["Processor: Memory utilization"], "color": "7C3AED", "label": "Memory %"}],
                extra=[f(INT, "lefty_max", 100)]),
            negative_axis(sw.svg("Optics: receive power (dBm)", 24, 48, 24, 5, me, [
                {"items": ["*Rx Power Sensor: Optical power"], "color": "2E9E5B", "label": "Rx"}],
                legend_lines=6), "-40"),
            sw.svg("Temperatures", 48, 48, 24, 5, me, [
                {"items": ["Temp: Cylon R0/18: Temperature"], "color": RED, "label": "ASIC"},
                {"items": ["Temp: Board R0/19: Temperature"], "color": "0EA5E9", "label": "Board"},
                {"items": ["Temp: Inlet R0/16: Temperature"], "color": "2E9E5B", "label": "Inlet"},
                {"items": ["Temp: Outlet R0/17: Temperature"], "color": "F59E0B", "label": "Outlet"},
                {"items": ["*transceiver * Temperature Sensor: Temperature"], "color": "7C3AED", "label": "Optics",
                 "width": 1}], legend_lines=8),
            sw.svg("In errors/s (all ports)", 0, 53, 18, 5, me, [
                {"items": ["Interface *: Inbound packets with errors"], "color": RED, "label": "In errors", "agg": 5}]),
            sw.svg("Out errors/s (all ports)", 18, 53, 18, 5, me, [
                {"items": ["Interface *: Outbound packets with errors"], "color": "F97316", "label": "Out errors", "agg": 5}]),
            sw.svg("In discards/s (all ports)", 36, 53, 18, 5, me, [
                {"items": ["Interface *: Inbound packets discarded"], "color": "7C3AED", "label": "In discards", "agg": 5}]),
            sw.svg("Out discards/s (all ports)", 54, 53, 18, 5, me, [
                {"items": ["Interface *: Outbound packets discarded"], "color": "0EA5E9", "label": "Out discards", "agg": 5}]),
            sw.problems(f"{short} problems", 0, 58, 72, 6, hostid=hid),
        ]
        pages.append({"name": f"{host} ({short})", "widgets": w})

    dash = z.call("dashboard.get", {"filter": {"name": [NAME]}, "output": ["dashboardid"]})
    click_to_graph.link_pages(pages, NAME, z=z)   # page item list + graphs where there is room
    params = {"name": NAME, "display_period": 60, "auto_start": 0, "pages": pages}
    if dash:
        z.call("dashboard.update", {"dashboardid": dash[0]["dashboardid"], **params})
        print(f'Updated dashboard "{NAME}" ({dash[0]["dashboardid"]})')
    else:
        print(f'Created dashboard "{NAME}" ({z.call("dashboard.create", params)["dashboardids"][0]})')


if __name__ == "__main__":
    main()
