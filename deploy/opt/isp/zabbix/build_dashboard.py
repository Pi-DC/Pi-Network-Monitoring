#!/usr/bin/env python3
"""Build the "A10 LLB & ISP Links" Zabbix dashboard (NOC overview + one page per ISP).

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
