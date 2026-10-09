#!/usr/bin/env python3
"""Click-to-graph for every Zabbix dashboard.

1. Every page (that still has room after step 2) gets an item navigator "Items on this page" listing the items its other widgets show (item tiles,
   gauges, SVG graphs, pie charts, top hosts, ...), with a follow graph beside it, placed at the bottom of the page
   (PAGE_ROWS high, skipped when the page has no room). It is kept in step with the page on every run.
2. Widgets that broadcast the item you click (item navigator, honeycomb) get a classic graph widget that follows
the clicked item. A source that has no such graph yet gets one placed directly below it (same x and width,
GRAPH_ROWS high) and everything below is moved down; if that would push the page past the 64-row grid the
source is left alone. Sources already linked (e.g. the side-by-side graphs build_switch_dashboard.py places)
are skipped, as is any source whose name ends with OPT_OUT. A dashboard whose name ends with OPT_OUT is left alone.

Used by the dashboard builders (link_pages) and run from /etc/cron.d/zabbix-click-to-graph for all dashboards,
so new devices, new pages and hand-made dashboards get the graphs automatically. Prints only what it changes (-v: also sources skipped for lack of room).
"""
import random
import re
import string
import sys

import setup_isp_links as base

SOURCES = ("itemnavigator", "honeycomb")
GRAPH_ROWS = 6
PAGE_ROWS = 8
PAGE_NAV = "Items on this page - click one to graph it"
MAX_ROWS = 64          # DASHBOARD_MAX_ROWS
OPT_OUT = "[no graph]"
INT, STR, GROUPREF, HOSTREF, ITEMREF = 0, 1, 2, 3, 4


def _field(w, name):
    return next((x["value"] for x in w["fields"] if x["name"] == name), None)


def _bottom(w):
    return int(w["y"]) + int(w["height"])


def _new_ref(used):
    while True:
        ref = "".join(random.choices(string.ascii_uppercase, k=5))
        if ref not in used:
            used.add(ref)
            return ref


def graph_name(source_name):
    short = re.sub(r"\s*(\(.*\)|- click an item to graph it)\s*$", "", source_name or "").strip() or "Selection"
    return f"{short} - graph of the clicked item"


def follow_graph(name, x, y, w, h, ref):
    """Classic simple graph of whatever item is selected in the widget with reference `ref`."""
    return {"type": "graph", "name": name, "x": x, "y": y, "width": w, "height": h, "view_mode": 0,
            "fields": [{"type": INT, "name": "source_type", "value": 1},
                       {"type": STR, "name": "itemid._reference", "value": ref + "._itemid"},
                       {"type": INT, "name": "show_legend", "value": 1},
                       {"type": INT, "name": "rf_rate", "value": 30}]}


def _page_items(z, widgets):
    """(hostids, item name patterns) of everything the page's non-navigator widgets show."""
    hostids, patterns, host_patterns, itemids = set(), [], set(), set()

    def want(pattern):
        if pattern and pattern not in patterns:
            patterns.append(pattern)

    for w in widgets:
        if w["type"] in SOURCES or (w["type"] == "graph" and _field(w, "itemid._reference")):
            continue
        fields = {x["name"]: x for x in w["fields"]}
        for x in w["fields"]:
            name, ftype = x["name"], int(x["type"])
            if ftype == ITEMREF:
                itemids.add(str(x["value"]))
            elif w["type"] in ("svggraph", "piechart") and re.fullmatch(r"ds\.\d+\.hosts\.\d+", name):
                host_patterns.add(x["value"])
            elif w["type"] in ("svggraph", "piechart") and re.fullmatch(r"ds\.\d+\.items\.\d+", name):
                want(x["value"])
            elif w["type"] == "tophosts" and ftype == HOSTREF:
                hostids.add(str(x["value"]))
            elif w["type"] == "tophosts" and ftype == GROUPREF:
                hostids.update(h["hostid"] for h in z.call("host.get", {"groupids": [x["value"]], "output": ["hostid"],
                                                                        "monitored_hosts": True}))
            elif w["type"] == "tophosts" and re.fullmatch(r"columns\.\d+\.item", name):
                if str(fields.get(name.rsplit(".", 1)[0] + ".data", {}).get("value", "1")) == "1":
                    want(x["value"])
    for hp in host_patterns:
        hostids.update(h["hostid"] for h in z.call("host.get", {"search": {"name": hp}, "searchWildcardsEnabled": True,
                                                                "output": ["hostid"]}))
    if itemids:
        for it in z.call("item.get", {"itemids": sorted(itemids), "output": ["hostid", "name_resolved"],
                                      "webitems": True}):
            hostids.add(it["hostid"])
            want(it["name_resolved"])
    return sorted(hostids, key=int), patterns


def page_navigator(name, x, y, w, h, hostids, patterns, ref):
    fields = [{"type": HOSTREF, "name": f"hostids.{i}", "value": hid} for i, hid in enumerate(hostids)]
    fields += [{"type": STR, "name": f"items.{i}", "value": p} for i, p in enumerate(patterns)]
    fields += [{"type": INT, "name": "group_by.0.attribute", "value": 1},   # group by host name
               {"type": INT, "name": "show_lines", "value": 500}, {"type": INT, "name": "rf_rate", "value": 30},
               {"type": STR, "name": "reference", "value": ref}]
    return {"type": "itemnavigator", "name": name, "x": x, "y": y, "width": w, "height": h, "view_mode": 0,
            "fields": fields}


def _nav_content(w):
    return ([str(x["value"]) for x in w["fields"] if x["name"].startswith("hostids.")],
            [x["value"] for x in w["fields"] if x["name"].startswith("items.")])


def add_page_navigators(z, pages, label="", verbose=False, used=None):
    """Step 1 (see module doc): add or refresh the per-page item navigator; returns the number of changes."""
    used = used if used is not None else {_field(w, "reference") for p in pages for w in p["widgets"]} - {None}
    changed = 0
    for page in pages:
        widgets = page["widgets"]
        mine = [w for w in widgets if w["type"] == "itemnavigator" and w.get("name") == PAGE_NAV]
        hostids, patterns = _page_items(z, widgets)
        where = f"{label} / {page.get('name') or '-'}"
        if mine:   # keep it in step with what the page shows
            nav = mine[0]
            if not hostids or not patterns:
                continue
            if _nav_content(nav) != (hostids, patterns):
                content = re.compile(r"(hostids|items)\.\d+$")
                fresh = page_navigator(PAGE_NAV, 0, 0, 1, 1, hostids, patterns, "")["fields"]
                nav["fields"] = [x for x in nav["fields"] if not content.match(x["name"])] + \
                    [x for x in fresh if content.match(x["name"])]
                print(f"  ~ {where}: page item list refreshed ({len(patterns)} items)")
                changed += 1
            continue
        if not hostids or not patterns:
            continue
        bottom = max((_bottom(w) for w in widgets), default=0)
        if bottom + PAGE_ROWS > MAX_ROWS:
            if verbose:
                print(f"  skip (page full): {where} / {PAGE_NAV}", file=sys.stderr)
            continue
        ref = _new_ref(used)
        widgets.append(page_navigator(PAGE_NAV, 0, bottom, 36, PAGE_ROWS, hostids, patterns, ref))
        widgets.append(follow_graph("Graph of the page item selected on the left", 36, bottom, 36, PAGE_ROWS, ref))
        print(f"  + {where}: page item list ({len(patterns)} items) + graph")
        changed += 1
    return changed


def link_pages(pages, label="", verbose=False, z=None):
    """Add follow graphs to `pages` (dashboard.get / builder format) in place; returns the number of changes.
    With a Zabbix API `z`, also adds the per-page item navigators (step 1).
    verbose: also report what was skipped because the page is full (cron runs stay quiet)."""
    used = {_field(w, "reference") for p in pages for w in p["widgets"]} - {None}
    added = 0
    for page in pages:
        widgets = page["widgets"]
        linked = {str(_field(w, "itemid._reference") or "").split(".")[0] for w in widgets if w["type"] == "graph"}
        todo = [w for w in widgets if w["type"] in SOURCES and not (w.get("name") or "").endswith(OPT_OUT)
                and (_field(w, "reference") is None or _field(w, "reference") not in linked)]
        # one inserted band per distinct bottom edge; work bottom-up so upper bands still see their own rows
        for bottom in sorted({_bottom(w) for w in todo}, reverse=True):
            group = [w for w in todo if _bottom(w) == bottom]
            if max(_bottom(w) for w in widgets) + GRAPH_ROWS > MAX_ROWS:
                for w in group if verbose else ():
                    print(f"  skip (page full): {label} / {page.get('name') or '-'} / {w.get('name')}", file=sys.stderr)
                continue
            for w in widgets:
                if int(w["y"]) >= bottom:
                    w["y"] = int(w["y"]) + GRAPH_ROWS
            for w in group:
                ref = _field(w, "reference")
                if ref is None:
                    ref = _new_ref(used)
                    w["fields"].append({"type": STR, "name": "reference", "value": ref})
                widgets.append(follow_graph(graph_name(w.get("name")), int(w["x"]), bottom, int(w["width"]),
                                            GRAPH_ROWS, ref))
                print(f"  + {label} / {page.get('name') or '-'} / {w.get('name')}")
                added += 1
    # page item lists last: graphs for the maps / lists come first when a page is short of room
    return added + (add_page_navigators(z, pages, label, verbose, used) if z is not None else 0)


def main():
    verbose = "-v" in sys.argv[1:]
    z = base.Zabbix()
    for dash in z.call("dashboard.get", {"output": ["dashboardid", "name"], "selectPages": "extend"}):
        pages = dash["pages"]
        if dash["name"].endswith(OPT_OUT):
            continue
        if link_pages(pages, dash["name"], verbose, z):
            z.call("dashboard.update", {"dashboardid": dash["dashboardid"], "pages": pages})
            print(f'Updated dashboard "{dash["name"]}" ({dash["dashboardid"]})')


if __name__ == "__main__":
    main()
