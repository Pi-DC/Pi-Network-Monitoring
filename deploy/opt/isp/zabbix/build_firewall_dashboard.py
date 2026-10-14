#!/usr/bin/env python3
"""Build the "Pi Firewall Fabric" dashboard from its host group (add_firewalls.py). Re-run after a device is added,
enabled or upgraded from ICMP-only to SNMP:  python3 build_firewall_dashboard.py

  Overview                - health table (every enabled device, ping-only ones too), firewall table (sessions,
                            session table use, VPN, NAT), sessions and VPN traffic of all firewalls, port maps, problems
  <firewall> – firewall   - sessions, session table, CPU (total / forwarding / management), memory, VPN tunnels and
                            traffic, NAT, DPI-SSL, model / serial / firmware, item list with graph, problems
  <FortiGate> – VPN & users   - IPsec tunnel map (phase-1 state), totals, traffic, every tunnel / selector / dial-up
                            gateway / SSL VPN user with graph, connected SSL VPN users and dial-up clients (lists)
  <FortiGate> – security & FortiGuard - contract expiry, update checks, definition versions, IPS / AV / web filter
                            per minute, conserve-mode memory, session rate, NPU / ephemeral tables, HA, config
                            changes, log devices, policy audit, per-VDOM counters with graph
  <SonicWall> – VPN & security - IPsec SA list and per-policy traffic, zone security services, syslog rate
  <device> – ports & health  - the fabric switch page (build_fabric_dashboard.switch_page): port maps, traffic,
                            interfaces, health; for the 1G-VDOM switch once its SNMP answers
Devices still waiting for SNMP (tag snmp=pending) show only in the health table (reachability and latency).
"""
import build_dashboard as d
import build_fabric_dashboard as fd
import build_switch_dashboard as sw
import click_to_graph
import coverage_pages
import setup_isp_links as base

NAME = "Pi Firewall Fabric"   # dashboard = host group
f, INT, STR = d.f, d.INT, d.STR
GREEN, AMBER, RED = d.GREEN, d.AMBER, d.RED
SESSION_TH = ((0, GREEN), (60, AMBER), (80, RED))
# tiles on a firewall page: item name, label, decimals, thresholds (only those the device has are shown)
FW_TILES = [("Firewall: Active sessions", "sessions", 0, ()),
            ("Firewall: Session table use", "session table", 1, SESSION_TH),
            ("Health: CPU utilization", "CPU", 1, sw.PCT_TH),
            ("Firewall: Forwarding and inspection CPU utilization", "fwd + inspect CPU", 1, sw.PCT_TH),
            ("Health: Memory utilization", "memory", 1, sw.PCT_TH),
            ("Firewall: VPN tunnels up (IPsec SAs)", "VPN SAs up", 0, ()),
            ("Firewall: VPN tunnels up", "VPN tunnels up", 0, ()),
            ("Firewall: VPN peers", "VPN peers", 0, ()),
            ("Firewall: SSL VPN users", "SSL VPN users", 0, ()),
            ("Firewall: NAT translations", "NAT", 0, ()),
            ("Uptime (network)", "uptime", 0, ())]
# model / serial / firmware (text) per vendor
INFO = {"sonicwall": ["SonicWall: Model", "SonicWall: Serial number", "SonicWall: Firmware version", "SonicWall: ROM version"],
        "fortinet": ["Hardware model name", "Hardware serial number", "Firmware version", "HA mode"]}
NUMERIC_ITEMS = ["Firewall: *", "Memory: *", "Processor module *", "Log partition*", "BGP peer *", "CPU utilization", "Memory utilization", "Health: CPU utilization",
                 "Health: Memory utilization", "ICMP response time", "ICMP loss"]


def items_by_name(z, h):
    return {i["name"]: i["itemid"] for i in z.call("item.get", {"hostids": h["hostid"], "output": ["name"],
                                                                "filter": {"status": 0}})}


def firewall_table(name, x, y, w, h, groupid):
    cols = [("Firewall", 2, "", 1, 0, ()),
            ("Active sessions", 1, "Firewall: Active sessions", 1, 0, ()),
            ("Session table %", 1, "Firewall: Session table use", 2, 2, SESSION_TH),
            ("VPN SAs up", 1, "Firewall: VPN tunnels up (IPsec SAs)", 1, 0, ()),
            ("VPN peers", 1, "Firewall: VPN peers", 1, 0, ()),
            ("VPN encrypted", 1, "Firewall: VPN traffic encrypted (sent into tunnels)", 1, 1, ()),
            ("VPN decrypted", 1, "Firewall: VPN traffic decrypted (received from tunnels)", 1, 1, ()),
            ("NAT translations", 1, "Firewall: NAT translations", 1, 0, ()),
            ("Fwd + inspect CPU %", 1, "Firewall: Forwarding and inspection CPU utilization", 2, 0, sw.PCT_TH),
            ("IPsec tunnels down", 1, "IPsec: tunnels down", 1, 0, ((0, GREEN), (1, AMBER))),
            ("SSL VPN users", 1, "Firewall: SSL VPN users", 1, 0, ()),
            ("FortiGuard days left", 1, "FortiGuard: days until the first contract expires", 1, 0,
             ((0, RED), (15, AMBER), (60, GREEN)))]
    fields = [f(fd.GROUPREF, "groupids.0", groupid), f(INT, "column", 1), f(INT, "order", 2),
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


def session_series(items):
    """SonicWall has one session table; FortiGate reports the ephemeral and NPU (offload) tables instead."""
    if "Firewall: Session table use" in items:
        return [{"items": ["Firewall: Session table use"], "color": "7C3AED", "label": "% used", "fill": 2}]
    return [{"items": [n], "color": c, "label": label, **extra}
            for n, c, label, extra in (("Firewall: ephemeral session table use", "7C3AED", "ephemeral", {"fill": 2}),
                                       ("Firewall: NPU session table use", "0EA5E9", "NPU", {"width": 1}))
            if n in items]


def vpn_traffic_graph(items, me, y):
    """SonicWall: encrypted / decrypted totals; FortiGate: IPsec in / out over all tunnels."""
    if "IPsec: traffic in (all tunnels)" in items and not any(n.startswith("Firewall: VPN traffic") for n in items):
        return sw.svg("IPsec traffic, all tunnels (in filled, out line)", 0, y, 36, 10, me, [
            {"items": ["IPsec: traffic in (all tunnels)"], "color": "2563EB", "label": "in", "fill": 2},
            {"items": ["IPsec: traffic out (all tunnels)"], "color": "F59E0B", "label": "out", "width": 1}])
    return sw.svg("VPN traffic (encrypted into tunnels filled, decrypted from tunnels line)", 0, y, 36, 10, me, [
        {"items": ["Firewall: VPN traffic encrypted*"], "color": "2563EB", "label": "encrypted", "fill": 2},
        {"items": ["Firewall: VPN traffic decrypted*"], "color": "F59E0B", "label": "decrypted", "width": 1}])


def firewall_page(z, h, page_no):
    items, me, hid = items_by_name(z, h), [h["name"]], h["hostid"]
    ref = sw.page_ref("FWI", page_no)
    tiles = [t for t in FW_TILES if t[0] in items]
    widths = [72 // len(tiles) + (n >= len(tiles) - 72 % len(tiles)) for n in range(len(tiles))]
    w = [sw.tile(label, items[item], sum(widths[:n]), 0, label, w=widths[n], decimals=dec, th=th,
                 value_size=16 if label == "uptime" else 22)
         for n, (item, label, dec, th) in enumerate(tiles)]
    y = 3
    w += [sw.svg("Active sessions and NAT translations", 0, y, 36, 10, me, [
              {"items": ["Firewall: Active sessions"], "color": "2563EB", "label": "sessions", "fill": 2},
              {"items": ["Firewall: NAT translations"], "color": "F59E0B", "label": "NAT", "width": 1}]),
          sw.svg("Session table use (%)", 36, y, 36, 10, me, session_series(items))]
    y += 10
    w += [sw.svg("CPU: total, forwarding + inspection, management (%)", 0, y, 36, 10, me, [
              {"items": ["Health: CPU utilization"], "color": "2563EB", "label": "total"},
              {"items": ["Firewall: Forwarding and inspection CPU utilization"], "color": "16A34A", "label": "fwd + inspect"},
              {"items": ["Firewall: Management CPU utilization"], "color": "F59E0B", "label": "management", "width": 1}],
              extra=[f(INT, "lefty_max", 100)]),
          sw.svg("Memory utilization (%)", 36, y, 36, 10, me, [
              {"items": ["Health: Memory utilization"], "color": "7C3AED", "label": "memory", "fill": 2}],
              extra=[f(INT, "lefty_max", 100)])]
    y += 10
    w += [vpn_traffic_graph(items, me, y),
          sw.svg("VPN tunnels / peers / users", 36, y, 36, 10, me, [
              {"items": ["Firewall: VPN tunnels up*"], "color": "16A34A", "label": "tunnels / SAs up"},
              {"items": ["Firewall: VPN peers", "Firewall: SSL VPN users"], "color": "0EA5E9", "label": "peers / users"}])]
    y += 10
    w += [navigator2("Firewall items - click one to graph it", 0, y, 36, 14, hid, NUMERIC_ITEMS, ["component"], ref,
                     lines=200),
          sw.follow_graph("Graph of the firewall item selected on the left", 36, y, 36, 14, ref)]
    y += 14
    info = [n for n in INFO.get(fd.tag(h, "vendor"), []) if n in items]
    for n, name in enumerate(info):
        iw = 72 // len(info) + (n >= len(info) - 72 % len(info))
        w.append(sw.tile(name.split(": ")[-1], items[name], sum(72 // len(info) + (k >= len(info) - 72 % len(info))
                                                                for k in range(n)), y, name.split(": ")[-1],
                         w=iw, decimals=0, value_size=12))
    y += 3 if info else 0
    peers = len([n for n in items if n.startswith("BGP peer ") and n.endswith(": state")])
    if peers:   # BGP4-MIB peers (add_model_items.py)
        mh = min(sw.map_rows(peers, 72, 3, 8), 64 - y - 4)
        w.append(sw.honeycomb(f"BGP peers ({peers}: green established, red not established)", 0, y, 72, mh, hid,
                              "BGP peer *: state", ((0, RED), (6, GREEN)),
                              label='{{ITEM.NAME}.regsub("^BGP peer ([^ ]+) .*", "\\1")}'))
        y += mh
    w.append(sw.problems(f"{fd.short(h)} problems", 0, y, 72, 64 - y, hostid=hid))
    return {"name": f"{fd.short(h)} – firewall", "widgets": w}


def tiles_row(items, specs, y, h=3):
    """A row of value tiles sharing the 72 columns; specs: (item name, label, decimals, thresholds)."""
    specs = [t for t in specs if t[0] in items]
    widths = [72 // len(specs) + (n >= len(specs) - 72 % len(specs)) for n in range(len(specs))] if specs else []
    return [sw.tile(label, items[name], sum(widths[:n]), y, label, w=widths[n], h=h,
                    decimals=0 if dec == "text" else dec, th=th,
                    value_size=12 if dec == "text" else 22)
            for n, (name, label, dec, th) in enumerate(specs)]


def history(name, x, y, w, h, itemid, column, lines=5):
    """Latest values of a text item (newest first): connected users, SA list, policy audit ..."""
    return d.widget("itemhistory", name, x, y, w, h, [
        f(STR, "columns.0.name", column), f(d.ITEM, "columns.0.itemid", itemid), f(INT, "columns.0.display", 1),
        f(INT, "columns.0.monospace_font", 1), f(INT, "show_lines", lines), f(INT, "show_timestamp", 1),
        f(INT, "sortorder", 0), f(INT, "show_column_header", 0), f(INT, "rf_rate", 60),
        # own period: these items store a value only on change (1-day heartbeat), so the dashboard's default
        # 1-hour period showed "No data found" for most of the day
        f(STR, "time_period.from", "now-7d"), f(STR, "time_period.to", "now")])


def navigator2(name, x, y, w, h, hostid, patterns, tags, ref, lines=3000):
    """Item navigator grouped by up to two tags (e.g. component, then tunnel)."""
    fields = [f(d.HOSTREF, "hostids.0", hostid)] + [f(STR, f"items.{i}", p) for i, p in enumerate(patterns)]
    for n, t in enumerate(tags):
        fields += [f(INT, f"group_by.{n}.attribute", 3), f(STR, f"group_by.{n}.tag_name", t)]
    # numeric items only (add_firewall_detail tags text items 'value: text'): a follow graph of a text item never
    # gets ready and breaks the PDF print of the dashboard
    fields += [f(INT, "item_tags_evaltype", 0), f(STR, "item_tags.0.tag", "value"), f(INT, "item_tags.0.operator", 5),
               f(STR, "item_tags.0.value", "")]
    fields += [f(INT, "show_lines", lines), f(INT, "rf_rate", 60), f(STR, "reference", ref)]
    return d.widget("itemnavigator", name, x, y, w, h, fields)


VPN_STATE_TH = ((0, RED), (1, AMBER), (2, GREEN))


def tunnel_map(name, x, y, w, h, hostid):
    """Honeycomb of IPsec phase-1 tunnels: green all selectors up, amber some, red none."""
    fields = [f(d.HOSTREF, "hostids.0", hostid), f(STR, "items.0", "IPsec tunnel *: state"),
              f(INT, "show.0", 1), f(INT, "show.1", 2), f(INT, "primary_label_type", 0),
              f(STR, "primary_label", '{{ITEM.NAME}.regsub("IPsec tunnel (.*): state", "\\1")}'),
              f(INT, "primary_label_size_type", 0), f(INT, "primary_label_bold", 1),
              f(INT, "secondary_label_type", 1), f(INT, "secondary_label_decimal_places", 0), f(INT, "rf_rate", 60)]
    return d.widget("honeycomb", name, x, y, w, h, fields + d.thresholds(*VPN_STATE_TH))


def fortigate_vpn_page(z, h, page_no):
    items, me, hid = items_by_name(z, h), [h["name"]], h["hostid"]
    w = tiles_row(items, [("IPsec: tunnels up", "IPsec tunnels up", 0, ()),
                          ("IPsec: tunnels partly up", "partly up", 0, ((0, GREEN), (1, AMBER))),
                          ("IPsec: tunnels down", "down", 0, ((0, GREEN), (1, RED))),
                          ("IPsec: tunnels configured", "configured", 0, ()),
                          ("IPsec: phase-2 selectors down", "selectors down", 0, ()),
                          ("IPsec dial-up: clients connected", "dial-up clients", 0, ()),
                          ("SSL VPN: users logged in (all VDOMs)", "SSL VPN users", 0, ()),
                          ("SSL VPN: tunnel-mode sessions (all VDOMs)", "SSL tunnels", 0, ()),
                          ("Firewall: authenticated users (all VDOMs)", "auth users", 0, ()),
                          ("IPsec: traffic in (all tunnels)", "IPsec in", 1, ()),
                          ("IPsec: traffic out (all tunnels)", "IPsec out", 1, ())], 0)
    y = 3
    cells = len([n for n in items if n.startswith("IPsec tunnel ") and n.endswith(": state")])
    mh = sw.map_rows(max(cells, 1), 72, 5, 10)
    w.append(tunnel_map(f"IPsec tunnels ({cells}: green all selectors up, amber some, red none)", 0, y, 72, mh, hid))
    y += mh
    w += [sw.svg("IPsec traffic, all tunnels (in filled, out line)", 0, y, 36, 8, me, [
              {"items": ["IPsec: traffic in (all tunnels)"], "color": "2563EB", "label": "in", "fill": 2},
              {"items": ["IPsec: traffic out (all tunnels)"], "color": "F59E0B", "label": "out", "width": 1}]),
          sw.svg("Tunnels up, dial-up clients, SSL VPN users", 36, y, 36, 8, me, [
              {"items": ["IPsec: tunnels up"], "color": "16A34A", "label": "IPsec tunnels up"},
              {"items": ["IPsec: tunnels down"], "color": "E5484D", "label": "IPsec tunnels down"},
              {"items": ["IPsec dial-up: clients connected"], "color": "7C3AED", "label": "dial-up clients"},
              {"items": ["SSL VPN: users logged in (all VDOMs)"], "color": "0EA5E9", "label": "SSL VPN users"}])]
    y += 8
    ref = sw.page_ref("FVN", page_no)
    w += [navigator2("Every tunnel, selector, dial-up gateway and SSL VPN user - click one to graph it", 0, y, 36, 16,
                     hid, ["IPsec*", "SSL VPN*"], ["component", "vpn"], ref),
          sw.follow_graph("Graph of the item selected on the left", 36, y, 36, 16, ref)]
    y += 16
    for n, (name, col) in enumerate((("SSL VPN: connected users", "Connected SSL VPN users (newest list first)"),
                                     ("IPsec dial-up: connected clients", "Connected IPsec dial-up clients"))):
        if name in items:
            w.append(history(col, n * 36, y, 36, 12, items[name], col))
    y += 12
    w.append(sw.problems(f"{fd.short(h)} VPN problems", 0, y, 72, 64 - y, hostid=hid))
    return {"name": f"{fd.short(h)} – VPN & users", "widgets": w}


def fortigate_security_page(z, h, page_no):
    items, me, hid = items_by_name(z, h), [h["name"]], h["hostid"]
    w = tiles_row(items, [("FortiGuard: days until the first contract expires", "contract days left", 0,
                           ((0, RED), (15, AMBER), (60, GREEN))),
                          ("FortiGuard: contract expiring first", "expires first", "text", ()),
                          ("FortiGuard: hours since the last update check", "h since update check", 1,
                           ((0, GREEN), (26, RED))),
                          ("FortiGuard: definition packages whose last update failed", "failed updates", 0,
                           ((0, GREEN), (1, RED))),
                          ("FortiGuard: antivirus definitions version", "AV definitions", "text", ()),
                          ("FortiGuard: IPS definitions version", "IPS definitions", "text", ())], 0)
    w += tiles_row(items, [("Memory utilization", "memory", 1, ((0, GREEN), (80, AMBER), (88, RED))),
                           ("Low memory (kernel) utilization", "kernel memory", 1, ((0, GREEN), (80, AMBER), (88, RED))),
                           ("Firewall: new sessions per second (1-min average)", "new sessions/s", 0, ()),
                           ("Firewall: NPU session table use", "NPU table", 1, SESSION_TH),
                           ("Firewall: ephemeral session table use", "ephemeral", 1, SESSION_TH),
                           ("HA: cluster members", "HA members", 0, ()),
                           ("HA: primary unit serial number", "HA primary", "text", ()),
                           ("Time since the last configuration change", "since config change", 0, ()),
                           ("Last reboot reason", "reboot reason", "text", ())], 3)
    w += tiles_row(items, [("Firewall policies: configured", "policies", 0, ()),
                           ("Firewall policies: no traffic since boot", "no traffic since boot", 0, ()),
                           ("Firewall policies: idle over 30 days", "idle > 30 d", 0, ()),
                           ("Firewall policies: idle over 90 days", "idle > 90 d", 0, ()),
                           ("Firewall: highest IP-pool port use", "IP pool use", 0, SESSION_TH),
                           ("DHCP: highest lease-pool use", "DHCP pool use", 0, SESSION_TH)], 6)
    y = 9
    w += [sw.svg("IPS per minute (all VDOMs)", 0, y, 36, 8, me, [
              {"items": ["Security: IPS intrusions detected per minute (all VDOMs)"], "color": "F59E0B", "label": "detected", "fill": 2},
              {"items": ["Security: IPS intrusions blocked per minute (all VDOMs)"], "color": "16A34A", "label": "blocked", "width": 1},
              {"items": ["Security: IPS critical-severity detections per minute (all VDOMs)"], "color": "E5484D", "label": "critical"},
              {"items": ["Security: IPS high-severity detections per minute (all VDOMs)"], "color": "7C3AED", "label": "high", "width": 1}]),
          sw.svg("Antivirus and web filter per minute (all VDOMs)", 36, y, 36, 8, me, [
              {"items": ["Security: viruses detected per minute (all VDOMs)"], "color": "E5484D", "label": "viruses"},
              {"items": ["Security: web filter: requests blocked*"], "color": "F59E0B", "label": "web blocked"},
              {"items": ["Security: VoIP calls blocked*", "Security: P2P connections blocked*"], "color": "0EA5E9",
               "label": "VoIP / P2P blocked", "width": 1}])]
    y += 8
    ref = sw.page_ref("FSN", page_no)
    w += [navigator2("Per VDOM, FortiGuard, log devices, HA, policies - click one to graph it", 0, y, 36, 18, hid,
                     ["VDOM *", "FortiGuard *", "Log device *", "HA*", "Firewall policies*", "Security:*",
                      "Sensor *", "Memory utilization", "Low memory*", "Firewall: *"], ["component", "vdom"], ref),
          sw.follow_graph("Graph of the item selected on the left", 36, y, 36, 18, ref)]
    y += 18
    if "Firewall policies without traffic since boot (by VDOM)" in items:
        w.append(history("Policies without traffic since boot, by VDOM (policy IDs) - candidates for review",
                         0, y, 36, 64 - y, items["Firewall policies without traffic since boot (by VDOM)"],
                         "Policies without traffic since boot", lines=1))
    w.append(sw.problems(f"{fd.short(h)} problems", 36, y, 36, 64 - y, hostid=hid))
    return {"name": f"{fd.short(h)} – security & FortiGuard", "widgets": w}


def sonicwall_detail_page(z, h, page_no):
    items, me, hid = items_by_name(z, h), [h["name"]], h["hostid"]
    w = tiles_row(items, [("Firewall: VPN tunnels up (IPsec SAs)", "IPsec SAs", 0, ()),
                          ("Firewall: VPN peers", "VPN peers", 0, ()),
                          ("Syslog: messages per minute", "syslog msgs/min", 0, ((0, RED), (1, GREEN))),
                          ("Content filter service", "content filter", "text", ()),
                          ("Zones without IPS or gateway anti-virus", "zones without IPS / GAV", 0, ((0, GREEN), (1, AMBER))),
                          ("Firewall: DPI-SSL connections peak", "DPI-SSL peak", 0, ())], 0)
    y = 3
    for name, col, hh in (("IPsec: security associations", "IPsec security associations (policy: peer, networks, created)", 10),
                          ("Zones: security services", "Security services per zone (CFS, gateway AV, anti-spyware, IPS, app control, SSL control)", 10)):
        if name in items:
            w.append(history(col, 0, y, 72, hh, items[name], col, lines=3))
            y += hh
    ref = sw.page_ref("SVN", page_no)
    w += [navigator2("VPN policies, syslog, zones - click one to graph it", 0, y, 36, 14, hid,
                     ["IPsec *", "Syslog*", "Zones*", "Firewall: *"], ["component", "vpn"], ref),
          sw.follow_graph("Graph of the item selected on the left", 36, y, 36, 14, ref)]
    y += 14
    w.append(sw.svg("Syslog messages per minute", 0, y, 36, 8, me, [
        {"items": ["Syslog: messages per minute"], "color": "2563EB", "label": "messages/min", "fill": 2}]))
    w.append(sw.problems(f"{fd.short(h)} problems", 36, y, 36, 64 - y, hostid=hid))
    return {"name": f"{fd.short(h)} – VPN & security", "widgets": w}


def build(z):
    gid = z.call("hostgroup.get", {"filter": {"name": [NAME]}, "output": ["groupid"]})[0]["groupid"]
    hosts = z.call("host.get", {"groupids": gid, "filter": {"status": 0}, "output": ["hostid", "host", "name"],
                                "selectTags": ["tag", "value"]})
    # firewalls first (SonicWall pair, then the rest), then the switch
    hosts.sort(key=lambda h: (fd.tag(h, "role") != "firewall", "Secondary" in h["host"], h["host"]))
    snmp = [h for h in hosts if fd.tag(h, "snmp") == "ok"]
    firewalls = [h for h in snmp if fd.tag(h, "role") == "firewall"]
    ports = {h["hostid"]: fd.port_count(z, h) for h in snmp}

    # ---------- Overview ----------
    table_h = 2 + (len(hosts) + 1) // 2
    health = fd.health_table("Device health (every device; ping-only ones until their SNMP is opened)",
                             0, 0, 72, table_h, gid)
    for fld in health["fields"]:
        if fld["name"] == "columns.0.name":
            fld["value"] = "Device"
    ov, y = [health], table_h
    if firewalls:
        fw_h = 2 + (len(firewalls) + 1) // 2
        ov.append(firewall_table("Firewalls (sessions, session table, VPN, NAT)", 0, y, 72, fw_h, gid))
        y += fw_h
        names = [h["name"] for h in firewalls]
        ov += [sw.svg("Active sessions, all firewalls", 0, y, 36, 8, names, [
                   {"items": ["Firewall: Active sessions"], "color": "2563EB", "label": ""}], legend_lines=len(names)),
               sw.svg("VPN traffic encrypted into tunnels, all firewalls", 36, y, 36, 8, names, [
                   {"items": ["Firewall: VPN traffic encrypted*"], "color": "16A34A", "label": ""}],
                   legend_lines=len(names))]
        y += 8
    half = []
    for h in snmp:   # port maps, two per row where they fit
        mw, mh = sw.overview_map_size(ports[h["hostid"]])
        half.append((h, mw, mh))
    row = []
    for h, mw, mh in half:
        if mw == 72:
            ov.append(sw.honeycomb(f"{fd.short(h)} ({sw.MAP_LEGEND})", 0, y, 72, mh, h["hostid"],
                                   sw.IF_STATE_ITEMS, sw.IF_STATUS_TH))
            y += mh
            continue
        row.append((h, mh))
        if len(row) == 2:
            rh = max(m for _, m in row)
            for n, (hh, _) in enumerate(row):
                ov.append(sw.honeycomb(f"{fd.short(hh)} ({sw.MAP_LEGEND})", n * 36, y, 36, rh, hh["hostid"],
                                       sw.IF_STATE_ITEMS, sw.IF_STATUS_TH))
            y += rh
            row = []
    if row:
        h, mh = row[0]
        ov.append(sw.honeycomb(f"{fd.short(h)} ({sw.MAP_LEGEND})", 0, y, 36, mh, h["hostid"],
                               sw.IF_STATE_ITEMS, sw.IF_STATUS_TH))
        y += mh
    ov.append(sw.problems(f"{NAME} problems (current and recent)", 0, y, 72, max(4, min(10, 64 - y)), groupid=gid))
    pages = [{"name": "Overview", "widgets": ov}]

    # ---------- per device ----------
    for n, h in enumerate(snmp):
        if fd.tag(h, "role") == "firewall":
            pages.append(firewall_page(z, h, n))
            if fd.tag(h, "vendor") == "fortinet":
                pages += [fortigate_vpn_page(z, h, n), fortigate_security_page(z, h, n)]
            elif fd.tag(h, "vendor") == "sonicwall":
                pages.append(sonicwall_detail_page(z, h, n))
        pages.append(fd.switch_page(z, h, n, ports[h["hostid"]], page_name=f"{fd.short(h)} – ports & health"))
    links = coverage_pages.links_page(z, snmp, 50)
    if links:
        pages.append(links)

    click_to_graph.link_pages(pages, NAME, z=z)
    dash = z.call("dashboard.get", {"filter": {"name": [NAME]}, "output": ["dashboardid"]})
    params = {"name": NAME, "display_period": 60, "auto_start": 0, "pages": pages}
    if dash:
        z.call("dashboard.update", {"dashboardid": dash[0]["dashboardid"], **params})
        print(f'Updated dashboard "{NAME}" ({dash[0]["dashboardid"]})')
    else:
        print(f'Created dashboard "{NAME}" ({z.call("dashboard.create", params)["dashboardids"][0]})')


if __name__ == "__main__":
    build(base.Zabbix())
