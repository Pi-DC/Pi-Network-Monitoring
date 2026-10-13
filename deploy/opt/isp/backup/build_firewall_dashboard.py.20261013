#!/usr/bin/env python3
"""Build the "Pi Firewall Fabric" dashboard from its host group (add_firewalls.py). Re-run after a device is added,
enabled or upgraded from ICMP-only to SNMP:  python3 build_firewall_dashboard.py

  Overview                - health table (every enabled device, ping-only ones too), firewall table (sessions,
                            session table use, VPN, NAT), sessions and VPN traffic of all firewalls, port maps, problems
  <firewall> – firewall   - sessions, session table, CPU (total / forwarding / management), memory, VPN tunnels and
                            traffic, NAT, DPI-SSL, model / serial / firmware, item list with graph, problems
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
NUMERIC_ITEMS = ["Firewall: *", "CPU utilization", "Memory utilization", "Health: CPU utilization",
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
            ("Fwd + inspect CPU %", 1, "Firewall: Forwarding and inspection CPU utilization", 2, 0, sw.PCT_TH)]
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
          sw.svg("Session table use (%)", 36, y, 36, 10, me, [
              {"items": ["Firewall: Session table use"], "color": "7C3AED", "label": "% used", "fill": 2}])]
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
    w += [sw.svg("VPN traffic (encrypted into tunnels filled, decrypted from tunnels line)", 0, y, 36, 10, me, [
              {"items": ["Firewall: VPN traffic encrypted*"], "color": "2563EB", "label": "encrypted", "fill": 2},
              {"items": ["Firewall: VPN traffic decrypted*"], "color": "F59E0B", "label": "decrypted", "width": 1}]),
          sw.svg("VPN tunnels / peers / users", 36, y, 36, 10, me, [
              {"items": ["Firewall: VPN tunnels up*"], "color": "16A34A", "label": "tunnels / SAs up"},
              {"items": ["Firewall: VPN peers", "Firewall: SSL VPN users"], "color": "0EA5E9", "label": "peers / users"}])]
    y += 10
    w += [fd.navigator("Firewall items - click one to graph it", 0, y, 36, 14, hid, NUMERIC_ITEMS, "component", ref,
                       lines=200, rate=30),
          sw.follow_graph("Graph of the firewall item selected on the left", 36, y, 36, 14, ref)]
    y += 14
    info = [n for n in INFO.get(fd.tag(h, "vendor"), []) if n in items]
    for n, name in enumerate(info):
        iw = 72 // len(info) + (n >= len(info) - 72 % len(info))
        w.append(sw.tile(name.split(": ")[-1], items[name], sum(72 // len(info) + (k >= len(info) - 72 % len(info))
                                                                for k in range(n)), y, name.split(": ")[-1],
                         w=iw, decimals=0, value_size=12))
    y += 3 if info else 0
    w.append(sw.problems(f"{fd.short(h)} problems", 0, y, 72, 64 - y, hostid=hid))
    return {"name": f"{fd.short(h)} – firewall", "widgets": w}


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
