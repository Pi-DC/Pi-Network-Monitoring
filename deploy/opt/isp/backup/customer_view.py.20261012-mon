#!/usr/bin/env python3
"""Customer-facing proof of ISP link availability.

- Tags the two "link really down" triggers per ISP (port down, gateway unreachable) with link_down=<ISP>.
- Adds 24h gateway-reachability % items.
- Creates one Zabbix service per ISP (status driven only by link_down problems) and daily + monthly
  SLAs over them, so availability % is recorded from today on.
- Builds the "ISP Link Status" dashboard and a read-only "customer" user that can only see it.

Re-runnable: existing objects are reused; the dashboard pages are rebuilt in place.
"""
import datetime as dt
import os
import secrets

import build_dashboard as d
import click_to_graph
import setup_isp_links as base

f, INT, STR, HOSTREF, ITEM = d.f, d.INT, d.STR, d.HOSTREF, d.ITEM
SLA_FIELD = 10
DASHBOARD = "ISP Link Status"
USER_GROUP = "Customer viewers"
USERNAME = "customer"
CRED = "/root/.credentials/zabbix_customer"
SLO = "99.9"


def refresh(widget_def, seconds):
    widget_def["fields"].append(f(INT, "rf_rate", seconds))
    return widget_def


def main():
    z = base.Zabbix()
    host = z.call("host.get", {"filter": {"host": [base.HOST]}, "selectHostGroups": ["groupid"]})[0]
    hostid, groupid = host["hostid"], host["hostgroups"][0]["groupid"]
    items = {i["key_"]: i["itemid"] for i in z.call("item.get", {"hostids": hostid, "output": ["key_"]})}

    # Downtime definition, used by the triggers' link_down tag, the "link up" item and the SLA services:
    # the A10 port is down, the gateway answers no ping for 30s, or the A10 load balancer marks the
    # gateway DOWN (A10 status from add_llb_stats.py, when present).
    def down_triggers(name, idx, gw):
        return (f"{name}: link port down (Ethernet {idx})", f"{name}: gateway {gw} unreachable",
                f"{name}: A10 marked gateway DOWN (removed from load balancing)")

    # 1. Tag the "really down" triggers.
    for t in z.call("trigger.get", {"hostids": hostid, "output": ["description"], "selectTags": "extend"}):
        for name, idx, gw, *_ in base.ISPS:
            if t["description"] in down_triggers(name, idx, gw):
                tags = [{"tag": x["tag"], "value": x["value"]} for x in t["tags"]]
                if {"tag": "link_down", "value": name} not in tags:
                    z.call("trigger.update", {"triggerid": t["triggerid"], "tags": tags + [{"tag": "link_down", "value": name}]})

    # 2. 24h reachability % per ISP.
    for name, _, gw, *_ in base.ISPS:
        key = f"isp.reach.24h[{name}]"
        if key not in items:
            items[key] = z.call("item.create", {
                "hostid": hostid, "name": f"{name}: Gateway reachability (last 24h)", "type": 15, "key_": key,
                "delay": "1m", "value_type": 0, "units": "%", "history": base.HISTORY, "trends": base.TRENDS,
                "params": f"avg(//icmpping[{gw},3,200,,500],1d)*100",
                "tags": [{"tag": "isp", "value": name}, {"tag": "component", "value": "availability"}]})["itemids"][0]

    # 2b. Link up/down on the SLA definition, and 24h availability from it. Raw ping reachability
    #     counts every ignored ping (Jio's gateway rate-limits ICMP), so the customer tiles use this.
    for name, _, gw, *_ in base.ISPS:
        up_key, avail_key = f"isp.linkup[{name}]", f"isp.avail.24h[{name}]"
        tags = [{"tag": "isp", "value": name}, {"tag": "component", "value": "availability"}]
        up_params = f"max(//icmpping[{gw},3,200,,500],30s)=1 and last(//isp.net.if.status[{name}])=1"
        up_desc = "1 = up. 0 = A10 port down, or gateway answered no ping for 30s"
        if f"a10.llb.status[{name}]" in items:
            # min() over the 30s evaluation window, so a DOWN seen at any 5s poll counts
            up_params += f" and min(//a10.llb.status[{name}],30s)=1"
            up_desc += ", or the A10 load balancer marked the gateway DOWN"
        up_desc += " (same rule as the link-down triggers and the SLA)."
        if up_key not in items:
            items[up_key] = z.call("item.create", {
                "hostid": hostid, "name": f"{name}: Link up (SLA definition)", "type": 15, "key_": up_key,
                "delay": "30s", "value_type": 3, "history": base.HISTORY, "trends": base.TRENDS, "tags": tags,
                "params": up_params, "description": up_desc})["itemids"][0]
        else:
            z.call("item.update", {"itemid": items[up_key], "params": up_params, "description": up_desc})
        if avail_key not in items:
            items[avail_key] = z.call("item.create", {
                "hostid": hostid, "name": f"{name}: Link availability (last 24h)", "type": 15, "key_": avail_key,
                "delay": "1m", "value_type": 0, "units": "%", "history": base.HISTORY, "trends": base.TRENDS,
                "tags": tags, "params": f"avg(//{up_key},1d)*100"})["itemids"][0]

    # 2c. Traffic in Mbps for the customer view. Zabbix auto-scales bps to Gbps; the "!" unit prefix
    #     switches that off, so these always read e.g. "1628.4 Mbps".
    for name, *_ in base.ISPS:
        for d_, word in (("in", "Download"), ("out", "Upload")):
            key = f"isp.mbps.{d_}[{name}]"
            if key not in items:
                items[key] = z.call("item.create", {
                    "hostid": hostid, "name": f"{name}: {word} (Mbps)", "type": 15, "key_": key,
                    "delay": base.TRAFFIC_POLL, "value_type": 0, "units": "!Mbps",
                    "history": base.HISTORY, "trends": base.TRENDS,
                    "params": f"last(//isp.net.if.{d_}[{name}])/1000000",
                    "tags": [{"tag": "isp", "value": name}, {"tag": "component", "value": "traffic"}]})["itemids"][0]

    # 3. Services + SLAs.
    services = {s["name"]: s["serviceid"] for s in z.call("service.get", {"output": ["serviceid", "name"]})}
    for name, *_ in base.ISPS:
        sname = f"{name} link"
        sdesc = (f"{name} is DOWN when the A10 port is down, the gateway answers no ping for 30s, or the A10 "
                 f"load balancer marks the gateway DOWN. Packet-loss/latency warnings do not count as downtime.")
        if sname not in services:
            services[sname] = z.call("service.create", {
                "name": sname, "algorithm": 1, "sortorder": 0,
                "problem_tags": [{"tag": "link_down", "operator": 0, "value": name}],
                "tags": [{"tag": "sla", "value": "isp-links"}, {"tag": "isp", "value": name}],
                "description": sdesc})["serviceids"][0]
        else:
            z.call("service.update", {"serviceid": services[sname], "description": sdesc})
    start_of_today = int(dt.datetime.now().replace(hour=0, minute=0, second=0, microsecond=0).timestamp())
    slas = {s["name"]: s["slaid"] for s in z.call("sla.get", {"output": ["slaid", "name"]})}
    for sla_name, period in (("ISP link availability (daily)", 0), ("ISP link availability (monthly)", 2)):
        if sla_name not in slas:
            slas[sla_name] = z.call("sla.create", {
                "name": sla_name, "period": period, "slo": SLO, "effective_date": start_of_today,
                "timezone": "Asia/Kolkata", "status": 1,
                "service_tags": [{"tag": "sla", "operator": 0, "value": "isp-links"}],
                "description": "Availability of each ISP link as seen by the NOC monitoring."})["slaids"][0]

    # 4. Customer dashboard.
    names = [n for n, *_ in base.ISPS]
    up_down = ((0, d.RED), (1, d.GREEN))
    reach_th = ((0, d.RED), (99, d.AMBER), (99.9, d.GREEN))

    def k(name, what):
        gw = next(g for n, _, g, *_ in base.ISPS if n == name)
        return items[{"ping": f"icmpping[{gw},3,200,,500]", "avail": f"isp.avail.24h[{name}]",
                      "in": f"isp.mbps.in[{name}]", "out": f"isp.mbps.out[{name}]",
                      "llb": f"a10.llb.status[{name}]"}[what]]

    live = []
    for i, n in enumerate(names):
        live.append(refresh(d.item_tile(f"{n} status", k(n, "ping"), i * 8, 0, 8, 3, f"{n} link", decimals=0,
                                        th=up_down, value_size=24), 10))
        live.append(refresh(d.item_tile(f"{n} availability", k(n, "avail"), 24 + i * 8, 0, 8, 3,
                                        f"{n} 24h", decimals=1, th=reach_th, value_size=20,
                                        units_size=18), 60))
        live.append(refresh(d.item_tile(f"{n} download", k(n, "in"), i * 24, 6, 12, 3, f"{n} · download now",
                                        decimals=0, value_size=22, show_time=True), 10))
        live.append(refresh(d.item_tile(f"{n} upload", k(n, "out"), i * 24 + 12, 6, 12, 3, f"{n} · upload now",
                                        decimals=0, value_size=22, show_time=True), 10))
    # A10 load balancer's own verdict per gateway (from add_llb_stats.py): 1 up / 2 down / 0 disabled.
    for i, n in enumerate(names):
        live.append(refresh(d.item_tile(f"{n} A10 LLB", k(n, "llb"), i * 24, 3, 24, 3,
                                        f"{n} · A10 load balancer", decimals=0,
                                        th=((0, d.AMBER), (1, d.GREEN), (2, d.RED)), value_size=24), 10))
    live.append(refresh(d.widget("problems", "Link-down events in selected period (empty = no outage)", 48, 0, 24, 3,
                                 [f(HOSTREF, "hostids.0", hostid), f(INT, "show", 2), f(INT, "show_lines", 10),
                                  f(INT, "evaltype", 0), f(STR, "tags.0.tag", "link_down"),
                                  f(INT, "tags.0.operator", 4), f(STR, "tags.0.value", ""),
                                  f(INT, "show_timeline", 0), f(INT, "sort_triggers", 4)]), 30))
    live.append(refresh(d.svggraph("Traffic per ISP link (continuous traffic = link up)", 0, 9, 72, 6,
                                   [{"item": f"{n}: Download (Mbps)", "color": d.ISP_COLORS[n], "width": 2,
                                     "fill": 1, "label": f"{n} download"} for n in names] +
                                   [{"item": f"{n}: Upload (Mbps)", "color": d.ISP_COLORS[n], "width": 1,
                                     "label": f"{n} upload"} for n in names], legend_lines=6), 30))
    live.append(refresh(d.svggraph("Gateway response time (every 5 seconds)", 0, 15, 36, 5,
                                   [{"item": f"{n}: Gateway latency", "color": d.ISP_COLORS[n], "width": 1,
                                     "label": n} for n in names]), 30))
    live.append(refresh(d.widget("slareport", "Availability today and recent days", 36, 15, 36, 5,
                                 [f(SLA_FIELD, "slaid.0", slas["ISP link availability (daily)"]),
                                  f(INT, "show_periods", 7)]), 60))
    if all(f"a10.llb.flaps.5m[{n}]" in items for n in names):
        live.append(refresh(d.svggraph("A10 load-balancer health flaps per 5 min (a bar = the A10 briefly took that link out of use)",
                                       0, 20, 72, 5,
                                       [{"item": f"{n}: A10 LLB health flaps (last 5 min)", "color": d.ISP_COLORS[n],
                                         "type": 3, "width": 2, "label": n} for n in names]), 30))
    if all(f"a10.llb.syn[{n}]" in items for n in names) and "a10.tcp.syn.rcv" in items:
        live.append(refresh(d.svggraph("New TCP connections (SYNs) per second per ISP link", 0, 25, 36, 5,
                                       [{"item": f"{n}: New TCP connections (SYNs) per second",
                                         "color": d.ISP_COLORS[n], "width": 2, "label": n} for n in names]), 30))
        live.append(refresh(d.svggraph("A10 SYN received / sent / dropped (SYN cookies = flood guard, should stay at 0)", 36, 25, 36, 5,
                                       [{"item": "A10: TCP SYN received per second", "color": "0EA5E9", "width": 2},
                                        {"item": "A10: TCP SYN sent to ISPs per second", "color": "2E9E5B", "width": 2},
                                        {"item": "A10: SYN dropped per second (total)", "color": d.RED, "width": 2},
                                        {"item": "A10: SYN cookies sent per second*", "color": "DB2777", "width": 1},
                                        {"item": "A10: TCP resets sent per second", "color": "8B5CF6", "width": 1}],
                                       legend_lines=5), 30))
    report = [
        d.widget("slareport", "Daily availability per ISP link", 0, 0, 72, 8,
                 [f(SLA_FIELD, "slaid.0", slas["ISP link availability (daily)"]), f(INT, "show_periods", 31)]),
        d.widget("slareport", "Monthly availability per ISP link", 0, 8, 72, 5,
                 [f(SLA_FIELD, "slaid.0", slas["ISP link availability (monthly)"]), f(INT, "show_periods", 6)]),
        d.widget("problems", "All link-down events (history)", 0, 13, 72, 5,
                 [f(HOSTREF, "hostids.0", hostid), f(INT, "show", 2), f(INT, "show_lines", 25),
                  f(INT, "evaltype", 0), f(STR, "tags.0.tag", "link_down"), f(INT, "tags.0.operator", 4),
                  f(STR, "tags.0.value", ""), f(INT, "show_timeline", 1), f(INT, "sort_triggers", 4)]),
    ]
    pages = [{"name": "Live status", "widgets": live}, {"name": "Availability report", "widgets": report}]

    # 5. Customer user group, user, sharing.
    groups = {g["name"]: g["usrgrpid"] for g in z.call("usergroup.get", {"output": ["usrgrpid", "name"]})}
    if USER_GROUP not in groups:
        groups[USER_GROUP] = z.call("usergroup.create", {
            "name": USER_GROUP, "gui_access": 0,
            "hostgroup_rights": [{"id": groupid, "permission": 2}]})["usrgrpids"][0]
    usrgrpid = groups[USER_GROUP]

    click_to_graph.link_pages(pages, DASHBOARD, z=z)   # "Items on this page" list + graph of the clicked item
    params = {"name": DASHBOARD, "display_period": 60, "auto_start": 0, "pages": pages,
              "private": 1, "userGroups": [{"usrgrpid": usrgrpid, "permission": 2}]}
    dash = z.call("dashboard.get", {"filter": {"name": [DASHBOARD]}, "output": ["dashboardid"]})
    if dash:
        dashid = dash[0]["dashboardid"]
        z.call("dashboard.update", {"dashboardid": dashid, **params})
    else:
        dashid = z.call("dashboard.create", params)["dashboardids"][0]

    landing = f"zabbix.php?action=dashboard.view&dashboardid={dashid}"
    users = z.call("user.get", {"filter": {"username": [USERNAME]}, "output": ["userid"]})
    if not users:
        password = secrets.token_urlsafe(12)
        user_role = z.call("role.get", {"filter": {"name": ["User role"]}, "output": ["roleid"]})[0]["roleid"]
        z.call("user.create", {"username": USERNAME, "name": "Customer", "passwd": password, "roleid": user_role,
                               "usrgrps": [{"usrgrpid": usrgrpid}], "url": landing, "autologout": "0",
                               "refresh": "10s"})
        with open(CRED, "w") as fh:
            fh.write(password + "\n")
        os.chmod(CRED, 0o600)
    print(f"Dashboard {dashid} ready; SLAs {list(slas.values())}; user '{USERNAME}' (password in {CRED}).")


if __name__ == "__main__":
    main()
