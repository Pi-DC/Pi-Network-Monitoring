#!/usr/bin/env python3
"""Provision ISP link monitoring for the A10 LLB in Zabbix.

Creates host group, A10 host (SNMP v2c), per-ISP traffic / utilisation / status
items, 5-second ICMP checks to each ISP gateway, triggers, graphs and a dashboard.

Credentials are read from /root/.credentials (zabbix_admin, a10_snmp_community).
"""
import json
import urllib.request

API = "http://127.0.0.1/zabbix/api_jsonrpc.php"
HOST = "A10-LLB"
HOST_NAME = "A10 LLB (PI-AMR-A10_LLB)"
A10_MGMT_IP = "172.20.96.83"
GROUP = "ISP Links"

# name, A10 port ifIndex, gateway IP, A10 IP on link, contracted bandwidth (bps), graph colours (in, out)
ISPS = [
    ("Airtel",    7,  "182.74.211.169",  "182.74.211.170",  4_000_000_000, ("1A7F37", "E5484D")),
    ("Jio",       11, "136.232.227.133", "136.232.227.134", 2_000_000_000, ("2563EB", "F59E0B")),
    ("PowerGrid", 4,  "103.176.159.241", "103.176.159.242", 2_000_000_000, ("7C3AED", "0D9488")),
]

# Traffic comes from the A10's private interface table (A10 MIB, 22610.2.4.1.7.1.2.1.1), whose
# octet counters refresh every second. The standard IF-MIB counters on this A10 refresh only
# every ~61s, so they are used for status/errors only.
A10_IF_IN_OCTETS = "1.3.6.1.4.1.22610.2.4.1.7.1.2.1.1.3"
A10_IF_OUT_OCTETS = "1.3.6.1.4.1.22610.2.4.1.7.1.2.1.1.5"
TRAFFIC_POLL = "5s"
# Inbound errors still use the slow IF-MIB counter: a raw item keeps only changed values and a
# calculated rate() spans real updates. (Discard-unchanged and change-per-second can't share one
# item: a discarded value also drops the change-per-second step's previous value.)
RATE_WINDOW = "150s"  # always holds 2-3 IF-MIB counter updates
TRAFFIC_INTERVAL = "1m"
PING_INTERVAL = "5s"
HISTORY = "90d"
TRENDS = "1825d"           # 5 years of hourly min/avg/max

DISCARD_UNCHANGED_HEARTBEAT = 20
CHANGE_PER_SECOND = 10
MULTIPLIER = 1
IN_RANGE = 13
DISCARD_VALUE = 1
# Counter resets/glitches turn into impossible rates (seen 2026-10-08: 19-72 Tbps on PowerGrid). The A10 ISP ports are
# 10 Gbps, so anything above 12.5 Gbps (port speed + headroom for 5s-poll/1s-counter jitter) is discarded.
MAX_BPS = "12500000000"
TRAFFIC_STEPS = ((CHANGE_PER_SECOND, ""), (MULTIPLIER, "8"), (IN_RANGE, f"0\n{MAX_BPS}", DISCARD_VALUE))
# Error counters are usually flat and need a heartbeat < RATE_WINDOW/2 so rate() always has 2 points.
RAW_ERROR_STEPS = ((DISCARD_UNCHANGED_HEARTBEAT, "1m"),)


def read(path):
    with open(path) as f:
        return f.read().strip()


class Zabbix:
    def __init__(self):
        self.token = None
        self.token = self.call("user.login", {"username": "Admin", "password": read("/root/.credentials/zabbix_admin")})

    def call(self, method, params):
        headers = {"Content-Type": "application/json-rpc"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        body = json.dumps({"jsonrpc": "2.0", "method": method, "params": params, "id": 1}).encode()
        with urllib.request.urlopen(urllib.request.Request(API, body, headers)) as r:
            resp = json.load(r)
        if "error" in resp:
            raise RuntimeError(f"{method}: {resp['error']['data']}")
        return resp["result"]


def pp(*steps):
    """Preprocessing steps as (type, params) or (type, params, error_handler)."""
    return [{"type": t, "params": p, "error_handler": rest[0] if rest else 0, "error_handler_params": ""}
            for t, p, *rest in steps]


def macro_bw(isp):
    return "{$" + isp.upper() + ".BW}"


def main():
    z = Zabbix()

    if z.call("host.get", {"filter": {"host": [HOST]}}):
        raise SystemExit(f"Host {HOST} already exists; delete it in Zabbix first to re-provision.")

    groups = z.call("hostgroup.get", {"filter": {"name": [GROUP]}})
    groupid = groups[0]["groupid"] if groups else z.call("hostgroup.create", {"name": GROUP})["groupids"][0]
    tmpl = z.call("template.get", {"filter": {"name": ["Generic by SNMP"]}})

    macros = [{"macro": "{$SNMP_COMMUNITY}", "value": read("/root/.credentials/a10_snmp_community"), "type": 1,
               "description": "A10 SNMP v2c community"},
              {"macro": "{$ISP.UTIL.WARN}", "value": "80", "description": "Utilisation % warning"},
              {"macro": "{$ISP.UTIL.HIGH}", "value": "95", "description": "Utilisation % high"},
              {"macro": "{$ISP.LOSS.WARN}", "value": "5", "description": "Packet loss % warning"},
              {"macro": "{$ISP.RTT.WARN}", "value": "0.15", "description": "Gateway RTT warning (seconds)"}]
    macros += [{"macro": macro_bw(n), "value": str(bw), "description": f"{n} contracted bandwidth (bps)"}
               for n, _, _, _, bw, _ in ISPS]

    hostid = z.call("host.create", {
        "host": HOST, "name": HOST_NAME,
        "groups": [{"groupid": groupid}],
        "interfaces": [{"type": 2, "main": 1, "useip": 1, "ip": A10_MGMT_IP, "dns": "", "port": "161",
                        "details": {"version": 2, "bulk": 1, "community": "{$SNMP_COMMUNITY}"}}],
        "templates": [{"templateid": t["templateid"]} for t in tmpl],
        "macros": macros,
        "tags": [{"tag": "role", "value": "llb"}],
    })["hostids"][0]
    ifid = z.call("hostinterface.get", {"hostids": hostid})[0]["interfaceid"]

    vm = z.call("valuemap.create", {"hostid": hostid, "name": "IF-MIB::ifOperStatus", "mappings": [
        {"value": v, "newvalue": n} for v, n in
        [("1", "up"), ("2", "down"), ("3", "testing"), ("4", "unknown"), ("5", "dormant"),
         ("6", "notPresent"), ("7", "lowerLayerDown")]]})["valuemapids"][0]
    vm_ping = z.call("valuemap.create", {"hostid": hostid, "name": "Service state", "mappings": [
        {"value": "0", "newvalue": "Down"}, {"value": "1", "newvalue": "Up"}]})["valuemapids"][0]

    def item(**kw):
        base = {"hostid": hostid, "interfaceid": ifid, "history": HISTORY, "trends": TRENDS}
        base.update(kw)
        return z.call("item.create", base)["itemids"][0]

    ids = {}
    for name, idx, gw, _a10ip, _bw, _ in ISPS:
        tags = [{"tag": "isp", "value": name}]
        i = ids[name] = {}
        for direction, oid, word in (("in", A10_IF_IN_OCTETS, "received"), ("out", A10_IF_OUT_OCTETS, "sent")):
            i[direction] = item(name=f"{name}: Bits {word}", type=20, snmp_oid=f"{oid}.{idx}",
                                key_=f"isp.net.if.{direction}[{name}]", value_type=0, units="bps",
                                delay=TRAFFIC_POLL, tags=tags + [{"tag": "component", "value": "traffic"}],
                                preprocessing=pp(*TRAFFIC_STEPS),
                                description=f"A10 Ethernet {idx} octets {direction} (A10 MIB, 1s refresh). "
                                            f"'{word}' is from the A10's point of view: received = download from {name}.")
            i[direction + "_util"] = item(name=f"{name}: Utilisation {'download' if direction == 'in' else 'upload'}",
                                          type=15, key_=f"isp.util.{direction}[{name}]", value_type=0, units="%",
                                          delay=TRAFFIC_POLL, interfaceid="0",
                                          params=f"last(//isp.net.if.{direction}[{name}])/{macro_bw(name)}*100",
                                          tags=tags + [{"tag": "component", "value": "utilisation"}])
        i["status"] = item(name=f"{name}: Port status (Ethernet {idx})", type=20, snmp_oid=f"1.3.6.1.2.1.2.2.1.8.{idx}",
                           key_=f"isp.net.if.status[{name}]", value_type=3, delay="30s", valuemapid=vm, trends="0",
                           tags=tags + [{"tag": "component", "value": "status"}],
                           preprocessing=pp((DISCARD_UNCHANGED_HEARTBEAT, "10m")))
        raw_err = item(name=f"{name}: Raw inbound errors", type=20, snmp_oid=f"1.3.6.1.2.1.2.2.1.14.{idx}",
                       key_=f"isp.net.if.raw.in.errors[{name}]", value_type=3, delay=TRAFFIC_POLL,
                       history="7d", trends="0", tags=tags + [{"tag": "component", "value": "raw"}],
                       preprocessing=pp(*RAW_ERROR_STEPS))
        i["errors"] = item(name=f"{name}: Inbound errors", type=15, interfaceid="0",
                           key_=f"isp.net.if.in.errors[{name}]", value_type=0, units="errors/s",
                           delay=TRAFFIC_INTERVAL, tags=tags + [{"tag": "component", "value": "errors"}],
                           params=f"rate(//isp.net.if.raw.in.errors[{name}],{RATE_WINDOW})")
        ping = f"{gw},3,200,,500"
        i["ping"] = item(name=f"{name}: Gateway reachable ({gw})", type=3, key_=f"icmpping[{ping}]", value_type=3,
                         delay=PING_INTERVAL, valuemapid=vm_ping, tags=tags + [{"tag": "component", "value": "ping"}])
        i["loss"] = item(name=f"{name}: Gateway packet loss", type=3, key_=f"icmppingloss[{ping}]", value_type=0,
                         units="%", delay=PING_INTERVAL, tags=tags + [{"tag": "component", "value": "ping"}])
        i["rtt"] = item(name=f"{name}: Gateway latency", type=3, key_=f"icmppingsec[{ping},avg]", value_type=0,
                        units="s", delay=PING_INTERVAL, tags=tags + [{"tag": "component", "value": "ping"}])

    triggers = []
    for name, idx, gw, _a10ip, _bw, _ in ISPS:
        h = f"/{HOST}/"
        tags = [{"tag": "isp", "value": name}]
        triggers += [
            {"description": f"{name}: link port down (Ethernet {idx})", "priority": 5, "tags": tags,
             "expression": f"last({h}isp.net.if.status[{name}])=2"},
            {"description": f"{name}: gateway {gw} unreachable", "priority": 4, "tags": tags,
             "expression": f"max({h}icmpping[{gw},3,200,,500],30s)=0"},
            {"description": f"{name}: packet loss over {{$ISP.LOSS.WARN}}% (1m avg)", "priority": 2, "tags": tags,
             "expression": f"avg({h}icmppingloss[{gw},3,200,,500],1m)>{{$ISP.LOSS.WARN}}"},
            {"description": f"{name}: gateway latency over {{$ISP.RTT.WARN}}s (1m avg)", "priority": 2, "tags": tags,
             "expression": f"avg({h}icmppingsec[{gw},3,200,,500,avg],1m)>{{$ISP.RTT.WARN}}"},
        ]
        for direction, label in (("in", "download"), ("out", "upload")):
            triggers += [
                {"description": f"{name}: {label} utilisation over {{$ISP.UTIL.WARN}}% for 5m", "priority": 2,
                 "tags": tags, "expression": f"min({h}isp.util.{direction}[{name}],5m)>{{$ISP.UTIL.WARN}}"},
                {"description": f"{name}: {label} utilisation over {{$ISP.UTIL.HIGH}}% for 5m", "priority": 4,
                 "tags": tags, "expression": f"min({h}isp.util.{direction}[{name}],5m)>{{$ISP.UTIL.HIGH}}"},
            ]
    z.call("trigger.create", triggers)

    graphs = {}
    for name, idx, gw, _a10ip, _bw, (cin, cout) in ISPS:
        i = ids[name]
        graphs[f"{name} traffic"] = z.call("graph.create", {"name": f"{name}: Traffic", "width": 900, "height": 200,
            "gitems": [{"itemid": i["in"], "color": cin, "drawtype": 1},
                       {"itemid": i["out"], "color": cout, "drawtype": 2}]})["graphids"][0]
        graphs[f"{name} util"] = z.call("graph.create", {"name": f"{name}: Utilisation %", "width": 900, "height": 200,
            "ymin_type": 1, "ymax_type": 1, "yaxismin": 0, "yaxismax": 100,
            "gitems": [{"itemid": i["in_util"], "color": cin, "drawtype": 2},
                       {"itemid": i["out_util"], "color": cout, "drawtype": 2}]})["graphids"][0]
        graphs[f"{name} ping"] = z.call("graph.create", {"name": f"{name}: Gateway latency & loss", "width": 900, "height": 200,
            "gitems": [{"itemid": i["rtt"], "color": cin, "drawtype": 0},
                       {"itemid": i["loss"], "color": "E5484D", "drawtype": 0, "yaxisside": 1}]})["graphids"][0]
    graphs["all down"] = z.call("graph.create", {"name": "All ISPs: Download (stacked)", "width": 900, "height": 200,
        "graphtype": 1, "gitems": [{"itemid": ids[n]["in"], "color": c[0], "drawtype": 1} for n, *_, c in ISPS]})["graphids"][0]
    graphs["all up"] = z.call("graph.create", {"name": "All ISPs: Upload (stacked)", "width": 900, "height": 200,
        "graphtype": 1, "gitems": [{"itemid": ids[n]["out"], "color": c[0], "drawtype": 1} for n, *_, c in ISPS]})["graphids"][0]
    graphs["all rtt"] = z.call("graph.create", {"name": "All ISPs: Gateway latency", "width": 900, "height": 200,
        "gitems": [{"itemid": ids[n]["rtt"], "color": c[0], "drawtype": 0} for n, *_, c in ISPS]})["graphids"][0]

    def graph_widget(name, gid, x, y, w=36, h=5):
        return {"type": "graph", "name": name, "x": x, "y": y, "width": w, "height": h,
                "fields": [{"type": 6, "name": "graphid.0", "value": gid}]}

    overview = [graph_widget("All ISPs: Download", graphs["all down"], 0, 0),
                graph_widget("All ISPs: Upload", graphs["all up"], 36, 0),
                graph_widget("All ISPs: Gateway latency", graphs["all rtt"], 0, 5),
                {"type": "problems", "name": "ISP problems", "x": 36, "y": 5, "width": 36, "height": 5,
                 "fields": [{"type": 2, "name": "groupids.0", "value": groupid}]}]
    pages = [{"name": "Overview", "widgets": overview}]
    for name, idx, *_ in ISPS:
        pages.append({"name": name, "widgets": [
            graph_widget(f"{name}: Traffic", graphs[f"{name} traffic"], 0, 0, 72, 5),
            graph_widget(f"{name}: Utilisation %", graphs[f"{name} util"], 0, 5),
            graph_widget(f"{name}: Gateway latency & loss", graphs[f"{name} ping"], 36, 5)]})
    z.call("dashboard.create", {"name": "A10 LLB & ISP Links", "display_period": 30, "auto_start": 0, "pages": pages})

    print(f"Created host {HOST} (hostid {hostid}), {sum(len(v) for v in ids.values())} items, "
          f"{len(triggers)} triggers, {len(graphs)} graphs and the 'A10 LLB & ISP Links' dashboard.")


if __name__ == "__main__":
    main()
