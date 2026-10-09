#!/usr/bin/env python3
"""Add A10 LLB (link load balancing) statistics for each ISP gateway.

Sources (A10 MIBs, confirmed against this A10 on 2026-10-08):
  A10-AX-MIB axServerStatServerStatus   22610.2.4.3.2.2.2.1.10.<ip>        0 disabled / 1 up / 2 down
  ACOS-SLB-STATS-MIB slbServerSTable    22610.2.4.10.108.21.1.1.1.<col>.<name>
      2 current connections, 3 total connections, 11 forward bytes, 12 reverse bytes
  ACOS-SLB-STATS-MIB service group member stateFlaps
                                        22610.2.4.10.108.22.3.1.1.1.23.<group>.<member>.<port>
  ACOS-SLB-STATS-MIB service group member totalConn
                                        22610.2.4.10.108.22.3.1.1.1.9.<group>.<member>.<port>
      SG_TCP_V4 -> new outbound TCP connections per ISP (each starts with a SYN sent via that ISP),
      SG_UDP_V4 -> new UDP flows per ISP. The A10 has no per-physical-interface SYN counter.
  A10-AX-MIB axNetStat (A10-wide)       22610.2.4.3.11.<n>.0
      3 TCP SYN received, 4 SYN cookies sent, 5 SYN cookie send failures, 10 SYN cookie (ACK) validation
      failures, 29 SYN throttle drops, 47 L4 SYN attack, 2 TCP resets sent. (12 "no SYN pkt drop" counts
      non-SYN packets without a session, not SYN drops, so it is not used. There is no A10-wide "SYN sent"
      counter: SYN sent = sum of the per-ISP new outbound TCP connections. The FPGA drop table
      22610.2.4.10.39.113 does not exist on BareMetal.)
All counters refresh every second on this A10. Forward = users -> ISP (upload), reverse = download.

Idempotent: existing items/triggers (by key / name) are skipped.
"""
import setup_isp_links as base

GATEWAYS = {"Airtel": "Airtel_GW", "Jio": "Jio_GW", "PowerGrid": "Powergrid_GW"}  # names as configured on the A10
HEALTH_GROUP = "SG_TCP_V4"   # service group whose member health flaps are tracked
SERVER_STATUS = "1.3.6.1.4.1.22610.2.4.3.2.2.2.1.10"
SERVER_STATS = "1.3.6.1.4.1.22610.2.4.10.108.21.1.1.1"
MEMBER_FLAPS = "1.3.6.1.4.1.22610.2.4.10.108.22.3.1.1.1.23"
MEMBER_TOTAL_CONN = "1.3.6.1.4.1.22610.2.4.10.108.22.3.1.1.1.9"
NET_STAT = "1.3.6.1.4.1.22610.2.4.3.11"
NET_COUNTERS = [  # (sub-OID, key, name)
    (3, "a10.tcp.syn.rcv", "A10: TCP SYN received per second"),
    (4, "a10.tcp.syncookie.sent", "A10: SYN cookies sent per second (SYN-flood protection active)"),
    (10, "a10.tcp.syncookie.fail", "A10: SYN cookie failures per second"),
    (2, "a10.tcp.rst.out", "A10: TCP resets sent per second"),
    (29, "a10.tcp.syn.throttle", "A10: SYN dropped by throttling per second"),
    (47, "a10.tcp.syn.attack", "A10: L4 SYN attack per second"),
    (5, "a10.tcp.syncookie.sendfail", "A10: SYN cookie send failures per second"),
]
SYN_DROP_KEYS = ("a10.tcp.syn.throttle", "a10.tcp.syn.attack", "a10.tcp.syncookie.sendfail")
POLL = base.TRAFFIC_POLL
CONNS_DESC = 'Sessions the A10 currently holds for this gateway (slbServerCurrRate). Not a live-traffic measure: after the A10 marks a gateway DOWN, new sessions stop at once but existing entries stay listed until their idle timeout expires, so this can stay above zero with no traffic. Use new connections per second and LLB upload/download for live activity.'
SHARE_DESC = "This gateway's share of the A10's session-table entries (same caveat: includes idle entries after a link goes down)."


def idx(text):
    """SNMP index for a string: length followed by its character codes."""
    return f"{len(text)}." + ".".join(str(ord(c)) for c in text)


def main():
    z = base.Zabbix()
    host = z.call("host.get", {"filter": {"host": [base.HOST]}, "selectInterfaces": ["interfaceid"],
                               "selectValueMaps": ["valuemapid", "name"]})[0]
    hostid, ifid = host["hostid"], host["interfaces"][0]["interfaceid"]
    have = {i["key_"] for i in z.call("item.get", {"hostids": hostid, "output": ["key_"]})}
    vmaps = {v["name"]: v["valuemapid"] for v in host["valuemaps"]}
    if "A10 server status" not in vmaps:
        vmaps["A10 server status"] = z.call("valuemap.create", {
            "hostid": hostid, "name": "A10 server status",
            "mappings": [{"value": "0", "newvalue": "Disabled"}, {"value": "1", "newvalue": "Up"},
                         {"value": "2", "newvalue": "Down"}]})["valuemapids"][0]

    def item(**kw):
        if kw["key_"] in have:
            return
        kw = {"hostid": hostid, "interfaceid": ifid, "type": 20, "history": base.HISTORY, "trends": base.TRENDS, **kw}
        z.call("item.create", kw)
        have.add(kw["key_"])

    for isp, gw_name in GATEWAYS.items():
        gw_ip = next(g for n, _, g, *_ in base.ISPS if n == isp)
        tags = [{"tag": "isp", "value": isp}, {"tag": "component", "value": "llb"}]
        item(name=f"{isp}: A10 LLB status ({gw_name})", key_=f"a10.llb.status[{isp}]", delay=POLL, value_type=3,
             snmp_oid=f"{SERVER_STATUS}.{idx(gw_ip)}", valuemapid=vmaps["A10 server status"], trends="0", tags=tags,
             description="The A10's own health-check verdict for this gateway. Down = the A10 has taken the "
                         "link out of load balancing.")
        item(name=f"{isp}: A10 LLB health flaps (since A10 boot)", key_=f"a10.llb.flaps[{isp}]", delay=POLL,
             value_type=3, snmp_oid=f"{MEMBER_FLAPS}.{idx(HEALTH_GROUP)}.{idx(gw_name)}.0", trends="0", tags=tags,
             preprocessing=base.pp((base.DISCARD_UNCHANGED_HEARTBEAT, "10m")),
             description=f"stateFlaps of {gw_name} in {HEALTH_GROUP}: how often the A10 health check marked it "
                         "down/up. Any increase = the A10 briefly removed this link.")
        item(name=f"{isp}: A10 LLB session-table entries", key_=f"a10.llb.conns[{isp}]", delay=POLL, value_type=3,
             snmp_oid=f"{SERVER_STATS}.2.{idx(gw_name)}", tags=tags, description=CONNS_DESC)
        item(name=f"{isp}: A10 LLB new connections per second", key_=f"a10.llb.cps[{isp}]", delay=POLL,
             value_type=0, units="conn/s", snmp_oid=f"{SERVER_STATS}.3.{idx(gw_name)}", tags=tags,
             preprocessing=base.pp((base.CHANGE_PER_SECOND, "")))
        for col, d, word in ((11, "out", "upload"), (12, "in", "download")):
            item(name=f"{isp}: A10 LLB {word}", key_=f"a10.llb.bits.{d}[{isp}]", delay=POLL, value_type=0,
                 units="bps", snmp_oid=f"{SERVER_STATS}.{col}.{idx(gw_name)}", tags=tags,
                 preprocessing=base.pp(*base.TRAFFIC_STEPS))
        for group, key, label in (("SG_TCP_V4", "a10.llb.syn", "New TCP connections (SYNs) per second"),
                                  ("SG_UDP_V4", "a10.llb.udp", "New UDP flows per second")):
            item(name=f"{isp}: {label}", key_=f"{key}[{isp}]", delay=POLL, value_type=0,
                 units="/s", snmp_oid=f"{MEMBER_TOTAL_CONN}.{idx(group)}.{idx(gw_name)}.0", trends=base.TRENDS,
                 tags=tags + [{"tag": "component", "value": "syn"}], preprocessing=base.pp((base.CHANGE_PER_SECOND, "")),
                 description=f"Rate of new {group} sessions the A10 opens via {gw_name}. For TCP each one is "
                             "a SYN sent out through this ISP.")
    for sub, key, name in NET_COUNTERS:
        item(name=name, key_=key, delay=POLL, value_type=0, units="/s", snmp_oid=f"{NET_STAT}.{sub}.0",
             tags=[{"tag": "component", "value": "syn"}], preprocessing=base.pp((base.CHANGE_PER_SECOND, "")))
    item(name="A10: TCP SYN sent to ISPs per second", key_="a10.tcp.syn.sent", type=15, interfaceid="0",
         delay=POLL, value_type=0, units="/s", tags=[{"tag": "component", "value": "syn"}],
         params="+".join(f"last(//a10.llb.syn[{isp}])" for isp in GATEWAYS),
         description="SYNs the A10 sent out through the ISP links: sum of new outbound TCP connections per ISP.")
    item(name="A10: SYN dropped per second (total)", key_="a10.tcp.syn.drop", type=15, interfaceid="0",
         delay=POLL, value_type=0, units="/s", tags=[{"tag": "component", "value": "syn"}],
         params="+".join(f"last(//{k})" for k in SYN_DROP_KEYS),
         description="SYN throttle drops + L4 SYN attack + SYN cookie send failures.")
    if "{$A10.SYN.MIN}" not in {mc["macro"] for mc in z.call("usermacro.get", {"hostids": hostid, "output": ["macro"]})}:
        z.call("usermacro.create", {"hostid": hostid, "macro": "{$A10.SYN.MIN}", "value": "2000",
                                    "description": "SYN-surge alert only above this many SYN/s"})

    for isp in GATEWAYS:
        # Flaps in the last 5 minutes: easier to read than the running total since boot.
        item(name=f"{isp}: A10 LLB health flaps (last 5 min)", key_=f"a10.llb.flaps.5m[{isp}]", type=15,
             interfaceid="0", delay="1m", value_type=3,
             params=f"last(//a10.llb.flaps[{isp}])-last(//a10.llb.flaps[{isp}],#1:now-5m)",
             tags=[{"tag": "isp", "value": isp}, {"tag": "component", "value": "llb"}],
             description="How many times the A10 health check changed this gateway's state in the last 5 minutes.")
    total = "+".join(f"last(//a10.llb.conns[{isp}])" for isp in GATEWAYS)
    for isp in GATEWAYS:
        item(name=f"{isp}: A10 LLB share of sessions", key_=f"a10.llb.conn.share[{isp}]", type=15, interfaceid="0",
             description=SHARE_DESC,
             delay=POLL, value_type=0, units="%", params=f"last(//a10.llb.conns[{isp}])/({total})*100",
             tags=[{"tag": "isp", "value": isp}, {"tag": "component", "value": "llb"}])

    h = f"/{base.HOST}/"
    have_t = {t["description"] for t in z.call("trigger.get", {"hostids": hostid, "output": ["description"]})}
    new = []
    for isp, gw_name in GATEWAYS.items():
        tags = [{"tag": "isp", "value": isp}, {"tag": "component", "value": "llb"}]
        new += [
            {"description": f"{isp}: A10 marked gateway DOWN (removed from load balancing)", "priority": 4,
             "tags": tags + [{"tag": "llb_down", "value": isp}],
             "expression": f"last({h}a10.llb.status[{isp}])=2"},
            {"description": f"{isp}: A10 health check flapped the gateway", "priority": 3, "tags": tags,
             "expression": f"change({h}a10.llb.flaps[{isp}])>0",
             "recovery_mode": 1, "recovery_expression": f"change({h}a10.llb.flaps[{isp}])=0",
             "comments": "The A10 briefly marked this gateway down and back up. Sessions on it may have been "
                         "moved or dropped even though ping and the port stayed up."},
        ]
        new.append({"description": f"{isp}: link up but no new TCP connections for 1m", "priority": 3,
                    "tags": tags + [{"tag": "component", "value": "syn"}],
                    "expression": f"max({h}a10.llb.syn[{isp}],1m)=0 and last({h}a10.llb.status[{isp}])=1"
                                  f" and last({h}isp.net.if.status[{isp}])=1",
                    "comments": "The A10 says the gateway is up, yet it opened no TCP sessions through it for a "
                                "minute: traffic is not being balanced onto this link."})
    syn_tags = [{"tag": "component", "value": "syn"}]
    new += [
        {"description": "A10: TCP SYN surge (over 3x the last hour's average for 2m)", "priority": 4, "tags": syn_tags,
         "expression": f"min({h}a10.tcp.syn.rcv,2m)>{{$A10.SYN.MIN}} and "
                       f"min({h}a10.tcp.syn.rcv,2m)>3*avg({h}a10.tcp.syn.rcv,1h:now-5m)",
         "comments": "Possible SYN flood or a reconnect storm (e.g. many clients reconnecting after a link failure)."},
        {"description": "A10: SYN-cookie protection active (possible SYN flood)", "priority": 3, "tags": syn_tags,
         "expression": f"min({h}a10.tcp.syncookie.sent,1m)>0"},
        {"description": "A10: SYN drops surge (over 3x the last hour's average for 2m)", "priority": 4, "tags": syn_tags,
         "expression": f"min({h}a10.tcp.syn.drop,2m)>500 and min({h}a10.tcp.syn.drop,2m)>3*avg({h}a10.tcp.syn.drop,1h:now-5m)"},
    ]
    new = [t for t in new if t["description"] not in have_t]
    if new:
        z.call("trigger.create", new)
    # Keep names/descriptions current on items created by earlier versions of this script.
    for i in z.call("item.get", {"hostids": hostid, "search": {"key_": "a10.llb.conn"}, "output": ["itemid", "key_"]}):
        isp = i["key_"].split("[")[1].rstrip("]")
        if i["key_"].startswith("a10.llb.conns["):
            z.call("item.update", {"itemid": i["itemid"], "name": f"{isp}: A10 LLB session-table entries", "description": CONNS_DESC})
        elif i["key_"].startswith("a10.llb.conn.share["):
            z.call("item.update", {"itemid": i["itemid"], "name": f"{isp}: A10 LLB share of sessions", "description": SHARE_DESC})
    print(f"LLB items ready for {', '.join(GATEWAYS)}; {len(new)} new triggers.")


if __name__ == "__main__":
    main()
