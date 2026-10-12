#!/usr/bin/env python3
"""Complete SNMP coverage of the A10 LLB (A10-LLB host), on top of setup_isp_links.py / add_llb_stats.py /
add_health_and_drop_alerts.py.

Added here (all on the host, discovered with low-level discovery where the A10 has a table):
  BGP          A10 BGP MIB 22610.2.5 (IPv4 AND IPv6 sessions; BGP4-MIB only shows IPv4): per peer state, admin
               state, remote AS / router ID, time in state, flaps (established transitions), last error,
               updates / messages per minute, time since last UPDATE, hold / keepalive, received prefixes
               (from the A10 BGP routes table); local AS, router ID, locally originated networks.
  Ports        every A10 port incl. the VE (axInterfaceTable / axInterfaceStatTable, counters refresh 1s):
               status, admin, speed, duplex, MTU, flow control, bits, packets, multicast, errors, drops,
               collisions, A10's own utilisation %; management port from IF-MIB.
  Trunks       LACP trunk status, traffic, errors, drops; member (bundled) status.
  SLB          every real server (ISP gateways incl. IPv6), service group, service-group member, virtual
               server and virtual port: status, current / new connections, bytes, peak connections,
               member response time.
  Sessions     A10 session table by type, current connections, new connections per second (L4/L7/NAT/SSL),
               total throughput, buffer drops.
  Drops        every axNetStat / axNetStatExt / axSwitchStats counter as a per-second rate.
  System       data / control CPU, disk, software versions, serial, startup mode, HA, ARP entries, routes.
Not available on this A10 (BareMetal, ACOS 6.0.8): temperature, fan and PSU OIDs all return 0; OSPF and HA
(VRRP-A) are not configured; no LLDP neighbours.

Idempotent: existing items / rules / prototypes / triggers (by key / name) are left as they are.
"""
import json

import add_routers as r
import setup_isp_links as base

H = base.HOST
A10 = "1.3.6.1.4.1.22610"
DEPENDENT, SNMP, CALCULATED = r.DEPENDENT, r.SNMP, r.CALCULATED
FLOAT, UINT, TEXT, CHAR = r.FLOAT, r.UINT, r.TEXT, 1
WALK_VALUE, WALK_JSON, JS = r.SNMP_WALK_VALUE, r.SNMP_WALK_TO_JSON, r.JAVASCRIPT
CPS, MULT, DISCARD_HB = base.CHANGE_PER_SECOND, base.MULTIPLIER, base.DISCARD_UNCHANGED_HEARTBEAT
TRENDS = "730d"

BGP_AS_ISP = {"9498": "Airtel", "55836": "Jio", "142470": "PowerGrid"}
PORT_ISP = {str(idx): name for name, idx, *_ in base.ISPS}

# ---------------------------------------------------------------- JavaScript used by discovery / items
BGP_LLD_JS = r"""
var isp = %s;
return JSON.stringify(JSON.parse(value).map(function (r) {
    var p = r['{#SNMPINDEX}'].split('.'), t = p.shift();
    if (t === '1') {
        r['{#PEER}'] = p.join('.'); r['{#AF}'] = 'IPv4';
    } else {
        var g = [];
        for (var i = 0; i < 16; i += 2) g.push((parseInt(p[i]) * 256 + parseInt(p[i + 1])).toString(16));
        r['{#PEER}'] = g.join(':').replace(/(^|:)0(:0)+(:|$)/, '::'); r['{#AF}'] = 'IPv6';
    }
    r['{#ISP}'] = isp[r['{#REMOTE_AS}']] || ('AS' + r['{#REMOTE_AS}']);
    return r;
}));
""" % json.dumps(BGP_AS_ISP)
# BGP NOTIFICATION code/subcode (RFC 4271) of the last error, e.g. "06 00" -> "6/0 Cease"
BGP_ERROR_JS = r"""
var b = value.replace(/[^0-9A-Fa-f ]/g, '').trim().split(/\s+/);
var c = parseInt(b[0] || '0', 16), s = parseInt(b[1] || '0', 16);
if (!c) return 'none';
var n = {1: 'Message header error', 2: 'OPEN message error', 3: 'UPDATE message error', 4: 'Hold timer expired',
         5: 'Finite state machine error', 6: 'Cease'}[c] || 'Unknown';
var cease = {1: 'max prefixes reached', 2: 'administrative shutdown', 3: 'peer de-configured', 4: 'administrative reset',
             5: 'connection rejected', 6: 'other configuration change', 7: 'connection collision', 8: 'out of resources'};
return c + '/' + s + ' ' + n + (c === 6 && cease[s] ? ' (' + cease[s] + ')' : '');
"""
COUNT_ROWS_JS = r"""
var n = 0, suffixes = %s;
value.split('\n').forEach(function (l) {
    var oid = l.split(' = ')[0];
    for (var i = 0; i < suffixes.length; i++) if (oid.slice(-suffixes[i].length) === suffixes[i]) { n++; break; }
});
return n;
"""
LOCAL_NET_SUFFIXES = [".1.0.0.0.0", ".2" + ".0" * 16]    # routes whose "peer" is 0.0.0.0 / :: = our own networks
PORT_LLD_JS = r"""
var isp = %s;
return JSON.stringify(JSON.parse(value).map(function (r) {
    var name = r['{#IFNAME}'] || '', alias = (r['{#IFALIAS}'] || '').replace(/#+/g, ' ').replace(/\s+/g, ' ').trim();
    alias = alias.replace(/[-_ ]*\d+(\.\d+)?\s*(Gbps|Mbps|Gig|Meg)\b/ig, '');   // never show contracted capacity
    var m = name.match(/^(Virtual )?Ethernet (\d+)$/);
    r['{#IFSHORT}'] = m ? (m[1] ? 've' : 'e') + m[2] : name;
    r['{#IFISP}'] = isp[r['{#SNMPINDEX}']] || '';
    r['{#IFDESC}'] = [name, r['{#IFISP}'] ? r['{#IFISP}'] + ' ISP' : '', alias].filter(function (x) { return x; }).join(', ');
    return r;
}));
""" % json.dumps(PORT_ISP)
VPORT_LLD_JS = r"""
var t = {1: 'firewall', 2: 'tcp', 3: 'udp', 5: 'others', 8: 'rtsp', 9: 'ftp', 12: 'fast-http', 14: 'http', 15: 'https',
         16: 'ssl-proxy', 17: 'smtp', 20: 'tcp-proxy', 22: 'dns-udp', 24: 'dns-tcp'};
return JSON.stringify(JSON.parse(value).map(function (r) {
    r['{#PROTO}'] = t[r['{#PTYPE}']] || ('type' + r['{#PTYPE}']);
    return r;
}));
"""

# ---------------------------------------------------------------- value maps
VALUEMAPS = {
    "BGP4-MIB::bgpPeerState": [(1, "idle"), (2, "connect"), (3, "active"), (4, "opensent"), (5, "openconfirm"),
                               (6, "established")],
    "BGP admin status": [(1, "stop (shut down)"), (2, "start (enabled)")],
    "BGP session state": [(0, "shutdown"), (1, "idle"), (2, "connect"), (3, "active"), (4, "opensent"),
                          (5, "openconfirm"), (6, "established")],
    "A10 port status": [(0, "up"), (1, "down"), (2, "disabled")],
    "A10 enabled": [(0, "disabled"), (1, "enabled")],
    "A10 duplex": [(0, "none"), (1, "half"), (2, "full"), (3, "auto")],
    "A10 up/down": [(0, "down"), (1, "up")],
    "A10 server status": [(0, "Disabled"), (1, "Up"), (2, "Down")],
    "A10 group status": [(0, "disabled"), (1, "all up"), (2, "functional up (some members down)"),
                         (3, "partial up"), (4, "stopped")],
    "A10 virtual server status": [(1, "up"), (2, "down"), (3, "disabled")],
    "A10 startup mode": [(0, "unknown"), (1, "primary disk"), (2, "secondary disk"), (3, "primary CF"),
                         (4, "secondary CF")],
    "IF-MIB::ifOperStatus": [(1, "up"), (2, "down"), (3, "testing"), (4, "unknown"), (5, "dormant"),
                             (6, "notPresent"), (7, "lowerLayerDown")],
}

# ---------------------------------------------------------------- scalar counters (walk master, OID, key, name, kind)
# kind: rate = per second, gauge = as is, bps = bytes -> bits per second (not used), text = string
NETSTAT = f"{A10}.2.4.3.11"
NET_COUNTERS = [  # sub-OID under axNetStat, key, name  (a10.tcp.* SYN counters already exist - add_llb_stats.py)
    ("1", "ip.out.noroute", "IP packets out with no route"),
    ("6", "tcp.rcv", "TCP packets received"), ("7", "udp.rcv", "UDP packets received"),
    ("8", "server.selfail", "Real-server selection failures"), ("9", "snat.fail", "Source NAT failures"),
    ("11", "novport.drop", "Drops: no matching virtual port"), ("12", "nosyn.drop", "Drops: TCP packet without session (no SYN)"),
    ("13", "connlimit.drop", "Drops: server connection limit"), ("14", "connlimit.reset", "Resets: server connection limit"),
    ("15", "proxy.nosock.drop", "Drops: proxy had no socket"), ("16", "aflex.drop", "Drops: aFleX"),
    ("17", "session.agingout", "Sessions aged out"), ("18", "tcp.noslb", "TCP packets in non-SLB processing"),
    ("19", "udp.noslb", "UDP packets in non-SLB processing"),
    ("20", "rst.nosyn", "TCP RST sent: no SYN"), ("21", "rst.l4proxy", "TCP RST sent: L4 proxy"),
    ("22", "rst.ackattack", "TCP RST sent: ACK attack"), ("23", "rst.aflex", "TCP RST sent: aFleX"),
    ("24", "rst.stale", "TCP RST sent: stale session"), ("25", "rst.proxy", "TCP RST sent: TCP proxy"),
    ("26", "nosyn.fin", "Drops: no-SYN FIN"), ("27", "nosyn.rst", "Drops: no-SYN RST"), ("28", "nosyn.ack", "Drops: no-SYN ACK"),
    ("41", "connrate.drop", "Drops: connection rate limit"), ("42", "connrate.reset", "Resets: connection rate limit"),
    ("43", "inbandhm.retry", "In-band health monitor retries"), ("44", "inbandhm.reassign", "In-band health monitor reassigns"),
    ("90.3", "snat.nofwdroute", "Source NAT: no forward route"), ("90.4", "snat.norevroute", "Source NAT: no reverse route"),
    ("90.5", "snat.icmp", "Source NAT: ICMP processed"), ("90.6", "snat.icmp.nomatch", "Source NAT: ICMP no match"),
    ("90.7", "autonat.idmismatch", "Auto NAT id mismatch"), ("90.9", "tcp.agedout", "TCP sessions aged out"),
    ("90.10", "udp.agedout", "UDP sessions aged out"), ("90.11", "other.agedout", "Other sessions aged out"),
    ("90.12", "autoreselect", "Auto-reselect server"), ("90.13", "fastaging.set", "Fast aging set"),
    ("90.15", "tcp.invalid.drop", "Drops: invalid TCP"), ("90.16", "outofseq.ack.drop", "Drops: out-of-sequence ACK"),
    ("90.17", "syn.stale.drop", "Drops: SYN on stale session"), ("90.18", "anomaly.outofseq", "Anomaly: out of sequence"),
    ("90.19", "anomaly.zerowin", "Anomaly: zero window"), ("90.20", "anomaly.badcontent", "Anomaly: bad content"),
    ("90.22", "noresource.drop", "Drops: no resource"), ("90.23", "reset.unknown", "Resets: unknown connection"),
    ("90.25", "syn.otherflags.drop", "Drops: SYN with other flags"), ("90.26", "syn.data.drop", "Drops: SYN with data"),
    ("90.28", "nat.portpreserve.try", "NAT port preserve tries"), ("90.29", "nat.portpreserve.ok", "NAT port preserve successes"),
    ("90.30", "bwlimit.drop", "Drops: bandwidth limit exceeded"), ("90.31", "bwwatermark.drop", "Drops: bandwidth watermark"),
    ("90.32", "l4cps.drop", "Drops: L4 connections/s limit"), ("90.33", "natcps.drop", "Drops: NAT connections/s limit"),
    ("90.34", "l7cps.drop", "Drops: L7 connections/s limit"), ("90.38", "l3vconnlimit.drop", "Drops: L3V connection limit"),
    ("90.39", "l4.server.hsfail", "L4 server handshake failures"), ("90.40", "l4.rexmit.syn", "L4: A10 re-sent SYN"),
    ("90.41", "l4.ackonsyn", "L4: ACK received on SYN"), ("90.42", "l4.rstonsyn", "L4: RST received on SYN"),
    ("90.43", "tcp.noest.agedout", "TCP not-established sessions aged out"),
    ("90.44", "noest.csyn.agedout", "Not-established: client SYN aged out"),
    ("90.45", "noest.ssyn.agedout", "Not-established: server SYN aged out"),
    ("90.46", "l4.rcv.rexmit.syn", "L4: retransmitted SYN received"),
    ("90.48", "l4.rcv.rexmit.synack", "L4: retransmitted SYN-ACK received"),
    ("90.52", "l4.fwd.fin", "L4: FIN from client"), ("90.55", "l4.rev.fin", "L4: FIN from server"),
    ("90.58", "l4.fwd.rst", "L4: RST from client"), ("90.59", "l4.rev.rst", "L4: RST from server"),
    ("90.60", "udp.noresp", "UDP requests without response"), ("90.65", "udp.reqs", "UDP requests"),
    ("90.66", "udp.resps", "UDP responses"), ("90.67", "l4.tcp.est", "L4 TCP connections established"),
]
SWSTAT = f"{A10}.2.4.3.16"
SWITCH_COUNTERS = [
    ("1", "l2.fwd", "L2 switched packets"), ("2", "l3.ipv4.fwd", "IPv4 routed packets"),
    ("3", "ipv4.noroute.drop", "Drops: IPv4 no route"), ("4", "l3.ipv6.fwd", "IPv6 routed packets"),
    ("5", "ipv6.noroute.drop", "Drops: IPv6 no route"), ("6", "l4.process", "Packets to VIP/NAT (L4 processing)"),
    ("7", "badlen.drop", "Drops: incorrect length"), ("8", "protodown.drop", "Drops: protocol down"),
    ("9", "unknownproto.drop", "Drops: unknown protocol"), ("10", "ttl.drop", "Drops: TTL exceeded"),
    ("11", "linkdown.drop", "Drops: outgoing link down"), ("12", "srcport.suppress", "Drops: source port suppression"),
    ("13", "vlan.flood", "VLAN flooded packets"), ("14", "ipfrag.rcv", "IPv4 fragments received"),
    ("15", "arp.req", "ARP requests received"), ("16", "arp.resp", "ARP responses received"),
    ("17", "kernel.fwd", "Packets to the A10 kernel (control plane)"), ("18", "tcpfrag.rcv", "TCP fragments received"),
    ("20", "frag.overlap.drop", "Drops: overlapping fragments"), ("21", "frag.reasm.ok", "Fragments reassembled"),
    ("22", "frag.reasm.fail", "Fragment reassembly failures"), ("23", "anom.land.drop", "DDoS drops: LAND attack"),
    ("24", "anom.ipopt.drop", "DDoS drops: IP options"), ("25", "anom.pod.drop", "DDoS drops: ping of death"),
    ("26", "anom.frag.drop", "DDoS drops: fragments"), ("27", "anom.tcpnoflag.drop", "DDoS drops: TCP no flags"),
    ("28", "anom.synfrag.drop", "DDoS drops: SYN fragment"), ("29", "anom.synfin.drop", "DDoS drops: SYN+FIN"),
    ("30", "anom.any.drop", "DDoS drops: total (hardware DDoS protection)"),
]
SESSION_ITEMS = [  # OID, key, name, kind, units
    (f"{A10}.2.4.3.19.1.1.0", "sess.tcp.est", "Sessions: TCP established", "gauge", ""),
    (f"{A10}.2.4.3.19.1.2.0", "sess.tcp.halfopen", "Sessions: TCP half-open", "gauge", ""),
    (f"{A10}.2.4.3.19.1.12.0", "sess.tcp.synhalfopen", "Sessions: TCP SYN half-open", "gauge", ""),
    (f"{A10}.2.4.3.19.1.3.0", "sess.udp", "Sessions: UDP", "gauge", ""),
    (f"{A10}.2.4.3.19.1.4.0", "sess.ip", "Sessions: other IP (not TCP/UDP)", "gauge", ""),
    (f"{A10}.2.4.3.19.1.5.0", "sess.other", "Sessions: other", "gauge", ""),
    (f"{A10}.2.4.3.19.1.6.0", "sess.revnat.tcp", "Sessions: reverse NAT TCP", "gauge", ""),
    (f"{A10}.2.4.3.19.1.7.0", "sess.revnat.udp", "Sessions: reverse NAT UDP", "gauge", ""),
    (f"{A10}.2.4.3.19.1.9.0", "sess.free", "Session table: free entries", "gauge", ""),
    (f"{A10}.2.4.3.19.1.13.0", "sess.smp.alloc", "Session table: SMP connections allocated", "gauge", ""),
    (f"{A10}.2.4.3.19.1.14.0", "sess.smp.free", "Session table: SMP connections free", "gauge", ""),
    (f"{A10}.2.4.3.1.2.11.0", "conn.current", "Current connections (total)", "gauge", ""),
    (f"{A10}.2.4.3.1.2.12.0", "conn.l4sessions", "Current L4 sessions", "gauge", ""),
    (f"{A10}.2.4.3.1.2.2.0", "conn.new", "New connections per second", "rate", "conn/s"),
    (f"{A10}.2.4.3.1.2.3.0", "conn.new.l4", "New L4 connections per second", "rate", "conn/s"),
    (f"{A10}.2.4.3.1.2.4.0", "conn.new.l7", "New L7 connections per second", "rate", "conn/s"),
    (f"{A10}.2.4.3.1.2.5.0", "conn.new.ipnat", "New IP-NAT connections per second", "rate", "conn/s"),
    (f"{A10}.2.4.3.1.2.6.0", "conn.new.ssl", "New SSL connections per second", "rate", "conn/s"),
    (f"{A10}.2.4.3.1.2.7.0", "l7.requests", "L7 requests per second", "rate", "req/s"),
    (f"{A10}.2.4.3.1.2.9.0", "buffer.drop", "Buffer (application packet) drops per second", "rate", "pkt/s"),
    (f"{A10}.2.4.3.1.2.13.0", "throughput", "Total throughput, all interfaces", "gauge", "bps"),
]
SYSTEM_ITEMS = [  # OID, key, name, kind, units
    (f"{A10}.2.4.1.3.3.0", "cpu.avg5s", "CPU average (all cores, 5 s)", "gauge", "%"),
    (f"{A10}.2.4.1.3.4.0", "cpu.control", "CPU control plane (5 s average)", "gauge", "%"),
    (f"{A10}.2.4.1.3.5.0", "cpu.data", "CPU data plane (5 s average)", "gauge", "%"),
    (f"{A10}.2.4.1.4.1.0", "disk.total", "Disk total", "mb", "B"),
    (f"{A10}.2.4.1.4.2.0", "disk.free", "Disk free", "mb", "B"),
    (f"{A10}.2.4.1.1.1.0", "sw.primary", "Software on primary disk", "text", ""),
    (f"{A10}.2.4.1.1.2.0", "sw.secondary", "Software on secondary disk", "text", ""),
    (f"{A10}.2.4.1.6.1.0", "startup", "Startup image", "map:A10 startup mode", ""),
    (f"{A10}.2.4.1.6.2.0", "serial", "Serial number", "text", ""),
    (f"{A10}.2.4.3.17.1.1.0", "ha.enabled", "High availability (VRRP-A) configured", "map:A10 enabled", ""),
    (f"{A10}.2.4.1.7.100.1.1.0", "arp.entries", "ARP entries", "gauge", ""),
    ("1.3.6.1.2.1.4.24.3.0", "routes", "IPv4 routes in routing table", "gauge", ""),
    (f"{A10}.2.5.2.0", "bgp.local.as", "BGP local AS", "gauge", ""),
    (f"{A10}.2.5.3.0", "bgp.router.id", "BGP router ID", "text", ""),
]


def main():
    z = base.Zabbix()
    host = z.call("host.get", {"filter": {"host": [H]}, "selectInterfaces": ["interfaceid"],
                               "selectValueMaps": ["valuemapid", "name"]})[0]
    hid, ifid = host["hostid"], host["interfaces"][0]["interfaceid"]
    vm = {v["name"]: v["valuemapid"] for v in host["valuemaps"]}
    for name, maps in VALUEMAPS.items():
        if name not in vm:
            vm[name] = z.call("valuemap.create", {"hostid": hid, "name": name, "mappings": [
                {"value": str(v), "newvalue": t} for v, t in maps]})["valuemapids"][0]
    items = {i["key_"]: i["itemid"] for i in z.call("item.get", {"hostids": hid, "output": ["key_"]})}
    created = {"items": 0, "rules": 0, "protos": 0, "triggers": 0}

    def item(key, **kw):
        if key not in items:
            base_kw = {"hostid": hid, "key_": key, "history": "90d"}
            if kw.get("type") == SNMP:
                base_kw["interfaceid"] = ifid
            items[key] = z.call("item.create", {**base_kw, **kw})["itemids"][0]
            created["items"] += 1
        return items[key]

    def rule(key, **kw):
        found = z.call("discoveryrule.get", {"hostids": hid, "filter": {"key_": key}, "output": ["itemid"]})
        if found:
            return found[0]["itemid"]
        created["rules"] += 1
        return z.call("discoveryrule.create", {"hostid": hid, "key_": key, "lifetime": "7d", **kw})["itemids"][0]

    def proto(rid, key, **kw):
        found = z.call("itemprototype.get", {"discoveryids": rid, "filter": {"key_": key}, "output": ["itemid"]})
        if found:
            return found[0]["itemid"]
        created["protos"] += 1
        return z.call("itemprototype.create", {"hostid": hid, "ruleid": rid, "key_": key, "history": "90d", **kw})["itemids"][0]

    def tproto(rid, description, **kw):
        have = {t["description"] for t in z.call("triggerprototype.get", {"discoveryids": rid, "output": ["description"]})}
        if description not in have:
            z.call("triggerprototype.create", {"description": description, **kw})
            created["triggers"] += 1

    have_t = {t["description"] for t in z.call("trigger.get", {"hostids": hid, "output": ["description"]})}

    def trigger(description, **kw):
        if description not in have_t:
            z.call("trigger.create", {"description": description, **kw})
            have_t.add(description)
            created["triggers"] += 1

    def walk_master(key, name, oids, delay):
        return item(key, name=f"A10 raw: {name}", type=SNMP, snmp_oid=r.walk(*oids), delay=delay,
                    value_type=TEXT, history="0", trends="0", tags=[{"tag": "component", "value": "raw"}])

    def wv(oid):
        return (WALK_VALUE, f"{oid}\n0")

    rate_steps = lambda oid: base.pp(wv(oid), (CPS, ""))
    status_steps = lambda oid, hb="10m": base.pp(wv(oid), (DISCARD_HB, hb))
    bits_steps = lambda oid: base.pp(wv(oid), *base.TRAFFIC_STEPS)

    # ================================================================ BGP
    bgp_peer = f"{A10}.2.5.4.1"
    bgp_walk = walk_master("a10.bgp.walk", "BGP peer table (A10 BGP MIB, IPv4 + IPv6)", [bgp_peer], "30s")
    routes_walk = walk_master("a10.bgp.routes.walk", "BGP routes table", [f"{A10}.2.5.5.1.3"], "1m")
    brule = rule("a10.bgp.peer.discovery", name="A10 BGP peer discovery (IPv4 + IPv6)", type=DEPENDENT,
                 master_itemid=bgp_walk,
                 preprocessing=base.pp((WALK_JSON, f"{{#REMOTE_AS}}\n{bgp_peer}.10\n0"),
                                       (JS, BGP_LLD_JS.strip()), (DISCARD_HB, "1h")),
                 description="Every BGP session configured on the A10, both address families.")
    bname = "BGP {#ISP} {#AF} peer {#PEER} (AS{#REMOTE_AS})"
    btags = [{"tag": "component", "value": "bgp"}, {"tag": "isp", "value": "{#ISP}"},
             {"tag": "bgp_peer", "value": "{#PEER}"}, {"tag": "af", "value": "{#AF}"}]
    col = lambda c: f"{bgp_peer}.{c}.{{#SNMPINDEX}}"

    def bproto(key, label, oid_col, steps=None, **kw):
        kw.setdefault("value_type", UINT)
        kw.setdefault("trends", TRENDS if kw["value_type"] in (UINT, FLOAT) else "0")
        return proto(brule, f"a10.bgp.{key}[{{#SNMPINDEX}}]", name=f"{bname}: {label}", type=DEPENDENT,
                     master_itemid=bgp_walk, tags=btags,
                     preprocessing=base.pp(*(steps or [wv(col(oid_col))])), **kw)

    bproto("state", "State", 3, valuemapid=vm["BGP4-MIB::bgpPeerState"], trends="0")
    bproto("admin", "Admin status", 4, [wv(col(4)), (DISCARD_HB, "1h")], valuemapid=vm["BGP admin status"], trends="0")
    proto(brule, "a10.bgp.session[{#SNMPINDEX}]", name=f"{bname}: Session state", type=CALCULATED, delay="30s",
          value_type=UINT, valuemapid=vm["BGP session state"], trends="0", tags=btags,
          params="last(//a10.bgp.state[{#SNMPINDEX}])*(last(//a10.bgp.admin[{#SNMPINDEX}])=2)",
          description="BGP state, or 0 = shutdown when the session is administratively stopped. 6 = Established.")
    bproto("remote.as", "Remote AS", 10, [wv(col(10)), (DISCARD_HB, "1h")], trends="0")
    bproto("router.id", "Remote router ID", 2, [wv(col(2)), (DISCARD_HB, "1h")], value_type=CHAR)
    bproto("uptime", "Time in current state", 17, units="uptime",
           description="Seconds since the session last entered Established (while up) or left it (while down).")
    bproto("flaps", "Flaps (times Established since A10 boot)", 16, description="bgpPeerFsmEstablishedTransitions.")
    bproto("lasterror", "Last error (NOTIFICATION code/subcode)", 15,
           [wv(col(15)), (JS, BGP_ERROR_JS.strip()), (DISCARD_HB, "1h")], value_type=CHAR)
    for c, key, label in ((11, "updates.in", "UPDATE messages received per minute"),
                          (12, "updates.out", "UPDATE messages sent per minute"),
                          (13, "msgs.in", "Messages received per minute"), (14, "msgs.out", "Messages sent per minute")):
        bproto(key, label, c, [wv(col(c)), (CPS, ""), (MULT, "60")], value_type=FLOAT, units="/min")
    bproto("update.elapsed", "Time since last UPDATE received", 25, units="uptime")
    bproto("holdtime", "Hold time (negotiated)", 19, [wv(col(19)), (DISCARD_HB, "1h")], units="s")
    bproto("keepalive", "Keepalive (negotiated)", 20, [wv(col(20)), (DISCARD_HB, "1h")], units="s")
    proto(brule, "a10.bgp.prefixes[{#SNMPINDEX}]", name=f"{bname}: Received prefixes", type=DEPENDENT,
          master_itemid=routes_walk, value_type=UINT, trends=TRENDS, tags=btags,
          preprocessing=base.pp((JS, COUNT_ROWS_JS.strip() % json.dumps([".{#SNMPINDEX}"]))),
          description="Routes in the A10 BGP table learned from this peer (each ISP normally sends a default route).")
    k = lambda key: f"/{H}/a10.bgp.{key}[{{#SNMPINDEX}}]"
    tproto(brule, f"{bname}: BGP session DOWN (state {{ITEM.LASTVALUE1}})", priority=4,
           expression=f"last({k('state')})<>6 and last({k('admin')})=2",
           recovery_mode=1, recovery_expression=f"last({k('state')})=6 or last({k('admin')})=1",
           tags=[{"tag": "component", "value": "bgp"}, {"tag": "isp", "value": "{#ISP}"}],
           comments="The BGP session is enabled on the A10 but not Established: routes from this ISP are withdrawn.")
    tproto(brule, f"{bname}: BGP session flapped (re-established in the last 10 min)", priority=3,
           expression=f"last({k('flaps')})-last({k('flaps')},#1:now-10m)>0",
           tags=[{"tag": "component", "value": "bgp"}, {"tag": "isp", "value": "{#ISP}"}],
           comments="The session went down and came back. Sessions over this ISP may have been reset.")
    tproto(brule, f"{bname}: Established but no prefixes received", priority=3,
           expression=f"max({k('prefixes')},3m)=0 and last({k('state')})=6",
           tags=[{"tag": "component", "value": "bgp"}, {"tag": "isp", "value": "{#ISP}"}],
           comments="The ISP stopped sending routes (normally a default route) although the session is up.")
    item("a10.bgp.local.networks", name="A10: BGP locally originated networks", type=DEPENDENT,
         master_itemid=routes_walk, value_type=UINT, trends=TRENDS, tags=[{"tag": "component", "value": "bgp"}],
         preprocessing=base.pp((JS, COUNT_ROWS_JS.strip() % json.dumps(LOCAL_NET_SUFFIXES))),
         description="Our own prefixes in the A10 BGP table (advertised to the ISPs).")
    item("a10.bgp.routes.total", name="A10: BGP routes in table", type=DEPENDENT, master_itemid=routes_walk,
         value_type=UINT, trends=TRENDS, tags=[{"tag": "component", "value": "bgp"}],
         preprocessing=base.pp((JS, "return value.split('\\n').filter(function (l) { return l.indexOf(' = ') > 0; }).length;")))

    # ================================================================ Ports
    if_cfg, if_stat = f"{A10}.2.4.1.7.1.1.2.1", f"{A10}.2.4.1.7.1.2.1.1"
    cfg_walk = walk_master("a10.if.cfg.walk", "interface table", [if_cfg], "30s")
    stat_walk = walk_master("a10.if.stat.walk", "interface counters (1 s refresh)", [if_stat], "10s")
    prule = rule("a10.if.discovery", name="A10 port discovery", type=DEPENDENT, master_itemid=cfg_walk,
                 preprocessing=base.pp((WALK_JSON, f"{{#IFNAME}}\n{if_cfg}.2\n0\n{{#IFALIAS}}\n{if_cfg}.11\n0"),
                                       (JS, PORT_LLD_JS.strip()), (DISCARD_HB, "1h")))
    pname = "A10 port {#IFSHORT} ({#IFDESC})"
    ptags = [{"tag": "component", "value": "port"}, {"tag": "interface", "value": "{#IFSHORT}"}]

    def pproto(key, label, master, steps, **kw):
        kw.setdefault("value_type", FLOAT)
        kw.setdefault("trends", TRENDS)
        return proto(prule, f"a10.if.{key}[{{#SNMPINDEX}}]", name=f"{pname}: {label}", type=DEPENDENT,
                     master_itemid=master, tags=ptags, preprocessing=base.pp(*steps), **kw)

    c_ = lambda t, c: f"{t}.{c}.{{#SNMPINDEX}}"
    pproto("status", "Status", cfg_walk, [wv(c_(if_cfg, 10)), (DISCARD_HB, "10m")], value_type=UINT, trends="0",
           valuemapid=vm["A10 port status"])
    pproto("admin", "Admin status", cfg_walk, [wv(c_(if_cfg, 9)), (DISCARD_HB, "1h")], value_type=UINT, trends="0",
           valuemapid=vm["A10 enabled"])
    pproto("speed", "Speed", cfg_walk, [wv(c_(if_cfg, 5)), (MULT, "1000000"), (DISCARD_HB, "1h")], value_type=UINT,
           units="bps", trends="0")
    pproto("duplex", "Duplex", cfg_walk, [wv(c_(if_cfg, 6)), (DISCARD_HB, "1h")], value_type=UINT, trends="0",
           valuemapid=vm["A10 duplex"])
    pproto("mtu", "MTU", cfg_walk, [wv(c_(if_cfg, 8)), (DISCARD_HB, "1h")], value_type=UINT, trends="0")
    pproto("flowctrl", "Flow control", cfg_walk, [wv(c_(if_cfg, 13)), (DISCARD_HB, "1h")], value_type=UINT,
           trends="0", valuemapid=vm["A10 enabled"])
    pproto("in", "Bits received", stat_walk, [wv(c_(if_stat, 3)), *base.TRAFFIC_STEPS], units="bps")
    pproto("out", "Bits sent", stat_walk, [wv(c_(if_stat, 5)), *base.TRAFFIC_STEPS], units="bps")
    for c, key, label, units in ((2, "pkts.in", "Packets received", "pps"), (4, "pkts.out", "Packets sent", "pps"),
                                 (6, "mcast.in", "Multicast received", "pps"), (7, "mcast.out", "Multicast sent", "pps"),
                                 (8, "errors.in", "Inbound errors", "errors/s"), (9, "errors.out", "Outbound errors", "errors/s"),
                                 (10, "drops.in", "Inbound drops", "pkt/s"), (11, "drops.out", "Outbound drops", "pkt/s"),
                                 (12, "collisions", "Collisions", "/s")):
        pproto(key, label, stat_walk, [wv(c_(if_stat, c)), (CPS, "")], units=units)
    pproto("util.in", "Port utilisation in (% of port speed)", stat_walk, [wv(c_(if_stat, 15))], units="%")
    pproto("util.out", "Port utilisation out (% of port speed)", stat_walk, [wv(c_(if_stat, 18))], units="%")
    pk = lambda key: f"/{H}/a10.if.{key}[{{#SNMPINDEX}}]"
    tproto(prule, f"{pname}: link went DOWN", priority=3,
           expression=f"last({pk('status')})=1 and last({pk('status')},#2)=0",
           recovery_mode=1, recovery_expression=f"last({pk('status')})<>1",
           tags=[{"tag": "component", "value": "port"}, {"tag": "interface", "value": "{#IFSHORT}"}],
           comments="The port was up and is now down (ports that were never cabled do not alert).")
    tproto(prule, f"{pname}: inbound errors over {{$A10.IF.ERRORS.WARN}}/s for 5m", priority=2,
           expression=f"min({pk('errors.in')},5m)>{{$A10.IF.ERRORS.WARN}}",
           tags=[{"tag": "component", "value": "port"}, {"tag": "interface", "value": "{#IFSHORT}"}])
    tproto(prule, f"{pname}: inbound drops over {{$A10.IF.DROPS.WARN}}/s for 5m", priority=2,
           expression=f"min({pk('drops.in')},5m)>{{$A10.IF.DROPS.WARN}}",
           tags=[{"tag": "component", "value": "port"}, {"tag": "interface", "value": "{#IFSHORT}"}])
    tproto(prule, f"{pname}: running half duplex", priority=2,
           expression=f"last({pk('duplex')})=1 and last({pk('status')})=0",
           tags=[{"tag": "component", "value": "port"}, {"tag": "interface", "value": "{#IFSHORT}"}])
    # Management port (not in the A10 interface table)
    mtags = [{"tag": "component", "value": "port"}, {"tag": "interface", "value": "mgmt"}]
    item("a10.mgmt.status", name="A10 management port: Status", type=SNMP,
         snmp_oid="1.3.6.1.2.1.2.2.1.8.0", delay="30s", value_type=UINT, trends="0", tags=mtags,
         valuemapid=vm["IF-MIB::ifOperStatus"], preprocessing=base.pp((DISCARD_HB, "10m")))
    for oid, key, label in (("1.3.6.1.2.1.31.1.1.1.6.0", "in", "Bits received"),
                            ("1.3.6.1.2.1.31.1.1.1.10.0", "out", "Bits sent")):
        item(f"a10.mgmt.{key}", name=f"A10 management port: {label}", type=SNMP, snmp_oid=oid,
             delay="1m", value_type=FLOAT, units="bps", trends=TRENDS, tags=mtags,
             preprocessing=base.pp((CPS, ""), (MULT, "8")))

    def slow_rate(rid, w, nm, tg, key, label, oid, mult, units):
        """Rate of a counter the A10 refreshes only every ~60 s (trunk and legacy SLB stat tables): a raw item keeps
        changed values only, and a calculated rate() over RATE_WINDOW spans 2-3 real updates (a 10 s change-per-second
        would read 0 five times, then 6x the real rate). Converts a dependent item from an earlier version in place."""
        raw = f"{key}.raw[{{#SNMPINDEX}}]"
        proto(rid, raw, name=f"A10 raw: {nm}: {label} (counter)", type=DEPENDENT, master_itemid=w, value_type=UINT,
              history="7d", trends="0", tags=tg + [{"tag": "component", "value": "raw"}],
              preprocessing=base.pp(wv(oid), (DISCARD_HB, "1m")))
        calc = dict(name=f"{nm}: {label}", type=CALCULATED, delay="30s", value_type=FLOAT, units=units,
                    trends=TRENDS, tags=tg, params=f"rate(//{raw},{base.RATE_WINDOW})" + (f"*{mult}" if mult != 1 else ""))
        found = z.call("itemprototype.get", {"discoveryids": rid, "filter": {"key_": f"{key}[{{#SNMPINDEX}}]"},
                                             "output": ["itemid", "type"]})
        if not found:
            proto(rid, f"{key}[{{#SNMPINDEX}}]", **calc)
        elif found[0]["type"] != str(CALCULATED):
            z.call("itemprototype.update", {"itemid": found[0]["itemid"], "preprocessing": [], **calc})

    # ================================================================ Trunks (LACP)
    tr_cfg, tr_stat, tr_mem = f"{A10}.2.4.1.7.3.1.2.1", f"{A10}.2.4.1.7.3.2.2.1", f"{A10}.2.4.1.7.3.3.2.1"
    tr_walk = walk_master("a10.trunk.walk", "trunk tables", [tr_cfg, tr_stat, tr_mem], "10s")
    trule = rule("a10.trunk.discovery", name="A10 trunk discovery", type=DEPENDENT, master_itemid=tr_walk,
                 preprocessing=base.pp((WALK_JSON, f"{{#TRUNK}}\n{tr_cfg}.1\n0\n{{#TRUNKDESC}}\n{tr_cfg}.3\n0"),
                                       (DISCARD_HB, "1h")))
    tname = "A10 trunk {#TRUNK} ({#TRUNKDESC})"
    ttags = [{"tag": "component", "value": "trunk"}, {"tag": "trunk", "value": "{#TRUNK}"}]

    def trproto(key, label, steps, **kw):
        kw.setdefault("value_type", FLOAT)
        kw.setdefault("trends", TRENDS)
        return proto(trule, f"a10.trunk.{key}[{{#SNMPINDEX}}]", name=f"{tname}: {label}", type=DEPENDENT,
                     master_itemid=tr_walk, tags=ttags, preprocessing=base.pp(*steps), **kw)

    trproto("status", "Status", [wv(c_(tr_cfg, 2)), (DISCARD_HB, "10m")], value_type=UINT, trends="0",
            valuemapid=vm["A10 up/down"])
    trproto("members", "Configured members", [wv(c_(tr_cfg, 5)), (DISCARD_HB, "1h")], value_type=UINT, trends="0")
    slow_rate(trule, tr_walk, tname, ttags, "a10.trunk.in", "Bits received", c_(tr_stat, 3), 8, "bps")
    slow_rate(trule, tr_walk, tname, ttags, "a10.trunk.out", "Bits sent", c_(tr_stat, 5), 8, "bps")
    for c, key, label, units in ((2, "pkts.in", "Packets received", "pps"), (4, "pkts.out", "Packets sent", "pps"),
                                 (8, "errors.in", "Inbound errors", "errors/s"), (9, "errors.out", "Outbound errors", "errors/s"),
                                 (10, "drops.in", "Inbound drops", "pkt/s"), (11, "drops.out", "Outbound drops", "pkt/s")):
        slow_rate(trule, tr_walk, tname, ttags, f"a10.trunk.{key}", label, c_(tr_stat, c), 1, units)
    tk = lambda key: f"/{H}/a10.trunk.{key}[{{#SNMPINDEX}}]"
    tproto(trule, f"{tname}: trunk DOWN", priority=4, expression=f"last({tk('status')})=0",
           tags=[{"tag": "component", "value": "trunk"}])
    mrule = rule("a10.trunk.member.discovery", name="A10 trunk member discovery", type=DEPENDENT,
                 master_itemid=tr_walk,
                 preprocessing=base.pp((WALK_JSON, f"{{#TRUNK}}\n{tr_mem}.1\n0\n{{#MEMBER}}\n{tr_mem}.2\n0"),
                                       (DISCARD_HB, "1h")))
    mname = "A10 trunk {#TRUNK} member e{#MEMBER}"
    for key, c, label in (("oper", 4, "LACP member status (bundled)"), ("admin", 3, "Admin status")):
        proto(mrule, f"a10.trunk.member.{key}[{{#SNMPINDEX}}]", name=f"{mname}: {label}", type=DEPENDENT,
              master_itemid=tr_walk, value_type=UINT, trends="0",
              valuemapid=vm["A10 up/down" if key == "oper" else "A10 enabled"],
              tags=ttags + [{"tag": "interface", "value": "e{#MEMBER}"}],
              preprocessing=base.pp(wv(c_(tr_mem, c)), (DISCARD_HB, "10m")))
    mk = lambda key: f"/{H}/a10.trunk.member.{key}[{{#SNMPINDEX}}]"
    tproto(mrule, f"{mname}: not in the LACP bundle", priority=3,
           expression=f"max({mk('oper')},2m)=0 and last({mk('admin')})=1",
           tags=[{"tag": "component", "value": "trunk"}, {"tag": "interface", "value": "e{#MEMBER}"}],
           comments="The trunk runs on fewer links: this member is enabled but LACP has not bundled it "
                    "(check the cable / optics and the LACP configuration on the switch or router at the other end).")

    # ================================================================ SLB objects
    def slb(prefix, label, table, macros, js=None, delay="10s"):
        w = walk_master(f"a10.slb.{prefix}.walk", f"{label} table", [table], delay)
        steps = [(WALK_JSON, "\n".join(f"{m}\n{table}.{c}\n0" for m, c in macros))]
        if js:
            steps.append((JS, js.strip()))
        steps.append((DISCARD_HB, "1h"))
        rid = rule(f"a10.slb.{prefix}.discovery", name=f"A10 {label} discovery", type=DEPENDENT, master_itemid=w,
                   preprocessing=base.pp(*steps))
        return w, rid

    SRV = f"{A10}.2.4.3.2.2.2.1"
    srv_walk, srule = slb("server", "real server (ISP gateway)", SRV,
                          [("{#NAME}", 2), ("{#ADDR}", 1)])
    sname, stags = "A10 gateway {#NAME} ({#ADDR})", [{"tag": "component", "value": "slb"}, {"tag": "slb_server", "value": "{#NAME}"}]

    def sproto(rid, w, nm, tg, key, label, oid, steps, **kw):
        kw.setdefault("value_type", FLOAT)
        kw.setdefault("trends", TRENDS)
        return proto(rid, f"{key}[{{#SNMPINDEX}}]", name=f"{nm}: {label}", type=DEPENDENT, master_itemid=w,
                     tags=tg, preprocessing=base.pp(wv(oid), *steps), **kw)

    sc = lambda c: f"{SRV}.{c}.{{#SNMPINDEX}}"
    sproto(srule, srv_walk, sname, stags, "a10.slb.server.status", "Health status", sc(10), [(DISCARD_HB, "10m")],
           value_type=UINT, trends="0", valuemapid=vm["A10 server status"])
    sproto(srule, srv_walk, sname, stags, "a10.slb.server.conns", "Current connections", sc(8), [], value_type=UINT)
    slow_rate(srule, srv_walk, sname, stags, "a10.slb.server.cps", "New connections per second", sc(7), 1, "conn/s")
    slow_rate(srule, srv_walk, sname, stags, "a10.slb.server.up", "Upload (users to ISP)", sc(4), 8, "bps")
    slow_rate(srule, srv_walk, sname, stags, "a10.slb.server.down", "Download (ISP to users)", sc(6), 8, "bps")
    sproto(srule, srv_walk, sname, stags, "a10.slb.server.peak", "Peak connections", sc(14), [(DISCARD_HB, "1h")], value_type=UINT)
    tproto(srule, f"{sname}: A10 health check DOWN", priority=4,
           expression=f"last(/{H}/a10.slb.server.status[{{#SNMPINDEX}}])=2 and {{$A10.SLB.SERVER.ALERT:\"{{#NAME}}\"}}=1",
           tags=[{"tag": "component", "value": "slb"}, {"tag": "llb_down", "value": "{#NAME}"}],
           comments="The A10 health check failed for this gateway, so it is out of load balancing. (The IPv4 "
                    "gateways already have their own 'A10 marked gateway DOWN' alert; macro context set to 0 for them.)")

    SG = f"{A10}.2.4.3.3.2.1.1"
    sg_walk, grule = slb("group", "service group", SG, [("{#SG}", 1)])
    gname, gtags = "A10 service group {#SG}", [{"tag": "component", "value": "slb"}, {"tag": "service_group", "value": "{#SG}"}]
    gc = lambda c: f"{SG}.{c}.{{#SNMPINDEX}}"
    sproto(grule, sg_walk, gname, gtags, "a10.slb.sg.status", "Status", gc(9), [(DISCARD_HB, "10m")], value_type=UINT,
           trends="0", valuemapid=vm["A10 group status"])
    sproto(grule, sg_walk, gname, gtags, "a10.slb.sg.conns", "Current connections", gc(7), [], value_type=UINT)
    slow_rate(grule, sg_walk, gname, gtags, "a10.slb.sg.cps", "New connections per second", gc(6), 1, "conn/s")
    slow_rate(grule, sg_walk, gname, gtags, "a10.slb.sg.up", "Upload", gc(3), 8, "bps")
    slow_rate(grule, sg_walk, gname, gtags, "a10.slb.sg.down", "Download", gc(5), 8, "bps")
    sproto(grule, sg_walk, gname, gtags, "a10.slb.sg.peak", "Peak connections", gc(13), [(DISCARD_HB, "1h")], value_type=UINT)
    gk = f"/{H}/a10.slb.sg.status[{{#SNMPINDEX}}]"
    tproto(grule, f"{gname}: STOPPED (no member up)", priority=4, expression=f"last({gk})=4",
           tags=[{"tag": "component", "value": "slb"}])
    tproto(grule, f"{gname}: not all members up", priority=2, expression=f"last({gk})=2 or last({gk})=3",
           tags=[{"tag": "component", "value": "slb"}],
           comments="Traffic of this group is carried by fewer ISP links than configured.")

    MEM = f"{A10}.2.4.3.3.4.1.1"
    mem_walk, merule = slb("member", "service group member", MEM, [("{#SG}", 1), ("{#MEMBER}", 3)])
    mename = "A10 service group {#SG} member {#MEMBER}"
    metags = [{"tag": "component", "value": "slb"}, {"tag": "service_group", "value": "{#SG}"},
              {"tag": "slb_server", "value": "{#MEMBER}"}]
    mc = lambda c: f"{MEM}.{c}.{{#SNMPINDEX}}"
    sproto(merule, mem_walk, mename, metags, "a10.slb.member.status", "Member status", mc(12), [(DISCARD_HB, "10m")],
           value_type=UINT, trends="0", valuemapid=vm["A10 server status"])
    sproto(merule, mem_walk, mename, metags, "a10.slb.member.conns", "Current connections", mc(11), [], value_type=UINT)
    slow_rate(merule, mem_walk, mename, metags, "a10.slb.member.cps", "New connections per second", mc(10), 1, "conn/s")
    slow_rate(merule, mem_walk, mename, metags, "a10.slb.member.up", "Upload", mc(6), 8, "bps")
    slow_rate(merule, mem_walk, mename, metags, "a10.slb.member.down", "Download", mc(8), 8, "bps")
    sproto(merule, mem_walk, mename, metags, "a10.slb.member.rtt", "Response time", mc(16), [(MULT, "0.001")], units="s")

    VS = f"{A10}.2.4.3.4.5.1.1"
    vs_walk, vrule = slb("vs", "virtual server", VS, [("{#VS}", 1)])
    vname, vtags = "A10 virtual server {#VS}", [{"tag": "component", "value": "slb"}, {"tag": "virtual_server", "value": "{#VS}"}]
    vc = lambda c: f"{VS}.{c}.{{#SNMPINDEX}}"
    sproto(vrule, vs_walk, vname, vtags, "a10.slb.vs.status", "Status", vc(9), [(DISCARD_HB, "10m")], value_type=UINT,
           trends="0", valuemapid=vm["A10 virtual server status"])
    sproto(vrule, vs_walk, vname, vtags, "a10.slb.vs.display", "Member status", vc(10), [(DISCARD_HB, "10m")],
           value_type=UINT, trends="0", valuemapid=vm["A10 group status"])
    sproto(vrule, vs_walk, vname, vtags, "a10.slb.vs.conns", "Current connections", vc(8), [], value_type=UINT)
    slow_rate(vrule, vs_walk, vname, vtags, "a10.slb.vs.cps", "New connections per second", vc(7), 1, "conn/s")
    slow_rate(vrule, vs_walk, vname, vtags, "a10.slb.vs.up", "Upload", vc(3), 8, "bps")
    slow_rate(vrule, vs_walk, vname, vtags, "a10.slb.vs.down", "Download", vc(5), 8, "bps")
    sproto(vrule, vs_walk, vname, vtags, "a10.slb.vs.peak", "Peak connections", vc(14), [(DISCARD_HB, "1h")], value_type=UINT)
    tproto(vrule, f"{vname}: virtual server DOWN", priority=4,
           expression=f"last(/{H}/a10.slb.vs.status[{{#SNMPINDEX}}])=2", tags=[{"tag": "component", "value": "slb"}],
           comments="Outbound traffic matching this virtual server is not being load balanced.")

    VP = f"{A10}.2.4.3.4.6.1.1"
    vp_walk, vprule = slb("vport", "virtual port", VP, [("{#VS}", 1), ("{#PTYPE}", 2), ("{#PORT}", 3)], VPORT_LLD_JS)
    vpname = "A10 virtual server {#VS} port {#PROTO}/{#PORT}"
    vptags = [{"tag": "component", "value": "slb"}, {"tag": "virtual_server", "value": "{#VS}"}]
    vpc = lambda c: f"{VP}.{c}.{{#SNMPINDEX}}"
    sproto(vprule, vp_walk, vpname, vptags, "a10.slb.vport.status", "Status", vpc(4), [(DISCARD_HB, "10m")],
           value_type=UINT, trends="0", valuemapid=vm["A10 virtual server status"])
    sproto(vprule, vp_walk, vpname, vptags, "a10.slb.vport.conns", "Current connections", vpc(11), [], value_type=UINT)
    slow_rate(vprule, vp_walk, vpname, vptags, "a10.slb.vport.cps", "New connections per second", vpc(10), 1, "conn/s")
    slow_rate(vprule, vp_walk, vpname, vptags, "a10.slb.vport.up", "Upload", vpc(6), 8, "bps")
    slow_rate(vprule, vp_walk, vpname, vptags, "a10.slb.vport.down", "Download", vpc(8), 8, "bps")
    tproto(vprule, f"{vpname}: virtual port DOWN", priority=3,
           expression=f"last(/{H}/a10.slb.vport.status[{{#SNMPINDEX}}])=2", tags=[{"tag": "component", "value": "slb"}])
    existing = {m["macro"] for m in z.call("usermacro.get", {"hostids": hid, "output": ["macro"]})}
    macros = [("{$A10.SLB.SERVER.ALERT}", "1", "Alert when an A10 real server (gateway) health check is DOWN")]
    macros += [(f"{{$A10.SLB.SERVER.ALERT:\"{gw}\"}}", "0", "Covered by add_llb_stats.py 'A10 marked gateway DOWN'")
               for gw in ("Airtel_GW", "Jio_GW", "Powergrid_GW")]
    macros += [("{$A10.IF.ERRORS.WARN}", "2", "A10 port inbound errors/s warning"),
               ("{$A10.IF.DROPS.WARN}", "100", "A10 port inbound drops/s warning"),
               ("{$A10.DISK.WARN}", "85", "A10 disk used % warning"),
               ("{$A10.NOROUTE.WARN}", "100", "A10 IPv4 no-route drops/s warning")]
    for m, v, desc in macros:
        if m not in existing:
            z.call("usermacro.create", {"hostid": hid, "macro": m, "value": v, "description": desc})

    # ================================================================ scalars: sessions, drops, switching, system
    sess_walk = walk_master("a10.sess.walk", "session and connection counters",
                            [f"{A10}.2.4.3.19.1", f"{A10}.2.4.3.1.2"], "10s")
    net_walk = walk_master("a10.netstat.walk", "axNetStat counters", [NETSTAT], "30s")
    sw_walk = walk_master("a10.switch.walk", "axSwitchStats counters", [SWSTAT], "30s")
    sys_walk = walk_master("a10.sys.walk", "system information",
                           sorted({o.rsplit(".", 1)[0] for o, *_ in SYSTEM_ITEMS}), "1m")

    def scalar(master, oid, key, name, kind, units, component):
        tags = [{"tag": "component", "value": component}]
        kw = dict(name=f"A10: {name}", type=DEPENDENT, master_itemid=master, tags=tags)
        if kind == "rate":
            return item(f"a10.{key}", value_type=FLOAT, units=units, trends=TRENDS, preprocessing=rate_steps(oid), **kw)
        if kind == "gauge":
            return item(f"a10.{key}", value_type=UINT, units=units, trends=TRENDS, preprocessing=base.pp(wv(oid)), **kw)
        if kind == "mb":
            return item(f"a10.{key}", value_type=UINT, units=units, trends=TRENDS,
                        preprocessing=base.pp(wv(oid), (MULT, "1048576")), **kw)
        if kind == "text":
            return item(f"a10.{key}", value_type=CHAR, trends="0", history="90d",
                        preprocessing=status_steps(oid, "1d"), **kw)
        return item(f"a10.{key}", value_type=UINT, trends="0", valuemapid=vm[kind[4:]],
                    preprocessing=status_steps(oid, "1h"), **kw)

    for oid, key, name, kind, units in SESSION_ITEMS:
        scalar(sess_walk, oid, key, name, kind, units, "sessions")
    for sub, key, name in NET_COUNTERS:
        scalar(net_walk, f"{NETSTAT}.{sub}.0", f"net.{key}", f"{name} per second", "rate", "/s", "drops")
    for sub, key, name in SWITCH_COUNTERS:
        scalar(sw_walk, f"{SWSTAT}.{sub}.0", f"switch.{key}", f"{name} per second", "rate", "pkt/s", "switching")
    for oid, key, name, kind, units in SYSTEM_ITEMS:
        scalar(sys_walk, oid, key, name, kind, units, "bgp" if key.startswith("bgp") else "system")
    item("a10.disk.pused", name="A10: Disk used %", type=CALCULATED, delay="1m", value_type=FLOAT, units="%",
         trends=TRENDS, params="100-last(//a10.disk.free)/last(//a10.disk.total)*100",
         tags=[{"tag": "component", "value": "system"}])
    item("a10.sess.total", name="A10: Sessions: total in session table", type=CALCULATED, delay="10s",
         value_type=UINT, trends=TRENDS, tags=[{"tag": "component", "value": "sessions"}],
         params="+".join(f"last(//a10.sess.{k})" for k in ("tcp.est", "tcp.halfopen", "udp", "ip", "other")))
    s = f"/{H}/a10"
    trigger("A10: disk used over {$A10.DISK.WARN}%", priority=2, expression=f"last({s}.disk.pused)>{{$A10.DISK.WARN}}",
            tags=[{"tag": "component", "value": "system"}])
    trigger("A10: software differs between primary and secondary disk", priority=1,
            expression=f"last({s}.sw.primary)<>last({s}.sw.secondary)", tags=[{"tag": "component", "value": "system"}])
    trigger("A10: rebooted into a different software image (startup not primary disk)", priority=2,
            expression=f"last({s}.startup)<>1", tags=[{"tag": "component", "value": "system"}])
    trigger("A10: IPv4 packets dropped for no route (over {$A10.NOROUTE.WARN}/s for 5m)", priority=3,
            expression=f"min({s}.switch.ipv4.noroute.drop,5m)>{{$A10.NOROUTE.WARN}}",
            tags=[{"tag": "component", "value": "drops"}],
            comments="Traffic the A10 cannot route: often a missing default route after a BGP session dropped.")
    trigger("A10: source NAT failures (over 1/s for 5m)", priority=3,
            expression=f"min({s}.net.snat.fail,5m)>1", tags=[{"tag": "component", "value": "drops"}],
            comments="NAT pool exhausted or unusable: new outbound connections fail.")
    trigger("A10: drops for lack of resources (over 1/s for 5m)", priority=3,
            expression=f"min({s}.net.noresource.drop,5m)>1", tags=[{"tag": "component", "value": "drops"}])
    trigger("A10: real-server selection failures (over 1/s for 5m)", priority=3,
            expression=f"min({s}.net.server.selfail,5m)>1", tags=[{"tag": "component", "value": "drops"}],
            comments="New connections found no usable ISP gateway in their service group.")
    trigger("A10: buffer (application packet) drops (over 100/s for 5m)", priority=2,
            expression=f"min({s}.buffer.drop,5m)>100", tags=[{"tag": "component", "value": "drops"}])
    trigger("A10: hardware DDoS protection dropping packets (over 100/s for 5m)", priority=2,
            expression=f"min({s}.switch.anom.any.drop,5m)>100", tags=[{"tag": "component", "value": "drops"}])
    trigger("A10: BGP routes withdrawn - no locally originated networks", priority=4,
            expression=f"max({s}.bgp.local.networks,3m)=0", tags=[{"tag": "component", "value": "bgp"}],
            comments="The A10 is no longer originating our prefixes, so the ISPs stop routing traffic to us.")
    trigger("A10: management port down", priority=2, expression=f"last({s}.mgmt.status)=2",
            tags=[{"tag": "component", "value": "port"}])

    # Names changed after the first run (the management port uses IF-MIB codes, so it stays off the A10 port map)
    for key, name in (("a10.mgmt.status", "A10 management port: Status"), ("a10.mgmt.in", "A10 management port: Bits received"),
                      ("a10.mgmt.out", "A10 management port: Bits sent")):
        z.call("item.update", {"itemid": items[key], "name": name})
    z.call("itemprototype.update", {"itemid": proto(merule, "a10.slb.member.status[{#SNMPINDEX}]"),
                                    "name": f"{mename}: Member status"})
    print("A10 full coverage: " + ", ".join(f"{v} new {k}" for k, v in created.items()))


if __name__ == "__main__":
    main()
