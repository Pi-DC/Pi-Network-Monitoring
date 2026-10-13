#!/usr/bin/env python3
"""Detailed firewall monitoring on the PIDC firewall templates (called by add_firewalls.py; idempotent - re-running
updates every item, rule and trigger in place; --rediscover also re-runs the stock discovery rules on the hosts now):

FortiGate by SNMP - PIDC (all counters summed over every VDOM - the stock IPS / SSL VPN items read VDOM 1 only)
  IPsec site-to-site  every phase-2 selector: status, traffic in/out, phase-1 / peer / VDOM in name and tags;
                      every phase-1 tunnel: state (up / partly up / down), selectors up / total, traffic;
                      totals; alert when a tunnel that was up in the last 24 h has been down 5 min (stays open
                      until it is up again - the stock trigger cleared itself after one poll)
  IPsec dial-up       clients per dial-up gateway, traffic, connected-client list (text, kept 180 days)
  SSL VPN             users / tunnels / web sessions (all VDOMs), connected-user list (user, VDOM, source IP,
                      tunnel IP, since; text, kept 180 days), per-user sessions and traffic (kept 30 days after the
                      last login), firewall-authenticated users
  FortiGuard          days to the soonest contract expiry (alerts at 60 / 15 / 0 days), every contract, every
                      scheduled definition package (version, hours since update; alerts for the key packages),
                      hours since the last update check (alert > 26 h)
  Security            IPS (detected / blocked / critical / high), antivirus, web filter (blocked / examined),
                      VoIP / P2P blocks - per VDOM and totals, per minute
  System              session setup rate, IPv6 sessions, NPU / ephemeral session tables, conserve-mode memory
                      alert, reboot reason, configuration revision / last change, DHCP and IP-pool use,
                      log devices (sent / failed / dropped per minute, alerts), firewall policy audit (policies
                      without traffic since boot, idle > 30 days), HA (members, failover, sync), hardware sensors
SonicWall by SNMP - PIDC
  IPsec               per VPN policy: SAs, peers, traffic; SA list (policy, peer, networks, created)
  System              syslog messages per minute (alert when none for 15 min), content filter state,
                      DPI-SSL peak, security services per zone (text + count of zones without IPS / GAV)
"""
import add_routers as R
import add_vmware_fabric as fab
import setup_isp_links as base

FORTIGATE, SONICWALL = "FortiGate by SNMP - PIDC", "SonicWall by SNMP - PIDC"
FG = "1.3.6.1.4.1.12356.101"
VPN_TUN = FG + ".12.2.2.1"        # fgVpnTunEntry: 2 phase1, 3 phase2, 4 remote gw, 18/19 in/out octets, 20 status, 21 vdom
DIALUP = FG + ".12.4.1.1"         # fgVpn2DialupEntry: 3 gw (hex), 11 dst (hex), 14/15 in/out, 16 phase1, 17 vdom
SSL_STATS, SSL_TUN = FG + ".12.2.3.1", FG + ".12.2.4.1"
VDNAME = FG + ".3.2.1.1.2"
LIC = FG + ".4.6.3"
LOGDEV = FG + ".21.2.1.1"         # fgLogDeviceEntry: 2 enabled, 3 name, 4 sent, 6 cached, 7 failed, 8 dropped
POLICY = FG + ".5.1.2.1.1"        # fgFwPolStatsEntry: 4 last used
SW = "1.3.6.1.4.1.8741.1.3"
SA = SW + ".2.1.1.1"              # sonicSAStatEntry
ZONE = SW + ".7.1.1.1"            # sonicwallFwZoneEntry

TEXT, UINT, FLOAT = R.TEXT, R.UINT, R.FLOAT
JS, WALK_VALUE, DEP, SNMP, CALC = R.JAVASCRIPT, R.SNMP_WALK_VALUE, R.DEPENDENT, R.SNMP, R.CALCULATED
CHANGE, MULT, HEARTBEAT = base.CHANGE_PER_SECOND, base.MULTIPLIER, base.DISCARD_UNCHANGED_HEARTBEAT
DISCARD = 1
HIST, TEXT_HIST = "90d", "180d"
TEXT_TAG = {"tag": "value", "value": "text"}   # see tag_text_items()

# ---------------------------------------------------------------- JavaScript (Duktape, ES5)
# W(value): walk[] text -> {oid: value}; C(t, base): one column {index: value}; N(): number (also Timeticks);
# IP(): hex-string IP -> dotted; D(): 'Tue Oct 13 09:40:05 2026' (device local time, {$FG.TZ.OFFSET.MIN}) -> ms
LIB = r"""
function W(v) {
    var t = {};
    String(v).split('\n').forEach(function (l) {
        var i = l.indexOf(' = '); if (i < 0) return;
        var o = l.slice(0, i).replace(/^\./, ''), x = l.slice(i + 3), m = x.match(/^[A-Za-z0-9-]+: ?([\s\S]*)$/);
        if (m) x = m[1];
        x = x.trim();
        if (x.length > 1 && x.charAt(0) === '"' && x.charAt(x.length - 1) === '"') x = x.slice(1, -1);
        t[o] = x;
    });
    return t;
}
function C(t, b) { var r = {}, p = b + '.'; for (var o in t) if (o.indexOf(p) === 0) r[o.slice(p.length)] = t[o]; return r; }
function N(x) { var m = String(x).match(/^\((\d+)\)/), n = parseFloat(m ? m[1] : x); return isNaN(n) ? 0 : n; }
function IP(x) { var b = String(x).trim().split(/\s+/); return b.length === 4 ? b.map(function (h) { return parseInt(h, 16); }).join('.') : String(x); }
var MON = {Jan: 0, Feb: 1, Mar: 2, Apr: 3, May: 4, Jun: 5, Jul: 6, Aug: 7, Sep: 8, Oct: 9, Nov: 10, Dec: 11};
function D(s) {
    var p = String(s).trim().split(/\s+/); if (p.length < 5 || !(p[1] in MON)) return null;
    var h = p[3].split(':');
    return Date.UTC(+p[4], MON[p[1]], +p[2], +h[0], +h[1], +h[2] || 0) - TZ * 60000;
}
var TZ = parseInt('{$FG.TZ.OFFSET.MIN}', 10) || 0;
function pad(n) { return (n < 10 ? '0' : '') + n; }
function stamp(ms) {   // device local time, 'YYYY-MM-DD HH:MM'
    var d = new Date(ms + TZ * 60000);
    return d.getUTCFullYear() + '-' + pad(d.getUTCMonth() + 1) + '-' + pad(d.getUTCDate()) + ' ' + pad(d.getUTCHours()) + ':' + pad(d.getUTCMinutes());
}
function VD(t) { return C(t, '""" + VDNAME + """'); }
"""


def js(body):
    return (LIB + body).strip()


VPN_JS = js(r"""
var t = W(value), b = '""" + VPN_TUN + r"""', p1 = C(t, b + '.2'), p2 = C(t, b + '.3'), gw = C(t, b + '.4'),
    ib = C(t, b + '.18'), ob = C(t, b + '.19'), st = C(t, b + '.20'), vi = C(t, b + '.21'), vn = VD(t);
var r = {p2: {}, p1: {}, tot: {p1_up: 0, p1_partial: 0, p1_down: 0, p1_total: 0, p2_up: 0, p2_down: 0}};
for (var i in p2) {
    var n1 = p1[i] || p2[i], vd = vn[vi[i]] || vi[i] || '', up = st[i] === '2';
    r.p2[i] = {p1: n1, p2: p2[i], gw: gw[i] || '', vd: vd};
    var o = r.p1[n1] || (r.p1[n1] = {gw: gw[i] || '', vd: vd, up: 0, n: 0, i: 0, o: 0});
    o.n++; if (up) o.up++; o.i += N(ib[i]); o.o += N(ob[i]);
    if (up) r.tot.p2_up++; else r.tot.p2_down++;
}
for (var k in r.p1) {
    var q = r.p1[k]; q.state = q.up === 0 ? 0 : (q.up < q.n ? 1 : 2);
    r.tot.p1_total++; if (q.state === 2) r.tot.p1_up++; else if (q.state === 1) r.tot.p1_partial++; else r.tot.p1_down++;
}
return JSON.stringify(r);
""")
VPN_P2_LLD = r"""
var p2 = JSON.parse(value).p2, out = [];
for (var i in p2) {
    var e = p2[i];
    out.push({'{#SNMPINDEX}': i, '{#VPN.NAME}': e.p2, '{#VPN.P1}': e.p1, '{#VPN.RGW}': e.gw, '{#VPN.VDOM}': e.vd,
              '{#VPN.LABEL}': e.p1 === e.p2 ? e.p1 : e.p1 + ' / ' + e.p2});
}
return JSON.stringify(out);
"""
VPN_P1_LLD = r"""
var p1 = JSON.parse(value).p1, out = [];
for (var n in p1) out.push({'{#VPN.P1}': n, '{#VPN.RGW}': p1[n].gw, '{#VPN.VDOM}': p1[n].vd});
return JSON.stringify(out);
"""

DIALUP_JS = js(r"""
var t = W(value), b = '""" + DIALUP + r"""', gw = C(t, b + '.3'), dst = C(t, b + '.11'), ib = C(t, b + '.14'),
    ob = C(t, b + '.15'), p1 = C(t, b + '.16'), vi = C(t, b + '.17'), vn = VD(t);
var r = {n: 0, p1: {}, list: []};
for (var i in p1) {
    var n = p1[i], vd = vn[vi[i]] || vi[i] || '';
    var o = r.p1[n] || (r.p1[n] = {vd: vd, n: 0, i: 0, o: 0});
    o.n++; o.i += N(ib[i]); o.o += N(ob[i]); r.n++;
    r.list.push(n + ' (VDOM ' + vd + '): peer ' + IP(gw[i]) + ' -> ' + IP(dst[i]));
}
r.list.sort();
return JSON.stringify(r);
""")
DIALUP_LLD = r"""
var p1 = JSON.parse(value).p1, out = [];
for (var n in p1) out.push({'{#DIALUP.P1}': n, '{#DIALUP.VDOM}': p1[n].vd});
return JSON.stringify(out);
"""

SSL_JS = js(r"""
var t = W(value), s = '""" + SSL_STATS + r"""', b = '""" + SSL_TUN + r"""', vn = VD(t);
function sum(col) { var c = C(t, s + '.' + col), x = 0; for (var k in c) x += N(c[k]); return x; }
var st = C(t, s + '.1'), en = 0; for (var k in st) if (st[k] === '2') en = 1;
var auth = C(t, '""" + FG + r""".5.2.3.1.1.2'), au = 0; for (var a in auth) au += N(auth[a]);
var r = {enabled: en, users: sum(2), users_peak: sum(3), web: sum(4), web_peak: sum(5), tunnels: sum(6),
         tunnels_peak: sum(7), auth: au, per: {}, list: []};
var u = C(t, b + '.3'), vi = C(t, b + '.2'), src = C(t, b + '.4'), ip = C(t, b + '.5'), upt = C(t, b + '.6'),
    ib = C(t, b + '.7'), ob = C(t, b + '.8'), now = Date.now();
for (var i in u) {
    var o = r.per[u[i]] || (r.per[u[i]] = {n: 0, i: 0, o: 0});
    o.n++; o.i += N(ib[i]); o.o += N(ob[i]);
    // no login time in the text: it would make every poll a new value; each stored value's timestamp shows it
    r.list.push(u[i] + ' (VDOM ' + (vn[vi[i]] || vi[i]) + ') from ' + src[i] + ', tunnel IP ' + ip[i]);
}
r.list.sort();
return JSON.stringify(r);
""")
SSL_LLD = r"""
var p = JSON.parse(value).per, out = [];
for (var n in p) out.push({'{#SSL.USER}': n});
return JSON.stringify(out);
"""

LIC_JS = js(r"""
var t = W(value), b = '""" + LIC + r"""', now = Date.now();
var cd = C(t, b + '.1.2.1.1'), ce = C(t, b + '.1.2.1.2');
var sd = C(t, b + '.2.2.1.1'), sx = C(t, b + '.2.2.1.2'), sv = C(t, b + '.2.2.1.3'), su = C(t, b + '.2.2.1.4'),
    sm = C(t, b + '.2.2.1.5'), stt = C(t, b + '.2.2.1.6'), sr = C(t, b + '.2.2.1.7');
var r = {contracts: {}, sigs: {}, soon: null, check_h: null, failed: 0};
for (var i in cd) {
    var e = D(ce[i]); if (!cd[i] || e === null) continue;
    var days = Math.round((e - now) / 864000) / 100;
    r.contracts[cd[i]] = {days: days, date: stamp(e)};
    if (!r.soon || days < r.soon.days) r.soon = {days: days, name: cd[i], date: stamp(e)};
}
for (var j in sd) {
    if (!sd[j] || sm[j] !== 'scheduled') continue;
    var upd = D(su[j]), tr = D(stt[j]);
    var age = upd === null ? null : Math.round((now - upd) / 36000) / 100;
    if (r.sigs[sd[j]] && r.sigs[sd[j]].age_h !== null && (age === null || age > r.sigs[sd[j]].age_h)) continue;
    r.sigs[sd[j]] = {ver: sv[j], age_h: age, result: sr[j]};
    if (tr !== null) { var th = Math.round((now - tr) / 36000) / 100; if (r.check_h === null || th < r.check_h) r.check_h = th; }
    if (/fail/i.test(sr[j] || '')) r.failed++;
}
r.av = t['""" + FG + r""".4.2.1.0'] || '';
var ipsx = t['""" + FG + r""".4.2.4.0'] || '';   // extended IPS set; empty (0.00000) on units without it
r.ips = /^0\.00000/.test(ipsx) || !ipsx ? (t['""" + FG + r""".4.2.2.0'] || '') : ipsx;
return JSON.stringify(r);
""")
LIC_LLD = r"""
var c = JSON.parse(value).contracts, out = [];
for (var n in c) out.push({'{#LIC.NAME}': n});
return JSON.stringify(out);
"""
SIG_LLD = r"""
var s = JSON.parse(value).sigs, out = [];
for (var n in s) out.push({'{#SIG.NAME}': n});
return JSON.stringify(out);
"""

SEC_COLS = {   # per-VDOM counters (fg.sec.walk), name -> (label, OIDs summed)
    "ips.detected": ("IPS intrusions detected", [FG + ".9.2.1.1.1"]),
    "ips.blocked": ("IPS intrusions blocked", [FG + ".9.2.1.1.2"]),
    "ips.crit": ("IPS critical-severity detections", [FG + ".9.2.1.1.3"]),
    "ips.high": ("IPS high-severity detections", [FG + ".9.2.1.1.4"]),
    "av.detected": ("viruses detected", [FG + ".8.2.1.1.1"]),
    "av.blocked": ("viruses blocked", [FG + ".8.2.1.1.2"]),
    "wf.blocked": ("web filter: requests blocked (HTTP + HTTPS)", [FG + ".10.1.2.1.1.1", FG + ".10.1.2.1.1.2"]),
    "wf.examined": ("web filter: requests examined (HTTP + HTTPS)", [FG + ".10.1.2.2.1.1", FG + ".10.1.2.2.1.2"]),
    "voip.blocked": ("VoIP calls blocked", [FG + ".10.108.1.1.2"]),
    "p2p.blocked": ("P2P connections blocked", [FG + ".10.109.1.1.1"]),
}
SEC_JS = r"""
var idx = '{#SNMPINDEX}', oids = %s, x = 0, found = false;
String(value).split('\n').forEach(function (l) {
    var i = l.indexOf(' = '); if (i < 0) return;
    var o = l.slice(0, i).replace(/^\./, '');
    for (var k = 0; k < oids.length; k++) if (o === oids[k] + '.' + idx) {
        var m = l.slice(i + 3).match(/(\d+)\s*$/); if (m) { x += parseFloat(m[1]); found = true; }
    }
});
if (!found) throw 'no counter for VDOM ' + idx;
return x;
"""

SYS_JS = js(r"""
var t = W(value);
function col(o) { return C(t, '""" + FG + r"""' + o); }
function sum(c) { var x = 0; for (var k in c) x += N(c[k]); return x; }
function max(c) { var x = 0; for (var k in c) x = Math.max(x, N(c[k])); return x; }
var pn = col('.5.3.2.1.1.1'), pt = col('.5.3.2.1.1.24'), pu = col('.5.3.2.1.1.25'), worst = '', wv = -1;
for (var k in pn) { var v = Math.max(N(pt[k]), N(pu[k])); if (v > wv) { wv = v; worst = pn[k]; } }
return JSON.stringify({npu_sessions: sum(col('.20.2.1.1.3')), npu_table: sum(col('.20.2.1.1.2')),
                       dhcp_max: max(col('.23.2.1.1.2')), pool_max: Math.max(wv, 0), pool_worst: worst});
""")

LOG_LLD = js(r"""
var t = W(value), en = C(t, '""" + LOGDEV + r""".2'), nm = C(t, '""" + LOGDEV + r""".3'), out = [];
for (var i in nm) if (en[i] === '1') out.push({'{#SNMPINDEX}': i, '{#LOGDEV}': nm[i]});
return JSON.stringify(out);
""")
LOG_LOST_JS = r"""
var f = 0, d = 0, p7 = '""" + LOGDEV[0:] + r""".7.{#SNMPINDEX}', p8 = '""" + LOGDEV + r""".8.{#SNMPINDEX}';
String(value).split('\n').forEach(function (l) {
    var i = l.indexOf(' = '); if (i < 0) return;
    var o = l.slice(0, i).replace(/^\./, ''), m = l.slice(i + 3).match(/(\d+)\s*$/);
    if (m && o === p7) f = parseFloat(m[1]); if (m && o === p8) d = parseFloat(m[1]);
});
return f + d;
"""

POL_JS = js(r"""
var t = W(value), lu = C(t, '""" + POLICY + r""".4'), vn = VD(t);
var mult = {second: 1 / 86400, minute: 1 / 1440, hour: 1 / 24, day: 1, month: 30, year: 365};
var r = {total: 0, nohit: 0, idle30: 0, idle90: 0}, by = {};
for (var i in lu) {
    var p = i.split('.'), vd = vn[p[0]] || p[0], id = p[1];
    if (id === '0') continue;   // implicit deny
    r.total++;
    var m = String(lu[i]).match(/\((\d+) (second|minute|hour|day|month|year)/), days = m ? parseFloat(m[1]) * mult[m[2]] : null;
    if (days === null) { r.nohit++; (by[vd] = by[vd] || []).push(+id); }
    else { if (days > 30) r.idle30++; if (days > 90) r.idle90++; }
}
var lines = Object.keys(by).sort().map(function (v) {
    return v + ' (' + by[v].length + '): ' + by[v].sort(function (a, b) { return a - b; }).join(', ');
});
r.list = lines.join('\n');
return JSON.stringify(r);
""")

HA_JS = r"""
var n = 0, prim = '';
String(value).split('\n').forEach(function (l) {
    var i = l.indexOf(' = '); if (i < 0) return;
    var o = l.slice(0, i).replace(/^\./, '');
    if (o.indexOf('1.3.6.1.4.1.12356.101.13.2.1.1.1.') === 0) n++;
    if (o.indexOf('1.3.6.1.4.1.12356.101.13.2.1.1.16.') === 0 && !prim) prim = l.slice(i + 3).replace(/^[A-Za-z0-9-]+: ?/, '').replace(/"/g, '').trim();
});
return JSON.stringify({members: n, primary: prim});
"""

SA_JSON = js(r"""
var t = W(value), b = '""" + SA + r"""', peer = C(t, b + '.2'), sb = C(t, b + '.3'), se = C(t, b + '.4'),
    db = C(t, b + '.5'), de = C(t, b + '.6'), cr = C(t, b + '.7'), enc = C(t, b + '.9'), dec = C(t, b + '.11'),
    nm = C(t, b + '.14');
function rng(a, z) { return a === z ? a : (a === '0.0.0.0' && z === '255.255.255.255' ? 'any' : a + '-' + z); }
var r = {pol: {}, list: []};
for (var i in peer) {
    var n = nm[i] || '(unnamed)', o = r.pol[n] || (r.pol[n] = {sas: 0, peers: {}, enc: 0, dec: 0});
    o.sas++; o.peers[peer[i]] = 1; o.enc += N(enc[i]); o.dec += N(dec[i]);
    r.list.push(n + ': peer ' + peer[i] + ', ' + rng(sb[i], se[i]) + ' <-> ' + rng(db[i], de[i]) + ', created ' + cr[i]);
}
for (var k in r.pol) r.pol[k].peers = Object.keys(r.pol[k].peers).length;
r.list.sort();
return JSON.stringify(r);
""")
SA_LLD = r"""
var p = JSON.parse(value).pol, out = [];
for (var n in p) out.push({'{#SA.NAME}': n});
return JSON.stringify(out);
"""
ZONE_JS = js(r"""
var t = W(value), b = '""" + ZONE + r"""', nm = C(t, b + '.1'), ifs = C(t, b + '.3');
var svc = [['5', 'CFS'], ['8', 'GAV'], ['9', 'Anti-Spyware'], ['10', 'IPS'], ['11', 'App Control'], ['12', 'SSL Control']];
var lines = [], weak = 0;
for (var i in nm) {
    var on = [], off = [];
    svc.forEach(function (s) { (C(t, b + '.' + s[0])[i] === '2' ? on : off).push(s[1]); });
    if (C(t, b + '.10')[i] !== '2' || C(t, b + '.8')[i] !== '2') weak++;
    lines.push(nm[i] + ' [' + (ifs[i] || '-') + ']: on ' + (on.join(', ') || 'none') + '; off ' + (off.join(', ') || 'none'));
}
return JSON.stringify({list: lines.sort().join('\n'), weak: weak, zones: lines.length});
""")


def get_js(path, missing="throw 'not reported';"):
    """JS reading one value from a JSON item, e.g. get_js("tot.p1_up")."""
    expr = "JSON.parse(value)" + "".join(f"[{p}]" if p.startswith("'") else f".{p}" for p in path.split("|"))
    return f"var v; try {{ v = {expr}; }} catch (e) {{ v = undefined; }}\nif (v === undefined || v === null) {{ {missing} }}\nreturn v;"


# ---------------------------------------------------------------- upsert helpers (create, or update in place)
def _clean(kw):
    return {k: v for k, v in kw.items() if v is not None}


def item(z, tid, key, name, **kw):
    kw = _clean(kw)
    kw.setdefault("value_type", UINT)
    kw.setdefault("history", HIST)
    if kw["value_type"] in (TEXT, 1, 2):
        kw["trends"] = "0"
        kw["tags"] = [t for t in kw.get("tags", []) if t != TEXT_TAG] + [TEXT_TAG]
    if kw.get("type") in (DEP,):
        kw.pop("delay", None)
    found = z.call("item.get", {"templateids": tid, "filter": {"key_": key}, "output": ["itemid"]})
    if found:
        z.call("item.update", {"itemid": found[0]["itemid"], "name": name, **kw})
        return found[0]["itemid"]
    return z.call("item.create", {"hostid": tid, "key_": key, "name": name, **kw})["itemids"][0]


def rule(z, tid, key, name, **kw):
    kw = _clean(kw)
    found = z.call("discoveryrule.get", {"templateids": tid, "filter": {"key_": key}, "output": ["itemid"]})
    if found:
        z.call("discoveryrule.update", {"itemid": found[0]["itemid"], "name": name, **kw})
        return found[0]["itemid"]
    return z.call("discoveryrule.create", {"hostid": tid, "key_": key, "name": name, **kw})["itemids"][0]


def proto(z, tid, rid, key, name, **kw):
    kw = _clean(kw)
    kw.setdefault("value_type", UINT)
    kw.setdefault("history", HIST)
    if kw["value_type"] in (TEXT, 1, 2):
        kw["trends"] = "0"
        kw["tags"] = [t for t in kw.get("tags", []) if t != TEXT_TAG] + [TEXT_TAG]
    if kw.get("type") == DEP:
        kw.pop("delay", None)
    found = z.call("itemprototype.get", {"discoveryids": rid, "filter": {"key_": key}, "output": ["itemid"]})
    if found:
        z.call("itemprototype.update", {"itemid": found[0]["itemid"], "name": name, **kw})
        return found[0]["itemid"]
    return z.call("itemprototype.create", {"hostid": tid, "ruleid": rid, "key_": key, "name": name, **kw})["itemids"][0]


def trigger(z, tid, description, expression, priority, comments="", recovery=None, tags=None, old=()):
    """Create / update a template trigger found by description (or by an older description in `old`)."""
    params = {"description": description, "expression": expression, "priority": priority, "comments": comments,
              "recovery_mode": 1 if recovery else 0, "manual_close": 1, "tags": tags or [{"tag": "component", "value": "firewall"}]}
    if recovery:
        params["recovery_expression"] = recovery
    found = z.call("trigger.get", {"templateids": tid, "filter": {"description": [description, *old]},
                                   "output": ["triggerid"], "inherited": False})
    if found:
        z.call("trigger.update", {"triggerid": found[0]["triggerid"], **params})
    else:
        z.call("trigger.create", params)


def trigger_proto(z, rid, description, expression, priority, comments="", recovery=None, tags=None, old=()):
    params = {"description": description, "expression": expression, "priority": priority, "comments": comments,
              "recovery_mode": 1 if recovery else 0, "manual_close": 1, "tags": tags or [{"tag": "component", "value": "firewall"}]}
    if recovery:
        params["recovery_expression"] = recovery
    found = z.call("triggerprototype.get", {"discoveryids": rid, "filter": {"description": [description, *old]},
                                            "output": ["triggerid"]})
    if found:
        z.call("triggerprototype.update", {"triggerid": found[0]["triggerid"], **params})
    else:
        z.call("triggerprototype.create", params)


def macro(z, tid, name, value, description):
    found = z.call("usermacro.get", {"hostids": tid, "filter": {"macro": name}, "output": ["hostmacroid"]})
    if not found:
        z.call("usermacro.create", {"hostid": tid, "macro": name, "value": value, "description": description})


def tags(*pairs):
    return [{"tag": t, "value": v} for t, v in pairs]


WALK_TIMEOUT = "15s"   # FortiGate agents answer walks slowly while other walks run (default SNMP timeout is 3 s)


def walk_item(z, tid, key, name, oids, delay):
    return item(z, tid, key, name, type=SNMP, snmp_oid=R.walk(*oids), value_type=TEXT, history="0", delay=delay,
                timeout=WALK_TIMEOUT, tags=tags(("component", "raw")))


def walk_timeouts(z, tid):
    """Every walk[] item on the template (stock ones too) gets WALK_TIMEOUT."""
    for i in z.call("item.get", {"templateids": tid, "filter": {"type": SNMP}, "output": ["itemid", "snmp_oid", "timeout"]}):
        if i["snmp_oid"].startswith("walk[") and i["timeout"] != WALK_TIMEOUT:
            z.call("item.update", {"itemid": i["itemid"], "timeout": WALK_TIMEOUT})
    for r in z.call("discoveryrule.get", {"templateids": tid, "filter": {"type": SNMP}, "output": ["itemid", "snmp_oid", "timeout"]}):
        if r["snmp_oid"].startswith("walk[") and r["timeout"] != WALK_TIMEOUT:
            z.call("discoveryrule.update", {"itemid": r["itemid"], "timeout": WALK_TIMEOUT})


def json_item(z, tid, key, name, master, script):
    return item(z, tid, key, name, type=DEP, master_itemid=master, value_type=TEXT, history="0",
                preprocessing=R.pp((JS, script)), tags=tags(("component", "raw")))


def dep(z, tid, key, name, master, path, comp, units="", value_type=UINT, rate=None, text=False, extra=(),
        description="", heartbeat=None, history=None, valuemapid=None):
    """Dependent item reading `path` from a JSON item; rate='s' -> per second x8 (bps), 'm' -> per minute."""
    steps = [(JS, get_js(path))]
    if rate == "bps":
        steps += [(CHANGE, "", DISCARD), (MULT, "8")]
        units, value_type = "bps", FLOAT
    elif rate == "m":
        steps += [(CHANGE, "", DISCARD), (MULT, "60")]
        value_type = FLOAT
    if heartbeat:
        steps.append((HEARTBEAT, heartbeat))
    steps += list(extra)
    return item(z, tid, key, name, type=DEP, master_itemid=master, value_type=TEXT if text else value_type,
                units=units, preprocessing=R.pp(*steps), tags=tags(("component", comp)), description=description,
                valuemapid=valuemapid,
                history=history or (TEXT_HIST if text else HIST))


# ---------------------------------------------------------------- FortiGate
def fortigate(z):
    tid = fab.template_id(z, FORTIGATE)
    t = f"/{FORTIGATE}/"
    macro(z, tid, "{$FG.TZ.OFFSET.MIN}", "330", "FortiGate local time zone offset from UTC in minutes (IST = 330); "
                                                "FortiGuard dates are reported in device local time")
    vpn_vm = R.valuemap(z, tid, "IPsec phase-1 state", [(0, "down"), (1, "partly up"), (2, "up")])
    state_vm = R.valuemap(z, tid, "Enabled state", [(0, "disabled"), (1, "enabled")])

    # ---- IPsec site-to-site: the stock walk now carries phase-1 name, peer, traffic and VDOM too
    master = z.call("item.get", {"templateids": tid, "filter": {"key_": "vpn.tunnel.walk"}, "output": ["itemid"]})[0]["itemid"]
    z.call("item.update", {"itemid": master, "snmp_oid": R.walk(*(f"{VPN_TUN}.{c}" for c in (2, 3, 4, 18, 19, 20, 21)), VDNAME),
                           "name": "SNMP walk VPN tunnels (phase-1, phase-2, peer, traffic, status, VDOM)"})
    vpn = json_item(z, tid, "fg.vpn.json", "IPsec: tunnel summary (JSON)", master, VPN_JS)
    p2rule = z.call("discoveryrule.get", {"templateids": tid, "filter": {"key_": "vpn.tunnel.discovery"},
                                          "output": ["itemid"]})[0]["itemid"]
    z.call("discoveryrule.update", {"itemid": p2rule, "master_itemid": vpn, "name": "IPsec phase-2 (selector) discovery",
                                    "lifetime": "7d",
                                    "preprocessing": R.pp((JS, VPN_P2_LLD.strip()), (HEARTBEAT, "1h"))})
    p2_tags = tags(("component", "vpn"), ("vpn", "{#VPN.P1}"), ("peer", "{#VPN.RGW}"), ("vdom", "{#VPN.VDOM}"))
    status = "vpn.tunnel.status[fgVpnTunEntStatus.{#SNMPINDEX}]"
    proto(z, tid, p2rule, status, "IPsec {#VPN.LABEL}: tunnel status", type=DEP, master_itemid=master,
          valuemapid=z.call("valuemap.get", {"hostids": tid, "filter": {"name": "VPN status"}, "output": ["valuemapid"]})[0]["valuemapid"],
          preprocessing=R.pp((WALK_VALUE, f"{VPN_TUN}.20.{{#SNMPINDEX}}\n0")), tags=p2_tags,
          description="Phase-2 selector status (1 down, 2 up). Peer {#VPN.RGW}, VDOM {#VPN.VDOM}.")
    for col, d in ((18, "in"), (19, "out")):
        proto(z, tid, p2rule, f"vpn.tunnel.{d}[{{#SNMPINDEX}}]", f"IPsec {{#VPN.LABEL}}: traffic {d}", type=DEP,
              master_itemid=master, value_type=FLOAT, units="bps", tags=p2_tags,
              preprocessing=R.pp((WALK_VALUE, f"{VPN_TUN}.{col}.{{#SNMPINDEX}}\n0"), (CHANGE, "", DISCARD), (MULT, "8")))
    s = f"/{FORTIGATE}/{status}"
    trigger_proto(z, p2rule, "IPsec {#VPN.LABEL} (VDOM {#VPN.VDOM}): tunnel down, peer {#VPN.RGW}",
                  f"max({s},{{$FG.VPN.DOWN.TIME}})=1 and max({s},1d)=2", 3, recovery=f"last({s})=2",
                  old=("FortiGate: VPN {#VPN.NAME}: Tunnel down",), tags=tags(("component", "vpn"), ("vpn", "{#VPN.P1}")),
                  comments="The phase-2 selector was up within the last 24 h and has now been down for {$FG.VPN.DOWN.TIME}. "
                           "Stays open until the tunnel is up again. Selectors that have not been up for a day do not alert.")
    macro(z, tid, "{$FG.VPN.DOWN.TIME}", "5m", "How long an IPsec selector must be down before it alerts")

    p1rule = rule(z, tid, "fg.vpn.p1.discovery", "IPsec phase-1 (tunnel) discovery", type=DEP, master_itemid=vpn,
                  lifetime="7d", preprocessing=R.pp((JS, VPN_P1_LLD.strip()), (HEARTBEAT, "1h")))
    p1_tags = tags(("component", "vpn"), ("vpn", "{#VPN.P1}"), ("peer", "{#VPN.RGW}"), ("vdom", "{#VPN.VDOM}"))
    p1 = "p1|'{#VPN.P1}'"
    for key, name, path, kw in (
            ("state", "state", "state", {"valuemapid": vpn_vm}),
            ("up", "phase-2 selectors up", "up", {}),
            ("total", "phase-2 selectors", "n", {"heartbeat": "1h"}),
            ("in", "traffic in", "i", {"rate": "bps"}),
            ("out", "traffic out", "o", {"rate": "bps"})):
        steps = [(JS, "var v = JSON.parse(value).p1['{#VPN.P1}'];\nif (!v) throw 'tunnel not reported';\nreturn v.%s;" % path)]
        vt, units = UINT, ""
        if kw.get("rate") == "bps":
            steps += [(CHANGE, "", DISCARD), (MULT, "8")]
            vt, units = FLOAT, "bps"
        if kw.get("heartbeat"):
            steps.append((HEARTBEAT, kw["heartbeat"]))
        proto(z, tid, p1rule, f"fg.vpn.p1.{key}[{{#VPN.P1}}]", f"IPsec tunnel {{#VPN.P1}}: {name}", type=DEP,
              master_itemid=vpn, value_type=vt, units=units, valuemapid=kw.get("valuemapid"), tags=p1_tags,
              preprocessing=R.pp(*steps),
              description="Phase-1 tunnel {#VPN.P1}, peer {#VPN.RGW}, VDOM {#VPN.VDOM}. State: 2 all selectors up, "
                          "1 some up, 0 all down." if key == "state" else "")
    for key, name, path in (("p1.up", "IPsec: tunnels up", "tot|p1_up"),
                            ("p1.partial", "IPsec: tunnels partly up", "tot|p1_partial"),
                            ("p1.down", "IPsec: tunnels down", "tot|p1_down"),
                            ("p1.total", "IPsec: tunnels configured", "tot|p1_total"),
                            ("p2.up", "IPsec: phase-2 selectors up", "tot|p2_up"),
                            ("p2.down", "IPsec: phase-2 selectors down", "tot|p2_down")):
        dep(z, tid, f"fg.vpn.{key}", name, vpn, path, "vpn")
    for d in ("in", "out"):
        item(z, tid, f"fg.vpn.{d}", f"IPsec: traffic {d} (all tunnels)", type=CALC, delay="1m", value_type=FLOAT,
             units="bps", params=f"sum(last_foreach(//fg.vpn.p1.{d}[*]))", tags=tags(("component", "vpn")))

    # ---- IPsec dial-up
    dw = walk_item(z, tid, "fg.vpn.dialup.walk", "SNMP walk IPsec dial-up tunnels",
                   [f"{DIALUP}.{c}" for c in (3, 11, 14, 15, 16, 17)] + [VDNAME], "1m")
    dj = json_item(z, tid, "fg.vpn.dialup.json", "IPsec dial-up: summary (JSON)", dw, DIALUP_JS)
    dep(z, tid, "fg.vpn.dialup.count", "IPsec dial-up: clients connected", dj, "n", "vpn")
    item(z, tid, "fg.vpn.dialup.list", "IPsec dial-up: connected clients", type=DEP, master_itemid=dj, value_type=TEXT,
         history=TEXT_HIST, tags=tags(("component", "vpn")),
         preprocessing=R.pp((JS, "return JSON.parse(value).list.join('\\n') || '(none)';"), (HEARTBEAT, "1h")),
         description="Dial-up gateway (VDOM): peer address -> address behind the tunnel. Stored on every change "
                     "(and hourly), so the history shows who was connected when.")
    drule = rule(z, tid, "fg.vpn.dialup.discovery", "IPsec dial-up gateway discovery", type=DEP, master_itemid=dj,
                 lifetime="30d", preprocessing=R.pp((JS, DIALUP_LLD.strip()), (HEARTBEAT, "1h")))
    d_tags = tags(("component", "vpn"), ("vpn", "{#DIALUP.P1}"), ("vdom", "{#DIALUP.VDOM}"))
    for key, name, path, rate in (("n", "clients connected", "n", None), ("in", "traffic in", "i", "bps"),
                                  ("out", "traffic out", "o", "bps")):
        steps = [(JS, "var v = JSON.parse(value).p1['{#DIALUP.P1}'];\nreturn v ? v.%s : 0;" % path)]
        if rate:
            steps += [(CHANGE, "", DISCARD), (MULT, "8")]
        proto(z, tid, drule, f"fg.vpn.dialup.{key}[{{#DIALUP.P1}}]", f"IPsec dial-up {{#DIALUP.P1}}: {name}", type=DEP,
              master_itemid=dj, value_type=FLOAT if rate else UINT, units="bps" if rate else "", tags=d_tags,
              preprocessing=R.pp(*steps))

    # ---- SSL VPN
    sw_ = walk_item(z, tid, "fg.ssl.walk", "SNMP walk SSL VPN (stats, tunnels) and authenticated users",
                    [SSL_STATS, SSL_TUN, VDNAME, f"{FG}.5.2.3.1.1.2"], "1m")
    sj = json_item(z, tid, "fg.ssl.json", "SSL VPN: summary (JSON)", sw_, SSL_JS)
    for key, name, path in (("users", "SSL VPN: users logged in (all VDOMs)", "users"),
                            ("tunnels", "SSL VPN: tunnel-mode sessions (all VDOMs)", "tunnels"),
                            ("web", "SSL VPN: web-mode sessions (all VDOMs)", "web"),
                            ("users.peak", "SSL VPN: peak users since boot", "users_peak"),
                            ("tunnels.peak", "SSL VPN: peak tunnels since boot", "tunnels_peak")):
        dep(z, tid, f"fg.ssl.{key}", name, sj, path, "sslvpn")
    dep(z, tid, "fg.ssl.enabled", "SSL VPN: enabled (any VDOM)", sj, "enabled", "sslvpn", heartbeat="1h",
        valuemapid=state_vm)
    dep(z, tid, "fg.auth.users", "Firewall: authenticated users (all VDOMs)", sj, "auth", "firewall",
        description="fgFwAuthIpv4UserNumber summed over VDOMs: users logged in through firewall authentication "
                    "(SSL VPN, FSSO, captive portal ...).")
    item(z, tid, "fg.ssl.list", "SSL VPN: connected users", type=DEP, master_itemid=sj, value_type=TEXT,
         history=TEXT_HIST, tags=tags(("component", "sslvpn")),
         preprocessing=R.pp((JS, "return JSON.parse(value).list.join('\\n') || '(none)';"), (HEARTBEAT, "1h")),
         description="User (VDOM) from source IP, tunnel IP. Stored on every change (and hourly): the history is "
                     "a login record (a user appears in the first value after the login).")
    urule = rule(z, tid, "fg.ssl.user.discovery", "SSL VPN user discovery", type=DEP, master_itemid=sj,
                 lifetime="30d", preprocessing=R.pp((JS, SSL_LLD.strip()), (HEARTBEAT, "1h")))
    u_tags = tags(("component", "sslvpn"), ("user", "{#SSL.USER}"))
    for key, name, path, rate in (("sessions", "sessions", "n", None), ("in", "traffic in", "i", "bps"),
                                  ("out", "traffic out", "o", "bps")):
        steps = [(JS, "var v = JSON.parse(value).per['{#SSL.USER}'];\nreturn v ? v.%s : 0;" % path)]
        if rate:
            steps += [(CHANGE, "", DISCARD), (MULT, "8")]
        proto(z, tid, urule, f"fg.ssl.user.{key}[{{#SSL.USER}}]", f"SSL VPN user {{#SSL.USER}}: {name}", type=DEP,
              master_itemid=sj, value_type=FLOAT if rate else UINT, units="bps" if rate else "", tags=u_tags,
              preprocessing=R.pp(*steps), history="90d")
    fw_ssl = z.call("item.get", {"templateids": tid, "filter": {"key_": "fw.vpn.users"}, "output": ["itemid"]})
    if fw_ssl:   # the dashboard tile: all VDOMs, not VDOM 1 only
        z.call("item.update", {"itemid": fw_ssl[0]["itemid"], "params": "last(//fg.ssl.users)"})

    # ---- FortiGuard contracts and definitions
    lw = walk_item(z, tid, "fg.lic.walk", "SNMP walk FortiGuard contracts and definitions",
                   [LIC, f"{FG}.4.2"], "1h")
    lj = json_item(z, tid, "fg.lic.json", "FortiGuard: summary (JSON)", lw, LIC_JS)
    dep(z, tid, "fg.lic.expiry.days", "FortiGuard: days until the first contract expires", lj, "soon|days", "fortiguard",
        value_type=FLOAT, units="d", history="365d")
    item(z, tid, "fg.lic.expiry.name", "FortiGuard: contract expiring first", type=DEP, master_itemid=lj,
         value_type=TEXT, history=TEXT_HIST, tags=tags(("component", "fortiguard")),
         preprocessing=R.pp((JS, "var s = JSON.parse(value).soon; if (!s) throw 'no contracts';\nreturn s.name + ' - expires ' + s.date;"),
                            (HEARTBEAT, "1d")))
    dep(z, tid, "fg.fortiguard.check.age", "FortiGuard: hours since the last update check", lj, "check_h", "fortiguard",
        value_type=FLOAT, units="h")
    dep(z, tid, "fg.fortiguard.failed", "FortiGuard: definition packages whose last update failed", lj, "failed", "fortiguard")
    dep(z, tid, "fg.fortiguard.av", "FortiGuard: antivirus definitions version", lj, "av", "fortiguard", text=True,
        heartbeat="1d")
    dep(z, tid, "fg.fortiguard.ips", "FortiGuard: IPS definitions version", lj, "ips", "fortiguard", text=True,
        heartbeat="1d")
    crule = rule(z, tid, "fg.lic.discovery", "FortiGuard contract discovery", type=DEP, master_itemid=lj,
                 lifetime="30d", preprocessing=R.pp((JS, LIC_LLD.strip()), (HEARTBEAT, "1d")))
    proto(z, tid, crule, "fg.lic.days[{#LIC.NAME}]", "FortiGuard contract {#LIC.NAME}: days until expiry", type=DEP,
          master_itemid=lj, value_type=FLOAT, units="d", history="365d",
          tags=tags(("component", "fortiguard"), ("contract", "{#LIC.NAME}")),
          preprocessing=R.pp((JS, "var v = JSON.parse(value).contracts['{#LIC.NAME}'];\nif (!v) throw 'not reported';\nreturn v.days;")))
    srule = rule(z, tid, "fg.sig.discovery", "FortiGuard definition package discovery", type=DEP, master_itemid=lj,
                 lifetime="30d", preprocessing=R.pp((JS, SIG_LLD.strip()), (HEARTBEAT, "1d")))
    sig_tags = tags(("component", "fortiguard"), ("package", "{#SIG.NAME}"))
    proto(z, tid, srule, "fg.sig.age[{#SIG.NAME}]", "FortiGuard {#SIG.NAME}: hours since last update", type=DEP,
          master_itemid=lj, value_type=FLOAT, units="h", tags=sig_tags,
          preprocessing=R.pp((JS, "var v = JSON.parse(value).sigs['{#SIG.NAME}'];\nif (!v || v.age_h === null) throw 'not reported';\nreturn v.age_h;")))
    proto(z, tid, srule, "fg.sig.version[{#SIG.NAME}]", "FortiGuard {#SIG.NAME}: version", type=DEP,
          master_itemid=lj, value_type=TEXT, history=TEXT_HIST, tags=sig_tags,
          preprocessing=R.pp((JS, "var v = JSON.parse(value).sigs['{#SIG.NAME}'];\nif (!v) throw 'not reported';\nreturn v.ver + ' (' + v.result + ')';"),
                             (HEARTBEAT, "1d")))
    age = f"/{FORTIGATE}/fg.sig.age[{{#SIG.NAME}}]"
    trigger_proto(z, srule, "FortiGuard {#SIG.NAME} not updated for over {$FG.SIG.AGE.MAX:\"{#SIG.NAME}\"} h",
                  f"{{$FG.SIG.AGE.MAX:\"{{#SIG.NAME}}\"}}>0 and last({age})>{{$FG.SIG.AGE.MAX:\"{{#SIG.NAME}}\"}}", 3,
                  tags=tags(("component", "fortiguard")),
                  comments="Only packages with a {$FG.SIG.AGE.MAX:\"<name>\"} macro above 0 alert (antivirus, IPS, "
                           "botnet, malicious URL, application definitions).")
    macro(z, tid, "{$FG.SIG.AGE.MAX}", "0", "Hours without a FortiGuard package update before alerting (0 = no alert; set per package with context)")
    for pkg, hours in (("Virus Definitions", "72"), ("Attack Extended Definitions", "168"),
                       ("IPS Malicious URL Database", "168"), ("Botnet Domain Database", "168"),
                       ("Application Definitions", "336")):
        macro(z, tid, f"{{$FG.SIG.AGE.MAX:\"{pkg}\"}}", hours, f"Alert when {pkg} is older than this (hours)")
    macro(z, tid, "{$FG.LIC.EXPIRY.WARN}", "60", "FortiGuard contract expiry warning (days)")
    macro(z, tid, "{$FG.LIC.EXPIRY.CRIT}", "15", "FortiGuard contract expiry alert (days)")
    macro(z, tid, "{$FG.UPDATE.CHECK.MAX}", "26", "Hours without a FortiGuard update check before alerting")
    exp, nm = f"last({t}fg.lic.expiry.days)", f"length(last({t}fg.lic.expiry.name))>0"
    trigger(z, tid, "FortiGuard contract expires in less than {$FG.LIC.EXPIRY.WARN} days ({ITEM.VALUE1})",
            f"{nm} and {exp}<{{$FG.LIC.EXPIRY.WARN}} and {exp}>={{$FG.LIC.EXPIRY.CRIT}}", 2,
            tags=tags(("component", "fortiguard")),
            old=("FortiGuard contract expires in less than {$FG.LIC.EXPIRY.WARN} days ({ITEM.VALUE2})",))
    trigger(z, tid, "FortiGuard contract expires in less than {$FG.LIC.EXPIRY.CRIT} days ({ITEM.VALUE1})",
            f"{nm} and {exp}<{{$FG.LIC.EXPIRY.CRIT}} and {exp}>0", 3, tags=tags(("component", "fortiguard")),
            old=("FortiGuard contract expires in less than {$FG.LIC.EXPIRY.CRIT} days ({ITEM.VALUE2})",))
    trigger(z, tid, "FortiGuard contract expired ({ITEM.VALUE1})", f"{nm} and {exp}<=0", 4,
            tags=tags(("component", "fortiguard")), old=("FortiGuard contract expired ({ITEM.VALUE2})",))
    trigger(z, tid, "FortiGuard: no update check for over {$FG.UPDATE.CHECK.MAX} h",
            f"last({t}fg.fortiguard.check.age)>{{$FG.UPDATE.CHECK.MAX}}", 3, tags=tags(("component", "fortiguard")),
            comments="The FortiGate has not contacted FortiGuard: check DNS / internet access / FortiGuard settings.")

    # ---- security counters per VDOM (stock VDOM discovery) and totals; the stock IPS items read VDOM 1 only
    secw = walk_item(z, tid, "fg.sec.walk", "SNMP walk IPS / antivirus / web filter / application counters",
                     [o for _, oids in SEC_COLS.values() for o in oids], "1m")
    vrule = z.call("discoveryrule.get", {"templateids": tid, "filter": {"key_": "vdom.discovery"},
                                         "output": ["itemid"]})[0]["itemid"]
    for key, (label, oids) in SEC_COLS.items():
        proto(z, tid, vrule, f"vdom.{key}[{{#SNMPINDEX}}]", f"VDOM {{#VDOM.NAME}}: {label} per minute", type=DEP,
              master_itemid=secw, value_type=FLOAT, units="", tags=tags(("component", "security"), ("vdom", "{#VDOM.NAME}")),
              preprocessing=R.pp((JS, (SEC_JS % repr(oids).replace("'", '"')).strip()), (CHANGE, "", DISCARD), (MULT, "60")))
        item(z, tid, f"fg.{key}", f"Security: {label} per minute (all VDOMs)", type=CALC, delay="1m",
             value_type=FLOAT, params=f"sum(last_foreach(//vdom.{key}[*]))", tags=tags(("component", "security")))
    proto(z, tid, vrule, "vdom.ssl.users[{#SNMPINDEX}]", "VDOM {#VDOM.NAME}: SSL VPN users", type=DEP,
          master_itemid=sw_, tags=tags(("component", "sslvpn"), ("vdom", "{#VDOM.NAME}")),
          preprocessing=R.pp((WALK_VALUE, f"{SSL_STATS}.2.{{#SNMPINDEX}}\n0")))
    for k in z.call("item.get", {"templateids": tid, "search": {"key_": "ips."}, "output": ["itemid", "key_", "status"]}):
        if k["key_"].startswith(("ips.detected", "ips.blocked")) and k["status"] == "0":
            z.call("item.update", {"itemid": k["itemid"], "status": 1})   # VDOM 1 only; replaced by fg.ips.*

    # ---- system
    for key, name, oid, kw in (
            ("fg.sessions.rate", "Firewall: new sessions per second (1-min average)", "4.1.11.0", {}),
            ("fg.sessions6", "Firewall: IPv6 active sessions", "4.1.15.0", {}),
            ("fg.mem.low", "Low memory (kernel) utilization", "4.1.9.0", {"units": "%"}),
            ("fg.eph.count", "Firewall: ephemeral sessions", "4.6.2.1.0", {}),
            ("fg.eph.limit", "Firewall: ephemeral session limit", "4.6.2.2.0", {"delay": "1h"}),
            ("fg.sessions.clash", "Firewall: session clashes (since boot)", "4.6.2.3.0", {"delay": "5m"}),
            ("fg.config.serial", "Configuration revision", "22.1.1.0", {"delay": "5m"})):
        item(z, tid, key, name, type=SNMP, snmp_oid=f"get[{FG}.{oid}]", delay=kw.get("delay", "1m"),
             units=kw.get("units", ""), tags=tags(("component", "system")))
    item(z, tid, "fg.config.changed", "Configuration last changed (uptime at the change)", type=SNMP,
         snmp_oid=f"get[{FG}.22.1.3.0]", delay="5m", units="uptime", preprocessing=R.pp((MULT, "0.01")),
         tags=tags(("component", "system")))
    item(z, tid, "fg.config.age", "Time since the last configuration change", type=CALC, delay="5m", units="uptime",
         params="last(//system.uptime[fgSysUpTime.0])-last(//fg.config.changed)", tags=tags(("component", "system")))
    item(z, tid, "fg.reboot.reason", "Last reboot reason", type=SNMP, snmp_oid=f"get[{FG}.4.1.23.0]", delay="1h",
         value_type=TEXT, history=TEXT_HIST, preprocessing=R.pp((HEARTBEAT, "1d")), tags=tags(("component", "system")))
    item(z, tid, "fg.eph.pused", "Firewall: ephemeral session table use", type=CALC, delay="1m", value_type=FLOAT,
         units="%", params="100*last(//fg.eph.count)/last(//fg.eph.limit)", tags=tags(("component", "firewall")))
    sysw = walk_item(z, tid, "fg.sys.walk", "SNMP walk NPU sessions and DHCP use",
                     [f"{FG}.20.2.1.1.2", f"{FG}.20.2.1.1.3", f"{FG}.23.2.1.1.2"], "5m")
    sj2 = json_item(z, tid, "fg.sys.json", "System: summary (JSON)", sysw, SYS_JS)
    # IP pools in their own walk: the FortiGate 120G (7.6) returns broken indexes there and the walk times out
    poolw = walk_item(z, tid, "fg.ippool.walk", "SNMP walk IP-pool use",
                      [f"{FG}.5.3.2.1.1.1", f"{FG}.5.3.2.1.1.24", f"{FG}.5.3.2.1.1.25"], "15m")
    pj2 = json_item(z, tid, "fg.ippool.json", "IP pools: summary (JSON)", poolw, SYS_JS)
    dep(z, tid, "fg.npu.sessions", "Firewall: NPU offloaded sessions", sj2, "npu_sessions", "firewall")
    dep(z, tid, "fg.npu.table", "Firewall: NPU session table size", sj2, "npu_table", "firewall", heartbeat="1d")
    item(z, tid, "fg.npu.pused", "Firewall: NPU session table use", type=CALC, delay="5m", value_type=FLOAT, units="%",
         params="100*last(//fg.npu.sessions)/max(last(//fg.npu.table),1)", tags=tags(("component", "firewall")))
    dep(z, tid, "fg.dhcp.max", "DHCP: highest lease-pool use", sj2, "dhcp_max", "system", units="%")
    dep(z, tid, "fg.ippool.max", "Firewall: highest IP-pool port use", pj2, "pool_max", "firewall", units="%")
    dep(z, tid, "fg.ippool.worst", "Firewall: IP pool with the highest use", pj2, "pool_worst", "firewall", text=True,
        heartbeat="1d")
    macro(z, tid, "{$FG.CONSERVE.MEM}", "88", "Memory % at which FortiOS enters conserve mode (red threshold)")
    mem = f"{t}vm.memory.util[memoryUsedPercentage.0]"
    trigger(z, tid, "Memory at conserve-mode level (over {$FG.CONSERVE.MEM}% for 5m)",
            f"min({mem},5m)>={{$FG.CONSERVE.MEM}}", 4, tags=tags(("component", "memory")),
            comments="In conserve mode FortiOS stops proxy-based inspection and may drop new sessions.")
    trigger(z, tid, "Ephemeral session table over 80% full", f"min({t}fg.eph.pused,5m)>80", 3)
    trigger(z, tid, "NPU session table over 80% full", f"min({t}fg.npu.pused,10m)>80", 3)
    trigger(z, tid, "DHCP lease pool over 90% used", f"min({t}fg.dhcp.max,15m)>90", 2, tags=tags(("component", "system")))
    trigger(z, tid, "IP pool over 90% used ({ITEM.VALUE1})", f"length(last({t}fg.ippool.worst))>=0 and min({t}fg.ippool.max,15m)>90", 3)
    trigger(z, tid, "Configuration changed (revision {ITEM.VALUE1})", f"change({t}fg.config.serial)<>0", 1,
            tags=tags(("component", "system")), comments="Information only: shows who/what to check in the FortiGate log.")

    # ---- log devices
    logw = walk_item(z, tid, "fg.log.walk", "SNMP walk log devices", [LOGDEV], "1m")
    lrule = rule(z, tid, "fg.log.discovery", "Log device discovery (enabled ones)", type=DEP, master_itemid=logw,
                 lifetime="7d", preprocessing=R.pp((JS, LOG_LLD), (HEARTBEAT, "1h")))
    l_tags = tags(("component", "logging"), ("logdev", "{#LOGDEV}"))
    for key, name, col, kw in (("sent", "logs sent per minute", 4, {"rate": True}),
                               ("cached", "logs queued", 6, {}),
                               ("failed", "logs failed per minute", 7, {"rate": True}),
                               ("dropped", "logs dropped per minute", 8, {"rate": True})):
        steps = [(WALK_VALUE, f"{LOGDEV}.{col}.{{#SNMPINDEX}}\n0")]
        if kw.get("rate"):
            steps += [(CHANGE, "", DISCARD), (MULT, "60")]
        proto(z, tid, lrule, f"fg.log.{key}[{{#LOGDEV}}]", f"Log device {{#LOGDEV}}: {name}", type=DEP,
              master_itemid=logw, value_type=FLOAT if kw.get("rate") else UINT, tags=l_tags, preprocessing=R.pp(*steps))
    proto(z, tid, lrule, "fg.log.lost[{#LOGDEV}]", "Log device {#LOGDEV}: logs lost (failed + dropped) per minute",
          type=DEP, master_itemid=logw, value_type=FLOAT, tags=l_tags,
          preprocessing=R.pp((JS, LOG_LOST_JS.strip()), (CHANGE, "", DISCARD), (MULT, "60")))
    lost, sent = f"/{FORTIGATE}/fg.log.lost[{{#LOGDEV}}]", f"/{FORTIGATE}/fg.log.sent[{{#LOGDEV}}]"
    trigger_proto(z, lrule, "Logs to {#LOGDEV} are being lost ({ITEM.LASTVALUE1}/min)",
                  f"min({lost},10m)>{{$FG.LOG.LOSS.MAX:\"{{#LOGDEV}}\"}}", 3, tags=tags(("component", "logging")),
                  comments="Log messages to this log device failed or were dropped for 10 minutes (audit trail gap).")
    trigger_proto(z, lrule, "No logs sent to {#LOGDEV} for 15 minutes",
                  f"{{$FG.LOG.IDLE.ALERT:\"{{#LOGDEV}}\"}}=1 and max({sent},15m)=0", 3, tags=tags(("component", "logging")))
    macro(z, tid, "{$FG.LOG.LOSS.MAX}", "0", "Lost (failed + dropped) logs per minute tolerated per log device")
    macro(z, tid, "{$FG.LOG.IDLE.ALERT}", "1", "1 = alert when a log device receives no logs for 15 min")
    # 'fds' = FortiGuard cloud log upload: on these units it drops every log (not subscribed), not an outage
    macro(z, tid, "{$FG.LOG.LOSS.MAX:\"fds\"}", "1000000000", "FortiGuard cloud logging (fds): loss not alerted")
    macro(z, tid, "{$FG.LOG.IDLE.ALERT:\"fds\"}", "0", "FortiGuard cloud logging (fds): no idle alert")

    # ---- firewall policy audit
    pw = walk_item(z, tid, "fg.policy.walk", "SNMP walk firewall policy usage", [f"{POLICY}.4", VDNAME], "1h")
    pj = json_item(z, tid, "fg.policy.json", "Firewall policies: summary (JSON)", pw, POL_JS)
    for key, name, path in (("total", "Firewall policies: configured", "total"),
                            ("nohit", "Firewall policies: no traffic since boot", "nohit"),
                            ("idle30", "Firewall policies: idle over 30 days", "idle30"),
                            ("idle90", "Firewall policies: idle over 90 days", "idle90")):
        dep(z, tid, f"fg.policy.{key}", name, pj, path, "policy")
    dep(z, tid, "fg.policy.nohit.list", "Firewall policies without traffic since boot (by VDOM)", pj, "list",
        "policy", text=True, heartbeat="1d")

    # ---- HA
    haw = z.call("item.get", {"templateids": tid, "filter": {"key_": "ha.members.walk"}, "output": ["itemid"]})[0]["itemid"]
    hj = json_item(z, tid, "fg.ha.json", "HA: summary (JSON)", haw, HA_JS)
    dep(z, tid, "fg.ha.members", "HA: cluster members", hj, "members", "ha")
    dep(z, tid, "fg.ha.primary", "HA: primary unit serial number", hj, "primary", "ha", text=True, heartbeat="1h")
    trigger(z, tid, "HA cluster lost a member ({ITEM.LASTVALUE1} left)",
            f"max({t}fg.ha.members,5m)<max({t}fg.ha.members,7d)", 3, tags=tags(("component", "ha")),
            recovery=f"last({t}fg.ha.members)>=max({t}fg.ha.members,7d)")
    trigger(z, tid, "HA failover: primary unit changed to {ITEM.LASTVALUE1}",
            f"last({t}fg.ha.primary,#1)<>last({t}fg.ha.primary,#2) and length(last({t}fg.ha.primary))>0", 3,
            tags=tags(("component", "ha")))
    hrule = z.call("discoveryrule.get", {"templateids": tid, "filter": {"key_": "ha.discovery"}, "output": ["itemid"]})[0]["itemid"]
    trigger_proto(z, hrule, "HA member {#HA.ID}: configuration not synchronized",
                  f"max(/{FORTIGATE}/ha.sync.status[fgHaStatsSyncStatus.{{#SNMPINDEX}}],10m)=0", 3,
                  tags=tags(("component", "ha")))
    snrule = z.call("discoveryrule.get", {"templateids": tid, "filter": {"key_": "hw.sensor.discovery"}, "output": ["itemid"]})[0]["itemid"]
    trigger_proto(z, snrule, "Hardware sensor {#SENSOR.NAME} in alarm",
                  f"last(/{FORTIGATE}/hw.sensor.status[fgHwSensorEntAlarmStatus.{{#SENSOR.ID}}])=1", 3,
                  tags=tags(("component", "sensor")))
    walk_timeouts(z, tid)
    # ---- FortiAP: the stock AP items read the WTP session table, but its walk covers only the WTP config table
    apw = z.call("item.get", {"templateids": tid, "filter": {"key_": "wireless.ap.walk"}, "output": ["itemid"]})[0]["itemid"]
    z.call("item.update", {"itemid": apw, "snmp_oid": R.walk(f"{FG}.14.4.3.1", f"{FG}.14.4.4.1")})
    macro(z, tid, "{$WC.ID.NOT_MATCHES}", "^AP-11N-SERIAL-0001$",
          "FortiAP IDs not to monitor (FortiOS factory sample AP entry, never connected)")
    wrule = z.call("discoveryrule.get", {"templateids": tid, "filter": {"key_": "wireless.discovery"},
                                         "output": ["itemid"]})[0]["itemid"]
    z.call("discoveryrule.update", {"itemid": wrule, "filter": {"evaltype": 1, "conditions": [
        {"macro": "{#WC.NAME}", "operator": 8, "value": "{$WC.NAME.MATCHES}"},
        {"macro": "{#WC.NAME}", "operator": 9, "value": "{$WC.NAME.NOT_MATCHES}"},
        {"macro": "{#WC.ID}", "operator": 9, "value": "{$WC.ID.NOT_MATCHES}"}]}})
    print(f"{FORTIGATE}: detail items / rules / triggers up to date")


# ---------------------------------------------------------------- SonicWall
def sonicwall(z):
    tid = fab.template_id(z, SONICWALL)
    t = f"/{SONICWALL}/"
    vpnw = z.call("item.get", {"templateids": tid, "filter": {"key_": "fw.vpn.walk"}, "output": ["itemid"]})[0]["itemid"]
    z.call("item.update", {"itemid": vpnw, "snmp_oid": R.walk(*(f"{SA}.{c}" for c in (2, 3, 4, 5, 6, 7, 9, 11, 14)))})
    vj = json_item(z, tid, "fw.vpn.json", "IPsec: SA summary (JSON)", vpnw, SA_JSON)
    item(z, tid, "fw.vpn.list", "IPsec: security associations", type=DEP, master_itemid=vj, value_type=TEXT,
         history=TEXT_HIST, tags=tags(("component", "vpn")),
         preprocessing=R.pp((JS, "return JSON.parse(value).list.join('\\n') || '(none)';"), (HEARTBEAT, "1h")),
         description="VPN policy: peer gateway, local <-> remote networks, created. Stored on every change (and hourly).")
    prule = rule(z, tid, "fw.vpn.policy.discovery", "IPsec VPN policy discovery", type=DEP, master_itemid=vj,
                 lifetime="30d", preprocessing=R.pp((JS, SA_LLD.strip()), (HEARTBEAT, "1h")))
    p_tags = tags(("component", "vpn"), ("vpn", "{#SA.NAME}"))
    for key, name, path, rate in (("sas", "SAs up", "sas", None), ("peers", "peers", "peers", None),
                                  ("enc", "traffic encrypted (into the tunnel)", "enc", "bps"),
                                  ("dec", "traffic decrypted (from the tunnel)", "dec", "bps")):
        steps = [(JS, "var v = JSON.parse(value).pol['{#SA.NAME}'];\nreturn v ? v.%s : 0;" % path)]
        if rate:
            steps += [(CHANGE, "", DISCARD), (MULT, "8")]
        proto(z, tid, prule, f"fw.vpn.policy.{key}[{{#SA.NAME}}]", f"IPsec {{#SA.NAME}}: {name}", type=DEP,
              master_itemid=vj, value_type=FLOAT if rate else UINT, units="bps" if rate else "", tags=p_tags,
              preprocessing=R.pp(*steps))
    item(z, tid, "fw.syslog.rate", "Syslog: messages per minute", type=SNMP, snmp_oid=f"get[{SW}.4.3.1.0]", delay="1m",
         value_type=FLOAT, preprocessing=R.pp((CHANGE, "", DISCARD), (MULT, "60")), tags=tags(("component", "logging")))
    item(z, tid, "fw.cfs", "Content filter service", type=SNMP, snmp_oid=f"get[{SW}.1.9.0]", delay="1h",
         valuemapid=R.valuemap(z, tid, "SonicWall enabled state", [(1, "disabled"), (2, "enabled")]),
         preprocessing=R.pp((HEARTBEAT, "1d")), tags=tags(("component", "security")))
    item(z, tid, "fw.dpissl.peak", "Firewall: DPI-SSL connections peak", type=SNMP, snmp_oid=f"get[{SW}.5.2.0]",
         delay="5m", tags=tags(("component", "firewall")))
    zw = walk_item(z, tid, "fw.zone.walk", "SNMP walk zones", [ZONE], "1h")
    zj = json_item(z, tid, "fw.zone.json", "Zones: summary (JSON)", zw, ZONE_JS)
    dep(z, tid, "fw.zone.list", "Zones: security services", zj, "list", "security", text=True, heartbeat="1d")
    dep(z, tid, "fw.zone.weak", "Zones without IPS or gateway anti-virus", zj, "weak", "security")
    macro(z, tid, "{$SW.SYSLOG.IDLE.ALERT}", "1", "1 = alert when the firewall sends no syslog for 15 minutes")
    trigger(z, tid, "No syslog messages for 15 minutes",
            f"{{$SW.SYSLOG.IDLE.ALERT}}=1 and max({t}fw.syslog.rate,15m)=0", 3, tags=tags(("component", "logging")))
    walk_timeouts(z, tid)
    print(f"{SONICWALL}: detail items / rules / triggers up to date")


def tag_text_items(z, tid):
    """Tag every text / character / log item and prototype 'value: text' (stock ones too). Dashboard item navigators
    that feed a follow graph exclude the tag: a follow graph of a text item never gets ready, and the PDF print of
    the whole dashboard then fails ("dashboard failed to get ready")."""
    rules = []
    for kind, getter in (("item", "item.get"), ("itemprototype", "itemprototype.get")):
        for i in z.call(getter, {"templateids": tid, "output": ["itemid", "value_type"], "selectTags": ["tag", "value"],
                                 **({"selectDiscoveryRule": ["itemid"]} if kind == "itemprototype" else {})}):
            if i["value_type"] in ("1", "2", "4") and TEXT_TAG not in i["tags"]:
                z.call(f"{kind}.update", {"itemid": i["itemid"], "tags": i["tags"] + [TEXT_TAG]})
                if kind == "itemprototype":
                    rules.append(i["discoveryRule"]["itemid"])
    return rules


def rediscover(z, template, keys, wait=90):
    """Run the template's dependent LLD rules `keys` on every host now. Their 'discard unchanged with heartbeat 1h'
    step would otherwise delay new prototypes by up to an hour: the step is removed, the master items are polled,
    and the step is put back after `wait` seconds (always, also on errors)."""
    import time
    tid = fab.template_id(z, template)
    rules = z.call("discoveryrule.get", {"templateids": tid, "filter": {"key_": keys},
                                         "output": ["itemid", "key_"], "selectPreprocessing": "extend"})
    keep = {r["itemid"]: [{k: p[k] for k in ("type", "params", "error_handler", "error_handler_params")}
                          for p in r["preprocessing"]] for r in rules}
    for r in rules:   # a crashed earlier run may have left the step out: never save a list without it
        if not any(p["type"] == str(HEARTBEAT) for p in keep[r["itemid"]]):
            keep[r["itemid"]].append({"type": str(HEARTBEAT), "params": "1h", "error_handler": "0",
                                      "error_handler_params": ""})
    try:
        for r in rules:
            z.call("discoveryrule.update", {"itemid": r["itemid"], "preprocessing": [
                p for p in keep[r["itemid"]] if p["type"] != str(HEARTBEAT)]})
        masters = sorted({r["master_itemid"] for r in z.call("discoveryrule.get", {
            "templated": False, "filter": {"key_": keys}, "output": ["master_itemid"]}) if r["master_itemid"] != "0"})
        for n in range(0, len(masters), 50):
            z.call("task.create", [{"type": 6, "request": {"itemid": m}} for m in masters[n:n + 50]])
        time.sleep(wait)
    finally:
        for r in rules:
            z.call("discoveryrule.update", {"itemid": r["itemid"], "preprocessing": keep[r["itemid"]]})
    print(f"{template}: re-ran discovery ({', '.join(keys)}) on {len(masters)} host walks")


def main(z=None):
    import sys
    z = z or base.Zabbix()
    fortigate(z)
    sonicwall(z)
    for template in (FORTIGATE, SONICWALL):
        tid = fab.template_id(z, template)
        changed = tag_text_items(z, tid)
        keys = sorted({r["key_"] for r in z.call("discoveryrule.get", {"itemids": changed, "output": ["key_"]})}) if changed else []
        if "--rediscover" in sys.argv:   # new / changed prototypes reach the hosts now, not within the hour
            keys = sorted(set(keys) | ({"vdom.discovery", "ha.discovery", "hw.sensor.discovery", "vpn.tunnel.discovery",
                                        "wireless.discovery"}
                                       if template == FORTIGATE else set()))
        if keys:
            rediscover(z, template, keys)


if __name__ == "__main__":
    main()
