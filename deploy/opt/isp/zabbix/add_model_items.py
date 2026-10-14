#!/usr/bin/env python3
"""Model-specific SNMP monitoring found by the 2026-10-14 coverage survey (one device per model: every MIB group the
agent answers, compared with what Zabbix polled). Idempotent; re-run after changing it.

Added only where the model answers the objects (checked on the devices), so there are no unsupported items:
  FortiGate (all models)    BGP4-MIB peers (state, admin, remote AS, time established) + alert when an enabled peer
                            is not established; NP / CP processor modules (sessions, IPsec SAs, memory); log
                            partition needs a scan (alert); session rate 10 / 30 / 60 min averages
  FortiGate 200F, 120G      free / freeable memory % (FortiOS 7.2 on the 300E has no such objects)
  Catalyst 2960+ / 2960S / 2960X, ASR920
                            CISCO-STACK-MIB chassis: power supply 1 / 2, fan, temperature alarm, minor / major alarm
                            (the 4948 does not answer this group)
  Catalyst 3650 (all four)  CISCO-ENTITY-FRU-CONTROL: each power supply, fan tray and module operational status
  HPE 5820                  each fan's status
  Juniper EX3400            craft panel yellow alarm (state + count; red alarm / overall health were already there)
  Arista (all models)       VRF state, 1 / 5 / 15 minute load averages
Not added (checked): A10 BGP (already from the A10 MIB), A10 hardware sensors (BareMetal: all 0), Juniper storage
(HOST-RESOURCES already), configuration-only groups (AAA, DHCP, ACL, VLAN / STP config ...).
"""
import setup_isp_links as base
from add_full_coverage import Template, wv, on_change, SNMP, FLOAT, UINT, CHAR, CPS, MULT

FG = "FortiGate by SNMP - PIDC"
FG_FREEMEM = ["FortiGate 200F by SNMP - PIDC", "FortiGate 120G by SNMP - PIDC"]
CHASSIS = ["Cisco Catalyst WS-C2960-Plus-48TC-S by SNMP - PIDC", "Cisco Catalyst WS-C2960S-48TS-L by SNMP - PIDC",
           "Cisco Catalyst WS-C2960X-48TD-L by SNMP - PIDC", "Cisco ASR920 by SNMP - PIDC"]
C3650 = ["Cisco Catalyst WS-C3650-24TS-E by SNMP - PIDC", "Cisco Catalyst WS-C3650-24TS-S by SNMP - PIDC",
         "Cisco Catalyst WS-C3650-48FQ-E by SNMP - PIDC", "Cisco Catalyst WS-C3650-48TS-S by SNMP - PIDC"]
HPE5820 = "HPE 5820AF-24XG by SNMP - PIDC"
EX3400 = "Juniper EX3400-24T by SNMP - PIDC"
ARISTA = "Arista by SNMP - PIDC"
AVERAGE, HIGH = 3, 4   # alerts are e-mailed from Average up (action "ISP link alerts")
ENTNAME = "1.3.6.1.2.1.47.1.1.1.1.7"


def tags(c):
    return [{"tag": "component", "value": c}]


# ------------------------------------------------------------------------------------------------ FortiGate
def fortigate_bgp(t):
    p = "1.3.6.1.2.1.15.3.1"
    m = t.walk("pidc.bgp4.walk", "BGP4-MIB peers", [f"{p}.2", f"{p}.3", f"{p}.7", f"{p}.9", f"{p}.16"], "1m")
    rid = t.rule("pidc.bgp4.discovery", m, "BGP peer discovery (BGP4-MIB)", r"""
var o = W(value), st = C(o, '1.3.6.1.2.1.15.3.1.2'), as = C(o, '1.3.6.1.2.1.15.3.1.9'),
    ad = C(o, '1.3.6.1.2.1.15.3.1.7'), out = [];
// FortiGate indexes the table with more than the 4 address bytes: name the peer by bgpPeerRemoteAddr
for (var i in st) out.push({'{#PEER}': i, '{#PEER.IP}': ad[i] || i, '{#REMOTE_AS}': as[i] || ''});
return JSON.stringify(out);""")
    # a peer that is no longer in the device's BGP table (dynamic neighbour that dropped, or removed) reads 0 and alerts
    vs = t.vm("BGP4-MIB peer state", [(0, "gone (not in BGP table)"), (1, "idle"), (2, "connect"), (3, "active"), (4, "opensent"), (5, "openconfirm"),
                                      (6, "established")])
    va = t.vm("BGP4-MIB admin status", [(0, "unknown (peer gone)"), (1, "stop (shut down)"), (2, "start")])
    tg = tags("bgp")
    t.proto(rid, "pidc.bgp4.state[{#PEER}]", "BGP peer {#PEER.IP} (AS{#REMOTE_AS}): state", m,
            [(28, f"{p}.2.{{#PEER}}\n0", 2, "0"), on_change()], value_type=UINT, valuemapid=vs, trends="0", tags=tg)
    t.proto(rid, "pidc.bgp4.admin[{#PEER}]", "BGP peer {#PEER.IP} (AS{#REMOTE_AS}): admin status", m,
            [(28, f"{p}.3.{{#PEER}}\n0", 2, "0"), on_change()], value_type=UINT, valuemapid=va, trends="0", tags=tg)
    t.proto(rid, "pidc.bgp4.uptime[{#PEER}]", "BGP peer {#PEER.IP} (AS{#REMOTE_AS}): time in current state", m,
            [wv(f"{p}.16.{{#PEER}}")], value_type=UINT, units="uptime", tags=tg)
    t.tproto(rid, "BGP peer {#PEER.IP} (AS{#REMOTE_AS}) is not established",
             f"max({t.k('pidc.bgp4.state[{#PEER}]')},5m)<6 and last({t.k('pidc.bgp4.admin[{#PEER}]')})<>1",
             AVERAGE, "bgp", comments="Not Established for 5 minutes and not shut down on purpose (admin stop); also when the peer has gone "
                      "from the device's BGP table.")


def fortigate_system(t):
    s = "1.3.6.1.4.1.12356.101.4.1"
    tg = tags("system")
    for col, key, name in ((12, "rate10", "Firewall: session setup rate (10 min average)"),
                           (13, "rate30", "Firewall: session setup rate (30 min average)"),
                           (14, "rate60", "Firewall: session setup rate (60 min average)")):
        t.item(f"pidc.fg.ses.{key}", name=name, type=SNMP, snmp_oid=f"get[{s}.{col}.0]", delay="5m",
               value_type=UINT, units="sessions/s", trends="730d", tags=tags("sessions"))
    vm = t.vm("FortiGate log partition scan", [(1, "not needed"), (2, "needed")])
    t.item("pidc.fg.logscan", name="Log partition needs a scan", type=SNMP, snmp_oid=f"get[{s}.21.0]", delay="15m",
           value_type=UINT, valuemapid=vm, trends="0", preprocessing=base.pp(on_change("1d")), tags=tg)
    t.trigger("Log partition needs a scan (run 'execute disk scan')", f"last({t.k('pidc.fg.logscan')})=2", AVERAGE, "logging")
    pm = "1.3.6.1.4.1.12356.101.4.5.3.1"
    m = t.walk("pidc.fg.procmod.walk", "processor modules", [f"{pm}.3", f"{pm}.4", f"{pm}.7", f"{pm}.8", f"{pm}.9"], "5m")
    rid = t.rule("pidc.fg.procmod.discovery", m, "Processor module discovery (NP / CP)", r"""
var o = W(value), n = C(o, '1.3.6.1.4.1.12356.101.4.5.3.1.3'), d = C(o, '1.3.6.1.4.1.12356.101.4.5.3.1.4'), out = [];
for (var i in n) out.push({'{#PM}': i, '{#PM.NAME}': n[i], '{#PM.DESCR}': d[i] || ''});
return JSON.stringify(out);""")
    tg = tags("cpu")
    for col, key, name, units in ((7, "mem", "memory utilization", "%"), (8, "sessions", "active sessions", ""),
                                  (9, "sa", "IPsec security associations", "")):
        t.proto(rid, f"pidc.fg.procmod.{key}[{{#PM}}]", f"Processor module {{#PM.NAME}}: {name}", m,
                [wv(f"{pm}.{col}.{{#PM}}")], value_type=UINT, units=units, tags=tg)


def fortigate_freemem(t):
    s = "1.3.6.1.4.1.12356.101.4.1"
    for col, key, name in ((36, "free", "Memory: free (%)"), (37, "freeable", "Memory: freeable (%)")):
        t.item(f"pidc.fg.mem.{key}", name=name, type=SNMP, snmp_oid=f"get[{s}.{col}.0]", delay="5m",
               value_type=UINT, units="%", trends="730d", tags=tags("memory"))


# ------------------------------------------------------------------------------------------------ Cisco
def cisco_chassis(t):
    c = "1.3.6.1.4.1.9.5.1.2"
    m = t.walk("pidc.chassis.walk", "chassis status (CISCO-STACK-MIB)", [f"{c}.4", f"{c}.7", f"{c}.9", f"{c}.11",
                                                                        f"{c}.12", f"{c}.13"], "1m")
    st = t.vm("CISCO-STACK-MIB status", [(1, "other / not present"), (2, "ok"), (3, "minor fault"), (4, "major fault")])
    al = t.vm("CISCO-STACK-MIB alarm", [(1, "off"), (2, "alarm ON"), (3, "alarm critical")])
    for col, key, name, vm, comp in ((4, "ps1", "Chassis: power supply 1 status", st, "power"),
                                     (7, "ps2", "Chassis: power supply 2 status", st, "power"),
                                     (9, "fan", "Chassis: fan status", st, "fan"),
                                     (13, "temp", "Chassis: temperature alarm", al, "temperature"),
                                     (11, "minor", "Chassis: minor alarm", al, "health"),
                                     (12, "major", "Chassis: major alarm", al, "health")):
        t.dep(m, f"pidc.chassis.{key}", name, [wv(f"{c}.{col}.0"), on_change()], value_type=UINT, trends="0",
              valuemapid=vm, tags=tags(comp))
    for key, what in (("ps1", "Power supply 1"), ("ps2", "Power supply 2"), ("fan", "Fan")):
        t.trigger(f"Chassis: {what} fault", f"last({t.k('pidc.chassis.' + key)})>=3", HIGH, "hardware")
    t.trigger("Chassis: temperature alarm", f"last({t.k('pidc.chassis.temp')})>=2", HIGH, "temperature")
    t.trigger("Chassis: major alarm", f"last({t.k('pidc.chassis.major')})=2", HIGH, "hardware")
    t.trigger("Chassis: minor alarm", f"last({t.k('pidc.chassis.minor')})=2", AVERAGE, "hardware")


def cisco_fru(t):
    f = "1.3.6.1.4.1.9.9.117.1"
    for key, label, col, rule_name, vm_name, pairs, ok, comp in (
            ("psu", "Power supply", f"{f}.1.2.1.2", "FRU power supply discovery", "CISCO-ENTITY-FRU power state",
             [(1, "off (environment)"), (2, "on"), (3, "off (admin)"), (4, "off (denied)"), (5, "off (power)"),
              (6, "off (temperature)"), (7, "off (fan)"), (8, "failed"), (9, "on, fan failed"), (10, "off (cooling)"),
              (11, "off (connector rating)"), (12, "on, inline power failed")], 2, "power"),
            ("fan", "Fan tray", f"{f}.4.1.1.1", "FRU fan tray discovery", "CISCO-ENTITY-FRU fan state",
             [(1, "unknown"), (2, "up"), (3, "down"), (4, "warning")], 2, "fan"),
            ("module", "Module", f"{f}.2.1.1.2", "FRU module discovery", "CISCO-ENTITY-FRU module state",
             [(1, "unknown"), (2, "ok"), (3, "disabled"), (4, "ok, diagnostics failed"), (5, "boot"), (6, "self test"),
              (7, "failed"), (8, "missing"), (9, "mismatch with parent"), (10, "mismatch config"), (11, "diagnostics failed"),
              (12, "dormant"), (13, "out of service (admin)"), (14, "out of service (temperature)"), (15, "powered down"),
              (16, "powered up"), (17, "power denied"), (18, "power cycled"), (19, "ok, power denied"), (20, "powered off")],
             2, "hardware")):
        m = t.walk(f"pidc.fru.{key}.walk", f"FRU {label.lower()} status", [col, ENTNAME], "1m")
        rid = t.rule(f"pidc.fru.{key}.discovery", m, rule_name, f"""
var o = W(value), s = C(o, '{col}'), n = C(o, '{ENTNAME}'), out = [];
for (var i in s) out.push({{'{{#FRU}}': i, '{{#FRU.NAME}}': n[i] || ('{label} ' + i)}});
return JSON.stringify(out);""")
        vm = t.vm(vm_name, pairs)
        t.proto(rid, f"pidc.fru.{key}[{{#FRU}}]", f"{label} {{#FRU.NAME}}: status", m, [wv(f"{col}.{{#FRU}}"), on_change()],
                value_type=UINT, trends="0", valuemapid=vm, tags=tags(comp))
        t.tproto(rid, f"{label} {{#FRU.NAME}} is not OK", f"last({t.k(f'pidc.fru.{key}[{{#FRU}}]')})<>{ok}", HIGH, comp)


# ------------------------------------------------------------------------------------------------ HPE, Juniper, Arista
def hpe_fans(t):
    col = "1.3.6.1.4.1.25506.8.35.9.1.1.1.2"
    m = t.walk("pidc.hpefan.walk", "fan status (HH3C-LSW-DEV-ADM-MIB)", [col], "1m")
    rid = t.rule("pidc.hpefan.discovery", m, "Fan discovery (device management MIB)", f"""
var s = C(W(value), '{col}'), out = [];
for (var i in s) if (s[i] !== '4') out.push({{'{{#FAN}}': i}});   // 4 = unsupported (empty slot)
return JSON.stringify(out);""")
    vm = t.vm("HH3C fan status", [(1, "active"), (2, "deactive"), (3, "not installed"), (4, "unsupported")])
    t.proto(rid, "pidc.hpefan.status[{#FAN}]", "Fan {#FAN}: status", m, [wv(f"{col}.{{#FAN}}"), on_change()],
            value_type=UINT, trends="0", valuemapid=vm, tags=tags("fan"))
    t.tproto(rid, "Fan {#FAN} is not active", f"last({t.k('pidc.hpefan.status[{#FAN}]')})=2", HIGH, "fan")


def juniper_yellow(t):
    y = "1.3.6.1.4.1.2636.3.4.2.2"
    vm = t.vm("Juniper craft alarm state", [(1, "other"), (2, "off"), (3, "alarm ON")])
    t.item("pidc.jnx.yellow", name="Craft panel: yellow alarm", type=SNMP, snmp_oid=f"get[{y}.1.0]", delay="1m",
           value_type=UINT, valuemapid=vm, trends="0", preprocessing=base.pp(on_change()), tags=tags("health"))
    t.item("pidc.jnx.yellow.count", name="Craft panel: active yellow alarms", type=SNMP, snmp_oid=f"get[{y}.2.0]",
           delay="1m", value_type=UINT, trends="730d", tags=tags("health"))
    t.trigger("Yellow alarm is on (see 'show chassis alarms')", f"last({t.k('pidc.jnx.yellow')})=3", AVERAGE, "hardware")


def arista_extra(t):
    v = "1.3.6.1.4.1.30065.3.18.1.1.1.4"
    m = t.walk("pidc.vrf.walk", "VRF state (ARISTA-VRF-MIB)", [v], "5m")
    rid = t.rule("pidc.vrf.discovery", m, "VRF discovery", f"""
var s = C(W(value), '{v}'), out = [];
for (var i in s) {{ var a = i.split('.'), n = '';
    for (var k = 1; k < a.length; k++) n += String.fromCharCode(parseInt(a[k], 10));   // index = name as length.chars
    out.push({{'{{#VRF.IDX}}': i, '{{#VRF}}': n}}); }}
return JSON.stringify(out);""")
    vm = t.vm("Arista VRF state", [(1, "active"), (2, "inactive")])
    t.proto(rid, "pidc.vrf.state[{#VRF.IDX}]", "VRF {#VRF}: state", m, [wv(f"{v}.{{#VRF.IDX}}"), on_change()],
            value_type=UINT, trends="0", valuemapid=vm, tags=tags("routing"))
    # alert kept on purpose (user: never mute alerts): EOS also reports a management VRF without IP routing
    # (MGMT, PIVRF) as inactive
    t.tproto(rid, "VRF {#VRF} is inactive", f"last({t.k('pidc.vrf.state[{#VRF.IDX}]')})=2", AVERAGE, "routing")
    for n, mins in ((1, 1), (2, 5), (3, 15)):
        t.item(f"pidc.load[{mins}]", name=f"CPU load average ({mins} min)", type=SNMP,
               snmp_oid=f"get[1.3.6.1.4.1.2021.10.1.3.{n}]", delay="1m", value_type=FLOAT, trends="730d",
               tags=tags("cpu"))


def main():
    z = base.Zabbix()
    def tech(name):   # technical name, given the technical or the visible one ("WS-C2960+48TC-S")
        return (z.call("template.get", {"filter": {"host": [name]}, "output": ["host"]})
                or z.call("template.get", {"filter": {"name": [name]}, "output": ["host"]}))[0]["host"]
    jobs = [(FG, [fortigate_bgp, fortigate_system])] + [(n, [fortigate_freemem]) for n in FG_FREEMEM] \
        + [(n, [cisco_chassis]) for n in CHASSIS] + [(n, [cisco_fru]) for n in C3650] \
        + [(HPE5820, [hpe_fans]), (EX3400, [juniper_yellow]), (ARISTA, [arista_extra])]
    for name, fns in jobs:
        t = Template(z, tech(name))
        for fn in fns:
            fn(t)
        print(f"{name}: {t.n}")


if __name__ == "__main__":
    main()
