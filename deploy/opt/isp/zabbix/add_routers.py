#!/usr/bin/env python3
"""Add the Cisco ASR920 edge routers (ASR_RTR-1 Airtel, ASR_RTR-2 Jio) to Zabbix.

Template "Cisco ASR920 by SNMP - PIDC" = copy of the stock "Cisco IOS by SNMP" (IOS-XE 16.12), tuned:
  - interface traffic from its own 10s walk (ASR920 counters refresh every 1s); status/errors walk every 30s
  - capacity figures stripped from ISP/uplink interface descriptions at discovery (e.g. "Jio-ISP-1.5Gbps" ->
    "Jio-ISP"): contracted capacities must never be shown in the tool
  - per-interface Admin status + calculated "Port state" (8 = shutdown), as on the Arista switches
  - CISCO-ENVMON-MIB checks removed (not supported on ASR920); replaced by CISCO-ENTITY-SENSOR-MIB discovery
    (temperatures, voltages, currents, optic Tx/Rx dBm) and CISCO-ENTITY-FRU-CONTROL-MIB PSU / fan status
  - BGP peers (BGP4-MIB + CISCO-BGP4-MIB accepted prefixes): state, admin status, uptime, prefixes; alert
    when an enabled peer is not Established, and when a session re-establishes (flap)
SNMP v2c community: /root/.credentials/router_snmp_community. Idempotent.
"""
import json
import uuid

import setup_isp_links as base

SOURCE = "Cisco IOS by SNMP"
TEMPLATE = "Cisco ASR920 by SNMP - PIDC"
GROUP = "WAN Routers"
ROUTERS = [  # host, visible name, IP, ISP
    ("ASR_RTR-1", "ASR_RTR-1 (ASR_RTR_1_Airtel)", "10.128.17.16", "Airtel"),
    ("ASR_RTR-2", "ASR_RTR-2 (ASR_RTR_2_JIO)", "10.128.17.15", "Jio"),
]
SNMP_WALK_VALUE, SNMP_WALK_TO_JSON, JAVASCRIPT = 28, 29, 21
DEPENDENT, SNMP, CALCULATED = 18, 20, 15
FLOAT, UINT, TEXT = 0, 3, 4

# LLD JavaScript: drop capacity figures from descriptions of ISP-facing ports ("##AIRTEL-2Gig-UPLINK##").
STRIP_CAPACITY_JS = r"""
var rows = JSON.parse(value);
rows.forEach(function (r) {
    var a = r['{#IFALIAS}'] || '';
    if (/ISP|ILL|UPLINK|AIRTEL|JIO|POWER\s*GRID|TATA|BSNL|VODAFONE/i.test(a)) {
        r['{#IFALIAS}'] = a.replace(/[-_ ]*\d+(\.\d+)?\s*(Gbps|Mbps|Kbps|Gig|Meg|G|M)\b/ig, '');
    }
});
return JSON.stringify(rows);
"""
# entSensorType -> (kind, label, units)
SENSOR_KINDS = {"8": ("temp", "Temperature", "°C"), "4": ("volt", "Voltage", "V"),
                "5": ("amp", "Current", "A"), "14": ("dbm", "Optical power", "dBm")}
SENSOR_JS = r"""
var kinds = %s;
return JSON.stringify(JSON.parse(value).filter(function (r) {
    return kinds[r['{#SENSOR_TYPE}']] !== undefined;
}).map(function (r) {
    r['{#SENSOR_KIND}'] = kinds[r['{#SENSOR_TYPE}']];
    r['{#SENSOR_NAME}'] = (r['{#SENSOR_NAME}'] || '').replace(/\s+/g, ' ').trim();
    return r;
}));
""" % json.dumps({k: v[0] for k, v in SENSOR_KINDS.items()})
KEEP_ROWS_WITH = r"""
return JSON.stringify(JSON.parse(value).filter(function (r) { return r['%s'] !== undefined; }));
"""


def pp(*steps):
    return base.pp(*steps)


def clone_template(z, source=SOURCE, template=TEMPLATE, description=None):
    """Copy template `source` to `template` (all name references renamed, fresh uuids). False if it exists."""
    if z.call("template.get", {"filter": {"host": [template]}}):
        return False
    src = z.call("template.get", {"filter": {"host": [source]}, "output": ["templateid"]})[0]["templateid"]
    # trigger expressions and graph items name the template too: rename every reference
    exported = z.call("configuration.export", {"format": "json", "options": {"templates": [src]}})
    data = json.loads(exported.replace(json.dumps(source)[1:-1], json.dumps(template)[1:-1]))
    t = data["zabbix_export"]["templates"][0]
    assert t["template"] == template
    t["description"] = description or (
        "PIDC copy of 'Cisco IOS by SNMP' for ASR920 (IOS-XE): 10s interface traffic, entity "
        "sensors, FRU PSU/fan status and BGP peers. Managed by /opt/isp/zabbix/add_routers.py.")

    def new_uuids(o):   # import needs uuids, and they must not clash with the source template's
        if isinstance(o, dict):
            if "uuid" in o:
                o["uuid"] = uuid.uuid4().hex
            for v in o.values():
                new_uuids(v)
        elif isinstance(o, list):
            for v in o:
                new_uuids(v)
    new_uuids(t)
    data["zabbix_export"]["templates"] = [t]
    rules = {"templates": {"createMissing": True}, "items": {"createMissing": True},
             "discoveryRules": {"createMissing": True}, "triggers": {"createMissing": True},
             "graphs": {"createMissing": True}, "valueMaps": {"createMissing": True},
             "templateDashboards": {"createMissing": True}, "templateLinkage": {"createMissing": True}}
    z.call("configuration.import", {"format": "json", "rules": rules, "source": json.dumps(data)})
    return True


def valuemap(z, tid, name, mappings):
    have = {v["name"]: v["valuemapid"] for v in z.call("valuemap.get", {"hostids": tid, "output": ["valuemapid", "name"]})}
    if name in have:
        return have[name]
    return z.call("valuemap.create", {"hostid": tid, "name": name, "mappings": [
        {"value": str(v), "newvalue": n} for v, n in mappings]})["valuemapids"][0]


def ensure_item(z, tid, key, **kw):
    found = z.call("item.get", {"templateids": tid, "filter": {"key_": key}, "output": ["itemid"]})
    if found:
        return found[0]["itemid"]
    return z.call("item.create", {"hostid": tid, "key_": key, **kw})["itemids"][0]


def ensure_rule(z, tid, key, **kw):
    found = z.call("discoveryrule.get", {"templateids": tid, "filter": {"key_": key}, "output": ["itemid"]})
    if found:
        return found[0]["itemid"]
    return z.call("discoveryrule.create", {"hostid": tid, "key_": key, **kw})["itemids"][0]


def ensure_proto(z, tid, rule, key, **kw):
    found = z.call("itemprototype.get", {"discoveryids": rule, "filter": {"key_": key}, "output": ["itemid"]})
    if found:
        return found[0]["itemid"]
    return z.call("itemprototype.create", {"hostid": tid, "ruleid": rule, "key_": key, **kw})["itemids"][0]


def ensure_trigger(z, rule, description, **kw):
    have = {t["description"] for t in z.call("triggerprototype.get", {"discoveryids": rule, "output": ["description"]})}
    if description not in have:
        z.call("triggerprototype.create", {"description": description, **kw})


def walk(*oids):
    return "walk[" + ",".join(oids) + "]"


def tune_interfaces(z, tid):
    items = {i["key_"]: i["itemid"] for i in z.call("item.get", {"templateids": tid, "output": ["key_"]})}
    z.call("item.update", {"itemid": items["net.if.walk"], "delay": "30s"})
    traffic = ensure_item(z, tid, "net.if.traffic.walk", name="Cisco IOS: SNMP walk interface traffic counters",
                          type=SNMP, snmp_oid=walk("1.3.6.1.2.1.31.1.1.1.6", "1.3.6.1.2.1.31.1.1.1.10"),
                          delay="10s", value_type=TEXT, history="0", trends="0",
                          description="ifHCInOctets / ifHCOutOctets every 10s (ASR920 counters refresh every 1s).",
                          tags=[{"tag": "component", "value": "raw"}])
    rule = z.call("discoveryrule.get", {"templateids": tid, "filter": {"key_": "net.if.discovery"},
                                        "output": ["itemid"], "selectPreprocessing": "extend"})[0]
    steps = [(int(p["type"]), p["params"], int(p["error_handler"])) for p in rule["preprocessing"]]
    if not any(t == JAVASCRIPT for t, _, _ in steps):
        steps.insert(1, (JAVASCRIPT, STRIP_CAPACITY_JS.strip(), 0))
        z.call("discoveryrule.update", {"itemid": rule["itemid"], "preprocessing": pp(*steps)})
    rid = rule["itemid"]
    for p in z.call("itemprototype.get", {"discoveryids": rid, "output": ["key_", "master_itemid"],
                                          "filter": {"key_": ["net.if.in[ifHCInOctets.{#SNMPINDEX}]",
                                                              "net.if.out[ifHCOutOctets.{#SNMPINDEX}]"]}}):
        if p["master_itemid"] != traffic:
            z.call("itemprototype.update", {"itemid": p["itemid"], "master_itemid": traffic})

    # Admin status + Port state (see tune_arista_template.py)
    admin_vm = valuemap(z, tid, "IF-MIB::ifAdminStatus", [(1, "enabled"), (2, "shutdown"), (3, "testing")])
    state_vm = valuemap(z, tid, "Port state", [(1, "up"), (2, "down"), (3, "testing"), (4, "unknown"),
                                               (5, "dormant"), (6, "notPresent"), (7, "lowerLayerDown"), (8, "shutdown")])
    tags = [{"tag": "component", "value": "network"}, {"tag": "description", "value": "{#IFALIAS}"},
            {"tag": "interface", "value": "{#IFNAME}"}]
    admin_key, oper_key = "net.if.adminstatus[ifAdminStatus.{#SNMPINDEX}]", "net.if.status[ifOperStatus.{#SNMPINDEX}]"
    ensure_proto(z, tid, rid, admin_key, name="Interface {#IFNAME}({#IFALIAS}): Admin status", type=DEPENDENT,
                 master_itemid=items["net.if.walk"], value_type=UINT, valuemapid=admin_vm, history="7d", trends="0",
                 tags=tags, preprocessing=pp((SNMP_WALK_VALUE, "1.3.6.1.2.1.2.2.1.7.{#SNMPINDEX}\n0"),
                                             (base.DISCARD_UNCHANGED_HEARTBEAT, "1h")))
    ensure_proto(z, tid, rid, "net.if.portstate[{#SNMPINDEX}]", name="Interface {#IFNAME}({#IFALIAS}): Port state",
                 type=CALCULATED, delay="30s", value_type=UINT, valuemapid=state_vm, history="90d", trends="0",
                 tags=tags, params=f"last(//{oper_key})+(last(//{admin_key})=2)*(8-last(//{oper_key}))",
                 description="Operational status, except 8 = shutdown (ifAdminStatus down).")


def replace_envmon(z, tid):
    """ASR920 has no CISCO-ENVMON-MIB: remove those walks (their LLD rules go with them)."""
    old = z.call("item.get", {"templateids": tid, "output": ["itemid"],
                              "filter": {"key_": ["sensor.temp.walk", "sensor.fans.walk", "sensor.psu.walk"]}})
    if old:
        z.call("item.delete", [i["itemid"] for i in old])

    # ---- Entity sensors ----
    master = ensure_item(z, tid, "sensor.entity.walk", name="Cisco IOS: SNMP walk entity sensors", type=SNMP,
                         snmp_oid=walk("1.3.6.1.4.1.9.9.91.1.1.1.1.1", "1.3.6.1.4.1.9.9.91.1.1.1.1.2",
                                       "1.3.6.1.4.1.9.9.91.1.1.1.1.3", "1.3.6.1.4.1.9.9.91.1.1.1.1.4",
                                       "1.3.6.1.2.1.47.1.1.1.1.7"),
                         delay="1m", value_type=TEXT, history="0", trends="0", tags=[{"tag": "component", "value": "raw"}])
    for stype, (kind, label, units) in SENSOR_KINDS.items():
        rule = ensure_rule(z, tid, f"sensor.entity.discovery[{kind}]", name=f"Entity sensor discovery: {label.lower()}",
                           type=DEPENDENT, master_itemid=master, lifetime="7d",
                           preprocessing=pp((SNMP_WALK_TO_JSON, "\n".join([
                               "{#SENSOR_TYPE}", "1.3.6.1.4.1.9.9.91.1.1.1.1.1", "0",
                               "{#SENSOR_SCALE}", "1.3.6.1.4.1.9.9.91.1.1.1.1.2", "0",
                               "{#SENSOR_PREC}", "1.3.6.1.4.1.9.9.91.1.1.1.1.3", "0",
                               "{#SENSOR_NAME}", "1.3.6.1.2.1.47.1.1.1.1.7", "0"])),
                               (JAVASCRIPT, SENSOR_JS.strip()), (base.DISCARD_UNCHANGED_HEARTBEAT, "1h")),
                           filter={"evaltype": 0, "conditions": [
                               {"macro": "{#SENSOR_KIND}", "operator": 8, "value": f"^{kind}$"}]})
        z.call("discoveryrule.update", {"itemid": rule, "preprocessing": pp(
            (SNMP_WALK_TO_JSON, z.call("discoveryrule.get", {"itemids": rule, "selectPreprocessing": ["params"],
                                                             "output": ["itemid"]})[0]["preprocessing"][0]["params"]),
            (JAVASCRIPT, SENSOR_JS.strip()), (base.DISCARD_UNCHANGED_HEARTBEAT, "1h"))})
        key = f"sensor.{kind}[entSensorValue.{{#SNMPINDEX}}]"
        ensure_proto(z, tid, rule, key, name=f"{{#SENSOR_NAME}}: {label}", type=DEPENDENT, master_itemid=master,
                     value_type=FLOAT, units=units, history="90d", trends="1825d",
                     tags=[{"tag": "component", "value": "optics" if kind == "dbm" else "environment"},
                           {"tag": "sensor", "value": kind}],
                     preprocessing=pp((SNMP_WALK_VALUE, "1.3.6.1.4.1.9.9.91.1.1.1.1.4.{#SNMPINDEX}\n0"),
                                      (JAVASCRIPT, "return value * Math.pow(10, 3 * ({#SENSOR_SCALE} - 9)) "
                                                   "/ Math.pow(10, {#SENSOR_PREC});")))
        if kind == "temp":
            ensure_trigger(z, rule, "{#SENSOR_NAME}: temperature is high (over {$TEMP.ENTITY.MAX:\"{#SENSOR_NAME}\"}°C)",
                           expression=f"min(/{TEMPLATE}/{key},5m)>{{$TEMP.ENTITY.MAX:\"{{#SENSOR_NAME}}\"}}",
                           priority=4, tags=[{"tag": "scope", "value": "availability"}])
        if kind == "dbm":
            ensure_trigger(z, rule, "{#SENSOR_NAME}: optical power is low (under {$OPTIC.DBM.MIN}dBm)",
                           expression=f"max(/{TEMPLATE}/{key},5m)<{{$OPTIC.DBM.MIN}}",
                           priority=2, tags=[{"tag": "scope", "value": "performance"}])

    # ---- Power supplies and fans (CISCO-ENTITY-FRU-CONTROL-MIB) ----
    fru = ensure_item(z, tid, "sensor.fru.walk", name="Cisco IOS: SNMP walk PSU and fan status", type=SNMP,
                      snmp_oid=walk("1.3.6.1.4.1.9.9.117.1.1.2.1.2", "1.3.6.1.4.1.9.9.117.1.4.1.1.1",
                                    "1.3.6.1.2.1.47.1.1.1.1.7"),
                      delay="1m", value_type=TEXT, history="0", trends="0", tags=[{"tag": "component", "value": "raw"}])
    psu_vm = valuemap(z, tid, "CISCO-ENTITY-FRU-CONTROL-MIB::cefcFRUPowerOperStatus", [
        (1, "offEnvOther"), (2, "on"), (3, "offAdmin"), (4, "offDenied"), (5, "offEnvPower"), (6, "offEnvTemp"),
        (7, "offEnvFan"), (8, "failed"), (9, "onButFanFail"), (10, "offCooling"), (11, "offConnectorRating"),
        (12, "onButInlinePowerFail")])
    fan_vm = valuemap(z, tid, "CISCO-ENTITY-FRU-CONTROL-MIB::cefcFanTrayOperStatus",
                      [(1, "unknown"), (2, "up"), (3, "down"), (4, "warning")])
    for what, oid, macro, vm, label in (
            ("psu", "1.3.6.1.4.1.9.9.117.1.1.2.1.2", "{#PSU_STATUS}", psu_vm, "Power supply status"),
            ("fan", "1.3.6.1.4.1.9.9.117.1.4.1.1.1", "{#FAN_STATUS}", fan_vm, "Fan tray status")):
        rule = ensure_rule(z, tid, f"sensor.fru.discovery[{what}]", name=f"FRU discovery: {label.lower()}",
                           type=DEPENDENT, master_itemid=fru, lifetime="7d",
                           preprocessing=pp((SNMP_WALK_TO_JSON, f"{macro}\n{oid}\n0\n{{#ENT_NAME}}\n1.3.6.1.2.1.47.1.1.1.1.7\n0"),
                                            (JAVASCRIPT, (KEEP_ROWS_WITH % macro).strip()),
                                            (base.DISCARD_UNCHANGED_HEARTBEAT, "1h")))
        key = f"sensor.{what}.status[{{#SNMPINDEX}}]"
        ensure_proto(z, tid, rule, key, name=f"{{#ENT_NAME}}: {label}", type=DEPENDENT, master_itemid=fru,
                     value_type=UINT, valuemapid=vm, history="90d", trends="0",
                     tags=[{"tag": "component", "value": "power" if what == "psu" else "fan"}],
                     preprocessing=pp((SNMP_WALK_VALUE, f"{oid}.{{#SNMPINDEX}}\n0"),
                                      (base.DISCARD_UNCHANGED_HEARTBEAT, "1h")))
        ensure_trigger(z, rule, f"{{#ENT_NAME}}: {label.lower()} is not OK", priority=4,
                       expression=f"last(/{TEMPLATE}/{key})<>2", tags=[{"tag": "scope", "value": "availability"}])


def add_bgp(z, tid):
    master = ensure_item(z, tid, "bgp.walk", name="Cisco IOS: SNMP walk BGP peers", type=SNMP,
                         snmp_oid=walk("1.3.6.1.2.1.15.3.1.2", "1.3.6.1.2.1.15.3.1.3", "1.3.6.1.2.1.15.3.1.9",
                                       "1.3.6.1.2.1.15.3.1.16", "1.3.6.1.4.1.9.9.187.1.2.8.1.1"),
                         delay="30s", value_type=TEXT, history="0", trends="0", tags=[{"tag": "component", "value": "raw"}])
    state_vm = valuemap(z, tid, "BGP4-MIB::bgpPeerState", [(1, "idle"), (2, "connect"), (3, "active"),
                                                           (4, "opensent"), (5, "openconfirm"), (6, "established")])
    admin_vm = valuemap(z, tid, "BGP4-MIB::bgpPeerAdminStatus", [(1, "shutdown"), (2, "enabled")])
    rule = ensure_rule(z, tid, "bgp.peer.discovery", name="BGP peer discovery", type=DEPENDENT,
                       master_itemid=master, lifetime="7d",
                       preprocessing=pp((SNMP_WALK_TO_JSON, "{#PEER_STATE}\n1.3.6.1.2.1.15.3.1.2\n0\n"
                                                            "{#REMOTE_AS}\n1.3.6.1.2.1.15.3.1.9\n0"),
                                        (JAVASCRIPT, (KEEP_ROWS_WITH % "{#REMOTE_AS}").strip()),
                                        (base.DISCARD_UNCHANGED_HEARTBEAT, "1h")))
    tags = [{"tag": "component", "value": "bgp"}, {"tag": "peer", "value": "{#SNMPINDEX}"},
            {"tag": "remote_as", "value": "{#REMOTE_AS}"}]
    name = "BGP peer {#SNMPINDEX} (AS{#REMOTE_AS})"
    walkval = lambda oid: (SNMP_WALK_VALUE, f"{oid}.{{#SNMPINDEX}}\n0")
    ensure_proto(z, tid, rule, "bgp.peer.state[{#SNMPINDEX}]", name=f"{name}: State", type=DEPENDENT,
                 master_itemid=master, value_type=UINT, valuemapid=state_vm, history="90d", trends="0", tags=tags,
                 preprocessing=pp(walkval("1.3.6.1.2.1.15.3.1.2")))
    ensure_proto(z, tid, rule, "bgp.peer.admin[{#SNMPINDEX}]", name=f"{name}: Admin status", type=DEPENDENT,
                 master_itemid=master, value_type=UINT, valuemapid=admin_vm, history="90d", trends="0", tags=tags,
                 preprocessing=pp(walkval("1.3.6.1.2.1.15.3.1.3"), (base.DISCARD_UNCHANGED_HEARTBEAT, "1h")))
    ensure_proto(z, tid, rule, "bgp.peer.uptime[{#SNMPINDEX}]", name=f"{name}: Time in current state",
                 type=DEPENDENT, master_itemid=master, value_type=UINT, units="uptime", history="90d",
                 trends="1825d", tags=tags, preprocessing=pp(walkval("1.3.6.1.2.1.15.3.1.16")),
                 description="bgpPeerFsmEstablishedTime: seconds since the session last entered (or left) Established.")
    ensure_proto(z, tid, rule, "bgp.peer.prefixes[{#SNMPINDEX}]", name=f"{name}: Accepted IPv4 prefixes",
                 type=DEPENDENT, master_itemid=master, value_type=UINT, history="90d", trends="1825d", tags=tags,
                 preprocessing=pp((SNMP_WALK_VALUE, "1.3.6.1.4.1.9.9.187.1.2.8.1.1.1.4.{#SNMPINDEX}.1.1\n0")))
    session_vm = valuemap(z, tid, "BGP session state", [(0, "shutdown"), (1, "idle"), (2, "connect"), (3, "active"),
                                                         (4, "opensent"), (5, "openconfirm"), (6, "established")])
    ensure_proto(z, tid, rule, "bgp.peer.session[{#SNMPINDEX}]", name=f"{name}: Session state", type=CALCULATED,
                 delay="30s", value_type=UINT, valuemapid=session_vm, history="90d", trends="0", tags=tags,
                 params="last(//bgp.peer.state[{#SNMPINDEX}])*(last(//bgp.peer.admin[{#SNMPINDEX}])=2)",
                 description="BGP state, or 0 = shutdown when the peer is administratively disabled.")
    st, ad, up = (f"/{TEMPLATE}/bgp.peer.{k}[{{#SNMPINDEX}}]" for k in ("state", "admin", "uptime"))
    ensure_trigger(z, rule, "BGP peer {#SNMPINDEX} (AS{#REMOTE_AS}) is not established", priority=3,
                   expression=f"last({st})<>6 and last({ad})=2",
                   recovery_mode=1, recovery_expression=f"last({st})=6 or last({ad})=1",
                   tags=[{"tag": "scope", "value": "availability"}, {"tag": "bgp_peer", "value": "{#SNMPINDEX}"}],
                   comments="The BGP session is enabled (not shut down) but not Established.")
    ensure_trigger(z, rule, "BGP peer {#SNMPINDEX} (AS{#REMOTE_AS}) session re-established (flap)", priority=2,
                   expression=f"last({st})=6 and last({up})<600 and last({up},#2)>last({up})",
                   recovery_mode=1, recovery_expression=f"last({up})>=600",
                   tags=[{"tag": "scope", "value": "availability"}, {"tag": "bgp_peer", "value": "{#SNMPINDEX}"}],
                   comments="The session came back up within the last 10 minutes (it went down and recovered).")


def template_macros(z, tid):
    have = {m["macro"] for m in z.call("usermacro.get", {"hostids": tid, "output": ["macro"]})}
    for macro, value, desc in (("{$TEMP.ENTITY.MAX}", "75", "Entity temperature sensor alarm level, °C"),
                               ("{$TEMP.ENTITY.MAX:\"Temp: Cylon R0/18\"}", "90",
                                "Forwarding ASIC runs hot by design (~70°C)"),
                               ("{$OPTIC.DBM.MIN}", "-20", "Optic Tx/Rx power alarm level, dBm")):
        if macro not in have:
            z.call("usermacro.create", {"hostid": tid, "macro": macro, "value": value, "description": desc})


def main():
    z = base.Zabbix()
    community = base.read("/root/.credentials/router_snmp_community")
    print("template cloned" if clone_template(z) else "template exists")
    tid = z.call("template.get", {"filter": {"host": [TEMPLATE]}, "output": ["templateid"]})[0]["templateid"]
    tune_interfaces(z, tid)
    replace_envmon(z, tid)
    add_bgp(z, tid)
    template_macros(z, tid)

    found = z.call("hostgroup.get", {"filter": {"name": [GROUP]}, "output": ["groupid"]})
    gid = found[0]["groupid"] if found else z.call("hostgroup.create", {"name": GROUP})["groupids"][0]
    created = []
    for host, name, ip, isp in ROUTERS:
        if z.call("host.get", {"filter": {"host": [host]}}):
            continue
        z.call("host.create", {
            "host": host, "name": name, "groups": [{"groupid": gid}], "templates": [{"templateid": tid}],
            "interfaces": [{"type": 2, "main": 1, "useip": 1, "ip": ip, "dns": "", "port": "161",
                            "details": {"version": 2, "bulk": 1, "community": "{$SNMP_COMMUNITY}"}}],
            "macros": [{"macro": "{$SNMP_COMMUNITY}", "value": community, "type": 1,
                        "description": "ASR920 SNMP v2c community"},
                       # discover every physical port incl. shut-down ones (shown as "shutdown" via Port state)
                       {"macro": "{$NET.IF.IFOPERSTATUS.NOT_MATCHES}", "value": "CHANGE_IF_NEEDED"},
                       {"macro": "{$NET.IF.IFADMINSTATUS.NOT_MATCHES}", "value": "CHANGE_IF_NEEDED"},
                       {"macro": "{$NET.IF.IFNAME.NOT_MATCHES}",
                        "value": r"(^Software Loopback Interface|^NULL[0-9.]*$|^[Ll]o[0-9.]*$|^[Ss]ystem$|^Nu[0-9.]*$|"
                                 r"^Vi[0-9]+$|^Loopback[0-9]+$)"}],
            "tags": [{"tag": "role", "value": "edge-router"}, {"tag": "vendor", "value": "cisco"},
                     {"tag": "isp", "value": isp}],
            "inventory_mode": 1,
        })
        created.append(host)
    hostids = [h["hostid"] for h in z.call("host.get", {"groupids": gid, "output": ["hostid"]})]
    rules = z.call("discoveryrule.get", {"hostids": hostids, "output": ["itemid"]})
    if rules:
        z.call("task.create", [{"type": 6, "request": {"itemid": r["itemid"]}} for r in rules])
    print(f"created {created or 'nothing new'}; ran {len(rules)} discovery rules now")


if __name__ == "__main__":
    main()
