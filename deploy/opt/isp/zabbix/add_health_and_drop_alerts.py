#!/usr/bin/env python3
"""Add A10 health items (CPU per core, memory) and sudden-traffic-drop triggers.

Idempotent: items/triggers that already exist (by key / name) are skipped.
Run after setup_isp_links.py and build_dashboard.py (needs the "Total" items).
"""
import subprocess

import setup_isp_links as base

A10_CPU_COUNT_OID = "1.3.6.1.4.1.22610.2.4.1.3.1.0"
A10_CPU_USAGE_OID = "1.3.6.1.4.1.22610.2.4.1.3.2.1.3.{}"   # % per CPU, 0-based index
A10_MEM_TOTAL_OID = "1.3.6.1.4.1.22610.2.4.1.2.1.0"        # KB
A10_MEM_USED_OID = "1.3.6.1.4.1.22610.2.4.1.2.2.0"         # KB

DROP_MACROS = [
    ("{$ISP.DROP.PCT}", "50", "Alert when 5m traffic falls below this % of the previous hour's average"),
    ("{$ISP.DROP.MIN}", "100000000", "Only check drops when the previous hour averaged above this (bps)"),
    ("{$A10.CPU.HIGH}", "75", "A10 CPU % (busiest core, 5m avg)"),
    ("{$A10.MEM.HIGH}", "85", "A10 memory used %"),
]


def main():
    z = base.Zabbix()
    host = z.call("host.get", {"filter": {"host": [base.HOST]}, "selectMacros": ["macro"],
                               "selectInterfaces": ["interfaceid"]})[0]
    hostid, ifid = host["hostid"], host["interfaces"][0]["interfaceid"]
    have_keys = {i["key_"] for i in z.call("item.get", {"hostids": hostid, "output": ["key_"]})}
    have_macros = {m["macro"] for m in host["macros"]}

    for macro, value, desc in DROP_MACROS:
        if macro not in have_macros:
            z.call("usermacro.create", {"hostid": hostid, "macro": macro, "value": value, "description": desc})

    def item(**kw):
        if kw["key_"] in have_keys:
            return
        base_kw = {"hostid": hostid, "history": base.HISTORY, "trends": base.TRENDS}
        base_kw.update(kw)
        z.call("item.create", base_kw)
        have_keys.add(kw["key_"])

    snmp = {"type": 20, "interfaceid": ifid, "delay": "1m"}
    tags = [{"tag": "component", "value": "a10-health"}]
    # CPU count is read once here so the item set matches the box.
    out = subprocess.run(["snmpget", "-v2c", "-c", base.read("/root/.credentials/a10_snmp_community"), "-Oqv",
                          base.A10_MGMT_IP, A10_CPU_COUNT_OID], capture_output=True, text=True).stdout.strip()
    cpus = int(out)
    for n in range(cpus):
        item(name=f"A10: CPU {n} usage", key_=f"a10.cpu.util[{n}]", snmp_oid=A10_CPU_USAGE_OID.format(n),
             value_type=0, units="%", tags=tags, **snmp)
    item(name="A10: CPU usage (busiest core)", key_="a10.cpu.util.max", type=15, interfaceid="0", delay="1m",
         value_type=0, units="%", tags=tags,
         params="max(" + ",".join(f"last(//a10.cpu.util[{n}])" for n in range(cpus)) + ")")
    item(name="A10: CPU usage (average)", key_="a10.cpu.util.avg", type=15, interfaceid="0", delay="1m",
         value_type=0, units="%", tags=tags,
         params="(" + "+".join(f"last(//a10.cpu.util[{n}])" for n in range(cpus)) + f")/{cpus}")
    item(name="A10: Memory total", key_="a10.mem.total", snmp_oid=A10_MEM_TOTAL_OID, value_type=3, units="B",
         tags=tags, preprocessing=base.pp((1, "1024")), **{**snmp, "delay": "1h"})
    item(name="A10: Memory used", key_="a10.mem.used", snmp_oid=A10_MEM_USED_OID, value_type=3, units="B",
         tags=tags, preprocessing=base.pp((1, "1024")), **snmp)
    item(name="A10: Memory used %", key_="a10.mem.pused", type=15, interfaceid="0", delay="1m", value_type=0,
         units="%", tags=tags, params="last(//a10.mem.used)/last(//a10.mem.total)*100")

    h = f"/{base.HOST}/"
    have_triggers = {t["description"] for t in z.call("trigger.get", {"hostids": hostid, "output": ["description"]})}
    triggers = []

    def drop(desc, key, prio, tag):
        prev = f"avg({h}{key},1h:now-10m)"
        triggers.append({
            "description": desc, "priority": prio, "tags": [{"tag": "isp", "value": tag},
                                                             {"tag": "alert", "value": "traffic-drop"}],
            "expression": f"{prev}>{{$ISP.DROP.MIN}} and avg({h}{key},5m)<{prev}*{{$ISP.DROP.PCT}}/100",
            "recovery_mode": 1,
            "recovery_expression": f"avg({h}{key},5m)>{prev}*({{$ISP.DROP.PCT}}+20)/100",
            "comments": "5-minute average traffic fell below {$ISP.DROP.PCT}% of the previous hour's average "
                        "while the link stayed up. Compare with the 'All ISPs' total: if the total also "
                        "dropped, the cause is the application/servers; if not, traffic moved between ISPs.",
        })

    for name, *_ in base.ISPS:
        drop(f"{name}: download traffic dropped sharply", f"isp.net.if.in[{name}]", 3, name)
        drop(f"{name}: upload traffic dropped sharply", f"isp.net.if.out[{name}]", 3, name)
    drop("All ISPs: total download dropped sharply", "isp.total.in", 4, "All")
    drop("All ISPs: total upload dropped sharply", "isp.total.out", 4, "All")
    triggers.append({"description": "A10: CPU high (busiest core over {$A10.CPU.HIGH}% for 5m)", "priority": 3,
                     "tags": tags, "expression": f"min({h}a10.cpu.util.max,5m)>{{$A10.CPU.HIGH}}"})
    triggers.append({"description": "A10: memory usage over {$A10.MEM.HIGH}%", "priority": 3, "tags": tags,
                     "expression": f"min({h}a10.mem.pused,5m)>{{$A10.MEM.HIGH}}"})

    new = [t for t in triggers if t["description"] not in have_triggers]
    if new:
        z.call("trigger.create", new)
    print(f"A10 health: {cpus} CPU cores + memory items ready; {len(new)} new triggers created.")


if __name__ == "__main__":
    main()
