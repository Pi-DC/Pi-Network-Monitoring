#!/usr/bin/env python3
"""Alerts for monitored states that had none (fleet audit 2026-10-15, user: "add an alert for every thing").
Idempotent: creates missing trigger prototypes only. Everything is >= Warning, so 'ISP link alerts' e-mails it.

The rest of that audit lives elsewhere:
  - reboot alert on every SNMP vendor template: device_uptime.restart_trigger (runs hourly with --setup)
  - FortiGate power supply missing / failed: add_firewall_detail.sensor_health

Temperature sensor state (the temperature value itself already alerts on its thresholds, but a dead sensor
silently stops reporting):
  - Arista ENTITY-SENSOR-MIB entPhySensorOperStatus: 1 ok, 2 unavailable, 3 nonoperational. Only 3 alerts -
    'unavailable' is normal for ~80 transceiver / unused slots.
  - Cisco Catalyst ciscoEnvMonTemperatureState: 1 normal, 2 warning, 3 critical, 4 shutdown, 5 notPresent,
    6 notFunctioning.
"""
import setup_isp_links as base

TAGS = [{"tag": "component", "value": "temperature"}]
PROTOS = [   # template, discovery rule key, description, expression (with {T} = template), priority
    ("Arista by SNMP - PIDC", "temp.discovery", "{#SENSOR_INFO}: temperature sensor is not operational",
     "last(/{T}/sensor.temp.status[entPhySensorOperStatus.{#SNMPINDEX}])=3", 2),
    ("Cisco Catalyst by SNMP - PIDC", "temperature.discovery", "{#SNMPVALUE}: temperature state is WARNING",
     "last(/{T}/sensor.temp.status[ciscoEnvMonTemperatureState.{#SNMPINDEX}])=2", 2),
    ("Cisco Catalyst by SNMP - PIDC", "temperature.discovery",
     "{#SNMPVALUE}: temperature state is {ITEM.LASTVALUE1} (critical / shutdown / sensor not functioning)",
     "last(/{T}/sensor.temp.status[ciscoEnvMonTemperatureState.{#SNMPINDEX}])=3 or "
     "last(/{T}/sensor.temp.status[ciscoEnvMonTemperatureState.{#SNMPINDEX}])=4 or "
     "last(/{T}/sensor.temp.status[ciscoEnvMonTemperatureState.{#SNMPINDEX}])=6", 4),
]


def main():
    z = base.Zabbix()
    for template, rule_key, description, expression, priority in PROTOS:
        tid = z.call("template.get", {"filter": {"host": [template]}, "output": ["templateid"]})[0]["templateid"]
        rule = z.call("discoveryrule.get", {"templateids": tid, "filter": {"key_": rule_key}, "output": ["itemid"],
                                            "inherited": False})[0]["itemid"]
        have = {t["description"] for t in z.call("triggerprototype.get", {"discoveryids": rule, "output": ["description"]})}
        if description in have:
            continue
        z.call("triggerprototype.create", {"description": description, "expression": expression.replace("{T}", template),
                                           "priority": priority, "manual_close": 1, "tags": TAGS})
        print(f"{template}: + {description}")


if __name__ == "__main__":
    main()
