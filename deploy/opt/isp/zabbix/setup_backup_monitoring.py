#!/usr/bin/env python3
"""Zabbix watches the nightly backup (/opt/isp/backup/backup.py, 21:00 IST).

Items on host "Zabbix server" (read by Zabbix agent 2 from /var/lib/pi-netmon-backup/status, no secrets there):
  Backup: last result       - "OK <time> ..." or "FAILED <time> <reason>"
  Backup: last success time - modification time of last-success
Triggers (High, so they are e-mailed by the "ISP link alerts" action, which includes the Zabbix server):
  Backup failed             - last result starts with FAILED
  No successful backup for 26 hours
Idempotent.
"""
import setup_isp_links as base

HOST = "Zabbix server"
STATUS = "/var/lib/pi-netmon-backup/status"
TAGS = [{"tag": "component", "value": "backup"}]


def main():
    z = base.Zabbix()
    h = z.call("host.get", {"filter": {"host": [HOST]}, "output": ["hostid"], "selectInterfaces": ["interfaceid", "type"]})[0]
    agent = next(i["interfaceid"] for i in h["interfaces"] if i["type"] == "1")
    items = {
        f"vfs.file.contents[{STATUS}/last-result]": dict(name="Backup: last result", value_type=4, delay="5m",
                                                          history="90d", trends="0"),
        f"vfs.file.time[{STATUS}/last-success,modify]": dict(name="Backup: last success time", value_type=3,
                                                              delay="5m", units="unixtime", history="90d"),
    }
    for key, kw in items.items():
        if not z.call("item.get", {"hostids": h["hostid"], "filter": {"key_": key}}):
            z.call("item.create", {"hostid": h["hostid"], "key_": key, "type": 0, "interfaceid": agent, "tags": TAGS,
                                   "description": "Nightly backup to GitHub, see /opt/isp/backup/README.md", **kw})
            print("item:", kw["name"])
    for desc, expr in (
            ("Backup failed (see /var/log/pi-netmon-backup.log)",
             f'find(/{HOST}/vfs.file.contents[{STATUS}/last-result],,"like","FAILED")=1'),
            ("No successful backup for 26 hours",
             f"now()-last(/{HOST}/vfs.file.time[{STATUS}/last-success,modify])>26h")):
        if not z.call("trigger.get", {"hostids": h["hostid"], "filter": {"description": desc}}):
            z.call("trigger.create", {"description": desc, "expression": expr, "priority": 4, "tags": TAGS,
                                      "comments": "Restore guide: RESTORE.md in git@github.com:Pi-DC/Pi-Network-Monitoring.git"})
            print("trigger:", desc)


if __name__ == "__main__":
    main()
