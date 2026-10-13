#!/usr/bin/env python3
"""Read-only Zabbix login for the monitoring team (added 2026-10-12, user request).

- User group MONITOR_GROUP: frontend access, READ on every host group (so every host, item, graph, problem and map
  is visible; nothing can be changed, acknowledged or closed). Built-in "User role" = Monitoring / Inventory /
  Reports menus only, no configuration or administration.
- User MONITOR_USER with an Office365 e-mail media to MONITOR_EMAIL, all severities. The alert actions
  (setup_email_alerts.py, add_ssl_monitoring.py) add this user to their recipients via alert_userids().
  Alerts only (user request 2026-10-13): daily PDF reports go to the Admin media (compute@ / network@), not here.
- Every dashboard is shared read-only with MONITOR_GROUP (they are private to Admin otherwise).
Password: generated once and kept in /root/.credentials/zabbix_pi_monitoring (never reset by re-runs).
Cron /etc/cron.d/zabbix-monitoring-user re-runs it hourly so new host groups and dashboards are covered.
Idempotent; prints only what it changed.
"""
import os
import secrets

import setup_isp_links as base

MONITOR_USER = "Pi-Monitoring"
MONITOR_NAME = "Pi Monitoring team"
MONITOR_EMAIL = "monitoring@pidatacenters.com"
MONITOR_GROUP = "Pi Monitoring (read-only)"
PASSWORD_FILE = "/root/.credentials/zabbix_pi_monitoring"
USER_ROLE = "User role"
READ = 2


def alert_userids(z):
    """Extra recipients for every alert action: the monitoring user, when it exists."""
    return [u["userid"] for u in z.call("user.get", {"filter": {"username": [MONITOR_USER]}, "output": ["userid"]})]


def password():
    if not os.path.exists(PASSWORD_FILE):
        pw = secrets.token_urlsafe(12) + "aA1!"
        fd = os.open(PASSWORD_FILE, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(pw + "\n")
    return base.read(PASSWORD_FILE)


def main():
    z = base.Zabbix()
    changed = []
    rights = [{"id": g["groupid"], "permission": READ} for g in z.call("hostgroup.get", {"output": ["groupid"]})]
    ug = z.call("usergroup.get", {"filter": {"name": [MONITOR_GROUP]}, "output": ["usrgrpid"],
                                  "selectHostGroupRights": "extend"})
    if not ug:
        ugid = z.call("usergroup.create", {"name": MONITOR_GROUP, "gui_access": 0,
                                           "hostgroup_rights": rights})["usrgrpids"][0]
        changed.append(f"user group '{MONITOR_GROUP}' created, read on {len(rights)} host groups")
    else:
        ugid = ug[0]["usrgrpid"]
        have = {(r["id"], r["permission"]) for r in ug[0]["hostgroup_rights"]}
        if have != {(r["id"], str(r["permission"])) for r in rights}:
            z.call("usergroup.update", {"usrgrpid": ugid, "hostgroup_rights": rights})
            changed.append(f"read rights now on {len(rights)} host groups")

    mt = z.call("mediatype.get", {"filter": {"name": ["Office365"]}, "output": ["mediatypeid"]})[0]["mediatypeid"]
    media = [{"mediatypeid": mt, "sendto": [MONITOR_EMAIL], "active": 0, "severity": 63, "period": "1-7,00:00-24:00"}]
    roleid = z.call("role.get", {"filter": {"name": [USER_ROLE]}, "output": ["roleid"]})[0]["roleid"]
    user = z.call("user.get", {"filter": {"username": [MONITOR_USER]}, "output": ["userid", "roleid"],
                               "selectUsrgrps": ["usrgrpid"], "selectMedias": ["mediatypeid", "sendto", "active"]})
    if not user:
        z.call("user.create", {"username": MONITOR_USER, "name": MONITOR_NAME, "roleid": roleid, "passwd": password(),
                               "usrgrps": [{"usrgrpid": ugid}], "medias": media})
        changed.append(f"user '{MONITOR_USER}' created ({MONITOR_EMAIL})")
    else:
        u = user[0]
        if (u["roleid"] != roleid or [g["usrgrpid"] for g in u["usrgrps"]] != [ugid]
                or [(m["mediatypeid"], m["sendto"], m["active"]) for m in u["medias"]] != [(mt, [MONITOR_EMAIL], "0")]):
            z.call("user.update", {"userid": u["userid"], "roleid": roleid, "usrgrps": [{"usrgrpid": ugid}],
                                   "medias": media})
            changed.append(f"user '{MONITOR_USER}' role / group / e-mail restored")

    for d in z.call("dashboard.get", {"output": ["dashboardid", "name", "private"], "selectUserGroups": "extend"}):
        if d["private"] == "0" or any(g["usrgrpid"] == ugid for g in d["userGroups"]):
            continue
        groups = [{"usrgrpid": g["usrgrpid"], "permission": int(g["permission"])} for g in d["userGroups"]]
        z.call("dashboard.update", {"dashboardid": d["dashboardid"],
                                    "userGroups": groups + [{"usrgrpid": ugid, "permission": READ}]})
        changed.append(f"dashboard '{d['name']}' shared")
    for c in changed:
        print(c)


if __name__ == "__main__":
    main()
