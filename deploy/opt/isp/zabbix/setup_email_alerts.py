#!/usr/bin/env python3
"""Email alerts for the A10-LLB host via Office 365.

- Enables Zabbix's built-in "Office365" media type with the alerts@ mailbox
  (password read from /root/.credentials/smtp_alerts_password).
- Gives the Admin user an email media for that address.
- Creates the "ISP link alerts" action: problems of severity Average or higher on A10-LLB, on the Zabbix server
  itself (caches, memory, disk) or on any host in
  any host in the switch/router groups (WAN Switches, PiSB Cloud Switches, WAN Routers, Pi VMware Fabric), plus recovery.
  Lower severities (packet loss / latency / 80% utilisation warnings) are left on the dashboards only,
  so Jio's ICMP rate-limiting doesn't flood the inbox.
Re-runnable.
"""
import setup_isp_links as base

SENDER = "alerts@pidatacenters.com"
RECIPIENTS = ["compute@pidatacenters.com", "network@pidatacenters.com"]
ACTION = "ISP link alerts"
MIN_SEVERITY = "3"   # 3 = Average; 4 = High; 5 = Disaster
SWITCH_GROUPS = ["WAN Switches", "PiSB Cloud Switches", "WAN Routers", "Pi VMware Fabric", "Pi MMR Cross Connect Fabric",
                 "Pi DH Cross Connect Fabric", "Pi 1G Colo Fabric"]
# The monitoring server itself: cache-usage / low-memory / VM memory and disk problems, so a full cache or memory
# shortage is mailed before it can crash Zabbix (added 2026-10-09).
SELF_HOST = "Zabbix server"


def main():
    z = base.Zabbix()
    mt = z.call("mediatype.get", {"filter": {"name": ["Office365"]}, "output": ["mediatypeid"]})[0]["mediatypeid"]
    z.call("mediatype.update", {"mediatypeid": mt, "status": 0, "smtp_email": SENDER, "username": SENDER,
                                "passwd": base.read("/root/.credentials/smtp_alerts_password"),
                                "smtp_authentication": 1, "smtp_verify_peer": 1, "smtp_verify_host": 1})

    admin = z.call("user.get", {"filter": {"username": ["Admin"]}, "selectMedias": "extend", "output": ["userid"]})[0]
    medias = [{k: v for k, v in md.items() if k in ("mediatypeid", "sendto", "active", "severity", "period")}
              for md in admin["medias"] if md["mediatypeid"] != mt]
    medias.append({"mediatypeid": mt, "sendto": RECIPIENTS, "active": 0, "severity": 63,
                   "period": "1-7,00:00-24:00"})
    z.call("user.update", {"userid": admin["userid"], "medias": medias})

    hostid = z.call("host.get", {"filter": {"host": [base.HOST]}})[0]["hostid"]
    switch_groups = [g["groupid"] for g in z.call("hostgroup.get", {"filter": {"name": SWITCH_GROUPS},
                                                                       "output": ["groupid"]})]
    letters = [c for c in "BDEFGHJKLMNOPQRSTUVWXYZ"]   # formula letters; A, C and I are taken
    assert len(switch_groups) <= len(letters), "too many groups for the formula letters"
    group_ids = letters[:len(switch_groups)]
    self_id = z.call("host.get", {"filter": {"host": [SELF_HOST]}})[0]["hostid"]
    params = {
        "name": ACTION, "eventsource": 0, "status": 0, "esc_period": "1h",
        # (host = A10-LLB or Zabbix server, or host group = any switch group) and severity >= Average
        "filter": {"evaltype": 3, "formula": f"(A or I or {' or '.join(group_ids)}) and C", "conditions": [
            {"conditiontype": 1, "operator": 0, "value": hostid, "formulaid": "A"},
            {"conditiontype": 1, "operator": 0, "value": self_id, "formulaid": "I"},
            *[{"conditiontype": 0, "operator": 0, "value": g, "formulaid": fid}
              for g, fid in zip(switch_groups, group_ids)],
            {"conditiontype": 4, "operator": 5, "value": MIN_SEVERITY, "formulaid": "C"}]},
        "operations": [{"operationtype": 0, "esc_step_from": 1, "esc_step_to": 1,
                        "opmessage": {"default_msg": 1, "mediatypeid": mt},
                        "opmessage_usr": [{"userid": admin["userid"]}]}],
        "recovery_operations": [{"operationtype": 11, "opmessage": {"default_msg": 1}}],
    }
    existing = z.call("action.get", {"filter": {"name": [ACTION]}, "output": ["actionid"]})
    if existing:
        params.pop("eventsource")
        z.call("action.update", {"actionid": existing[0]["actionid"], **params})
    else:
        z.call("action.create", params)
    print(f"Office365 media type {mt} enabled; Admin -> {', '.join(RECIPIENTS)}; action '{ACTION}' ready.")


if __name__ == "__main__":
    main()
