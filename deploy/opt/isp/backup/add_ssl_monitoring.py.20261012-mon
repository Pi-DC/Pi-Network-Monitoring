#!/usr/bin/env python3
"""Watch the https://isp.picloud.in certificate and email before it expires.

Renewal of this Let's Encrypt certificate needs a TXT value entered by hand on Windows DNS, so this is the
safety net: Zabbix agent 2 reads the served certificate hourly and alerts at < 21 days or if it isn't valid.
Idempotent.
"""
import setup_isp_links as base

DOMAIN = "isp.picloud.in"
HOST = "Zabbix server"           # has the local agent 2 interface
WARN_DAYS = 21
ACTION = "SSL certificate alerts"


def main():
    z = base.Zabbix()
    host = z.call("host.get", {"filter": {"host": [HOST]}, "selectInterfaces": ["interfaceid", "type"]})[0]
    hostid = host["hostid"]
    agent_if = next(i["interfaceid"] for i in host["interfaces"] if i["type"] == "1")
    have = {i["key_"]: i["itemid"] for i in z.call("item.get", {"hostids": hostid, "output": ["key_"]})}
    tags = [{"tag": "component", "value": "ssl"}, {"tag": "domain", "value": DOMAIN}]
    master_key = f"web.certificate.get[{DOMAIN},443]"
    if master_key not in have:
        have[master_key] = z.call("item.create", {
            "hostid": hostid, "interfaceid": agent_if, "type": 0, "key_": master_key, "value_type": 4,
            "name": f"SSL {DOMAIN}: certificate details", "delay": "1h", "history": "30d", "trends": "0",
            "tags": tags})["itemids"][0]
    deps = [
        ("ssl.cert.days_left", f"SSL {DOMAIN}: days until expiry", 0, "d",
         [(12, "$.x509.not_after.timestamp"), (21, "return Math.floor((value - Date.now() / 1000) / 86400);")]),
        ("ssl.cert.validity", f"SSL {DOMAIN}: validation result", 4, "", [(12, "$.result.value")]),
        ("ssl.cert.issuer", f"SSL {DOMAIN}: issuer", 4, "", [(12, "$.x509.issuer")]),
    ]
    for key, name, vtype, units, steps in deps:
        if key not in have:
            have[key] = z.call("item.create", {
                "hostid": hostid, "type": 18, "master_itemid": have[master_key], "key_": key, "name": name,
                "value_type": vtype, "units": units, "history": "90d", "trends": "0" if vtype == 4 else "365d",
                "tags": tags, "preprocessing": base.pp(*steps)})["itemids"][0]

    h = f"/{HOST}/"
    have_t = {t["description"] for t in z.call("trigger.get", {"hostids": hostid, "output": ["description"]})}
    triggers = [
        {"description": f"SSL {DOMAIN}: certificate expires in under {WARN_DAYS} days", "priority": 4, "tags": tags,
         "expression": f"last({h}ssl.cert.days_left)<{WARN_DAYS}",
         "comments": "Renewal is automatic (certbot timer -> acme-dns, via the CNAME _acme-challenge.isp.picloud.in -> 32827435-857f-43e8-a058-5c34e61f4ee0.auth.acme-dns.io). If this fires, check `certbot renew --dry-run` and /var/log/letsencrypt/letsencrypt.log; if acme-dns failed, the hook emailed a TXT value to set by hand."},
        {"description": f"SSL {DOMAIN}: certificate is not valid", "priority": 4, "tags": tags,
         "expression": f'last({h}ssl.cert.validity)<>"valid"'},
    ]
    new = [t for t in triggers if t["description"] not in have_t]
    if new:
        z.call("trigger.create", new)

    mt = z.call("mediatype.get", {"filter": {"name": ["Office365"]}, "output": ["mediatypeid"]})[0]["mediatypeid"]
    admin = z.call("user.get", {"filter": {"username": ["Admin"]}, "output": ["userid"]})[0]["userid"]
    params = {
        "name": ACTION, "eventsource": 0, "status": 0, "esc_period": "1h",
        "filter": {"evaltype": 1, "conditions": [
            {"conditiontype": 1, "operator": 0, "value": hostid},
            {"conditiontype": 26, "operator": 0, "value": "component", "value2": "ssl"}]},
        "operations": [{"operationtype": 0, "esc_step_from": 1, "esc_step_to": 1,
                        "opmessage": {"default_msg": 1, "mediatypeid": mt}, "opmessage_usr": [{"userid": admin}]}],
        "recovery_operations": [{"operationtype": 11, "opmessage": {"default_msg": 1}}],
    }
    existing = z.call("action.get", {"filter": {"name": [ACTION]}, "output": ["actionid"]})
    if existing:
        params.pop("eventsource")
        z.call("action.update", {"actionid": existing[0]["actionid"], **params})
    else:
        z.call("action.create", params)
    print(f"SSL monitoring for {DOMAIN} ready ({len(new)} new triggers); alerts emailed via '{ACTION}'.")


if __name__ == "__main__":
    main()
