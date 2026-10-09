#!/usr/bin/env python3
"""Daily PDF report e-mail for every Zabbix dashboard (Zabbix scheduled reports, rendered by zabbix-web-service).

One report per dashboard, named "Daily: <dashboard>", previous day (00:00-24:00 IST), sent at 08:00 IST to the
Admin user's Office365 media (compute@ / network@). Run from cron every hour (/etc/cron.d/zabbix-daily-reports):
  - a new dashboard gets its report automatically
  - a renamed dashboard gets its report renamed
  - reports of deleted dashboards are removed (Zabbix also drops them with the dashboard)
Every dashboard gets its own "Daily:" report (one e-mail per dashboard) by default, even if someone also created a
report for it by hand; hand-made reports are never changed or deleted by this script.
"""
import setup_isp_links as base

PREFIX = "Daily: "
START_TIME = 8 * 3600     # 08:00 in the report owner's (Admin = server) time zone, IST
PERIOD_PREVIOUS_DAY, CYCLE_DAILY = 0, 0


def main():
    z = base.Zabbix()
    admin = z.call("user.get", {"filter": {"username": ["Admin"]}, "output": ["userid"]})[0]["userid"]
    dashboards = {d["dashboardid"]: d["name"] for d in z.call("dashboard.get", {"output": ["dashboardid", "name"]})}
    reports = z.call("report.get", {"output": ["reportid", "name", "dashboardid", "subject"]})
    ours = {r["dashboardid"]: r for r in reports if r["name"].startswith(PREFIX)}

    created, renamed = [], []
    for did, name in sorted(dashboards.items(), key=lambda x: x[1]):
        params = {"name": (PREFIX + name)[:255], "subject": f"Daily report: {name} (previous day)",
                  "message": f'Attached: Zabbix dashboard "{name}" for the previous day (00:00-24:00 IST).\n'
                             "Live view: https://isp.picloud.in/zabbix/ - on-demand reports: https://isp.picloud.in/reports/"}
        if did not in ours:
            z.call("report.create", {**params, "userid": admin, "dashboardid": did, "period": PERIOD_PREVIOUS_DAY,
                                     "cycle": CYCLE_DAILY, "start_time": START_TIME, "status": 0,
                                     "users": [{"userid": admin, "access_userid": admin, "exclude": 0}]})
            created.append(name)
        elif ours[did]["name"] != params["name"]:
            z.call("report.update", {"reportid": ours[did]["reportid"], **params})
            renamed.append(name)
    stale = [r["reportid"] for did, r in ours.items() if did not in dashboards]
    if stale:
        z.call("report.delete", stale)
    if created or renamed or stale:
        print(f"created {created}; renamed {renamed}; removed {len(stale)}")


if __name__ == "__main__":
    main()
