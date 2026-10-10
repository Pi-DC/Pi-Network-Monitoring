#!/usr/bin/env python3
"""Daily PDF e-mail per Zabbix dashboard WITH every port and every item (replaces Zabbix's native scheduled reports).

Zabbix scheduled reports print a dashboard only as it looks on screen, so item navigators / port maps are cut off and
there is no chart per port or per item. This script e-mails instead, for every dashboard, the /reports "Dashboard PDF"
with "all ports, plus all items" (daily_pdf.php): each dashboard page followed by one panel per port (traffic in/out,
errors/discards, speed, % up, state) and one chart per item, for the previous day 00:00-24:00 IST.

Cron /etc/cron.d/zabbix-daily-reports runs it at 08:00 IST, log /var/log/zabbix/daily-reports.log. New dashboards are
picked up automatically; recipients = the Admin user's Office365 media (compute@ / network@). The matching native
"Daily: <dashboard>" Zabbix reports are kept disabled by sync_daily_reports.py so nobody gets two e-mails.

  send_daily_reports.py                    send all dashboards for yesterday
  send_daily_reports.py --only "ASR Routers" --to someone@pidatacenters.com --date 2026-10-09
  send_daily_reports.py --dry-run          build the PDFs (sizes, timings) without sending
"""
import argparse
import datetime as dt
import os
import smtplib
import subprocess
import sys
import tempfile
import time
from email.message import EmailMessage

import setup_isp_links as base
import setup_email_alerts as mail

PHP_CLI = os.path.join(os.path.dirname(os.path.abspath(__file__)), "daily_pdf.php")
MAX_ATTACH = 20 * 1024 * 1024   # Office365 caps a message at ~35 MB after base64 (+33%); fall back above this
SMTP_HOST, SMTP_PORT = "smtp.office365.com", 587


def log(msg):
    print(time.strftime("%Y-%m-%d %H:%M:%S"), msg, flush=True)


def build_pdf(dashid, day, mode, path):
    start = dt.datetime.combine(day, dt.time())
    end = start + dt.timedelta(days=1)
    subprocess.run(["php", PHP_CLI, str(dashid), start.strftime("%Y-%m-%dT%H:%M"), end.strftime("%Y-%m-%dT%H:%M"), path, mode],
                   check=True, capture_output=True, text=True, timeout=1800)
    return os.path.getsize(path)


def send(recipients, subject, body, pdf_path, filename):
    msg = EmailMessage()
    msg["From"], msg["To"], msg["Subject"] = mail.SENDER, ", ".join(recipients), subject
    msg.set_content(body)
    with open(pdf_path, "rb") as f:
        msg.add_attachment(f.read(), maintype="application", subtype="pdf", filename=filename)
    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=120) as s:
        s.starttls()
        s.login(mail.SENDER, base.read("/root/.credentials/smtp_alerts_password"))
        s.send_message(msg)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--date", help="report day YYYY-MM-DD (default yesterday, IST)")
    ap.add_argument("--only", action="append", help="dashboard name (repeatable)")
    ap.add_argument("--to", action="append", help="override recipients (repeatable)")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()
    day = dt.date.fromisoformat(a.date) if a.date else dt.date.today() - dt.timedelta(days=1)

    z = base.Zabbix()
    admin = z.call("user.get", {"filter": {"username": ["Admin"]}, "selectMedias": "extend", "output": ["userid"]})[0]
    mt = z.call("mediatype.get", {"filter": {"name": ["Office365"]}, "output": ["mediatypeid"]})[0]["mediatypeid"]
    recipients = a.to or sorted({r for m in admin["medias"] if m["mediatypeid"] == mt and m["active"] == "0" for r in m["sendto"]})
    dashboards = sorted(z.call("dashboard.get", {"output": ["dashboardid", "name"]}), key=lambda d: d["name"])
    if a.only:
        dashboards = [d for d in dashboards if d["name"] in a.only]
    if not dashboards or not recipients:
        sys.exit("no dashboards or no recipients")

    failed = []
    label = day.strftime("%d %b %Y")
    for d in dashboards:
        name = d["name"]
        fname = "".join(c if c.isalnum() else "-" for c in name).strip("-") + f"-{day:%Y%m%d}.pdf"
        with tempfile.TemporaryDirectory(prefix="daily-report-") as tmp:
            path = os.path.join(tmp, fname)
            t0 = time.time()
            try:
                note = "every port and every item"
                size = build_pdf(d["dashboardid"], day, "all", path)
                if size > MAX_ATTACH:   # too big for e-mail: leave out ports that carried no traffic that day
                    log(f"{name}: all ports = {size / 1e6:.1f} MB, too big; retrying with active ports only")
                    size = build_pdf(d["dashboardid"], day, "active", path)
                    note = "every port that carried traffic and every item (all ports would exceed the e-mail size limit)"
                if size > MAX_ATTACH:
                    raise RuntimeError(f"PDF is {size / 1e6:.1f} MB even with active ports only")
                body = (f'Attached: Zabbix dashboard "{name}" for {label} (00:00-24:00 IST).\n\n'
                        f"Each dashboard page is followed by charts for {note}: traffic in/out, errors/discards, "
                        "speed and time up per port, and min/avg/max per item.\n\n"
                        "Live view: https://isp.picloud.in/zabbix/ - on-demand reports: https://isp.picloud.in/reports/")
                if not a.dry_run:
                    send(recipients, f"Daily report: {name} ({label})", body, path, fname)
                log(f"{name}: {'built' if a.dry_run else 'sent'} {size / 1e6:.1f} MB in {time.time() - t0:.0f}s"
                    + ("" if a.dry_run else f" to {', '.join(recipients)}"))
            except subprocess.CalledProcessError as e:
                failed.append(name)
                log(f"{name}: FAILED building PDF: {(e.stderr or e.stdout).strip()[-500:]}")
            except Exception as e:
                failed.append(name)
                log(f"{name}: FAILED: {e}")
    if failed:
        sys.exit(f"failed: {failed}")


if __name__ == "__main__":
    main()
