#!/usr/bin/env python3
"""Independent self-healing watchdog for the monitoring server (cron every 2 min, /etc/cron.d/pi-netmon-watchdog).

systemd already restarts a crashed service (restart.conf drop-ins, Restart=on-failure, no start limit). This covers
what systemd cannot see, and e-mails directly through Office365 - not through Zabbix, which may be the broken part:
  - a core service stopped / failed            -> start it (mariadb before zabbix-server, never in one call)
  - zabbix-server running but collecting nothing (no new internal value for 10 min, seen on 2 runs) -> restart it
  - Zabbix web UI not answering (2 runs)        -> restart apache2
  - root disk > 90 % or clock not synchronised -> e-mail only
One e-mail when a problem starts (repeated at most every 6 h) and one when it clears. Nothing is restarted while
apt/dpkg is running or while /etc/pi-netmon-watchdog.disable exists (create it for planned maintenance).
Log: /var/log/zabbix/watchdog.log (only actions and problems). State: /var/lib/pi-netmon-watchdog/state.json
"""
import json
import os
import shutil
import smtplib
import socket
import subprocess
import time
import urllib.request
from email.message import EmailMessage

import setup_isp_links as base
import setup_email_alerts as mail

SERVICES = ["mariadb", "zabbix-server", "apache2", "zabbix-web-service", "zabbix-agent2"]   # start order
STATE = "/var/lib/pi-netmon-watchdog/state.json"
DISABLE_FLAG = "/etc/pi-netmon-watchdog.disable"
STALL_SECONDS = 600
DISK_MAX_PCT = 90
REMIND_SECONDS = 6 * 3600
WEB_URL = "http://127.0.0.1/zabbix/index.php"


def log(msg):
    print(time.strftime("%Y-%m-%d %H:%M:%S"), msg, flush=True)


def sh(*cmd, timeout=120):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def active(svc):
    return sh("systemctl", "is-active", svc).stdout.strip() == "active"


def apt_running():
    # dpkg locks only: unattended-upgrade-shutdown runs permanently and must not count as an upgrade
    return sh("pgrep", "-x", "apt|apt-get|dpkg").returncode == 0 or \
        sh("fuser", "/var/lib/dpkg/lock-frontend", "/var/lib/dpkg/lock").returncode == 0


def restart(svc, how="restart"):
    r = sh("systemctl", how, svc, timeout=600)
    log(f"{how} {svc}: {'OK' if r.returncode == 0 else 'FAILED ' + r.stderr.strip()}")
    return r.returncode == 0


def last_internal_value_age():
    """Seconds since the Zabbix server stored its own 'processed values per second' (internal item, every minute)."""
    q = ("SELECT UNIX_TIMESTAMP() - MAX(h.clock) FROM items i JOIN hosts ho ON ho.hostid = i.hostid "
         "JOIN history h ON h.itemid = i.itemid WHERE ho.host = 'Zabbix server' AND i.key_ = 'zabbix[wcache,values]' "
         "AND h.clock > UNIX_TIMESTAMP() - 86400")
    r = sh("mysql", "-N", "-B", "zabbix", "-e", q, timeout=60)
    v = r.stdout.strip()
    return None if r.returncode or v in ("", "NULL") else int(float(v))


def web_ok():
    try:
        with urllib.request.urlopen(WEB_URL, timeout=30) as resp:
            return resp.status == 200
    except Exception:
        return False


def send(subject, body):
    msg = EmailMessage()
    msg["From"], msg["To"] = mail.SENDER, ", ".join(mail.RECIPIENTS)
    msg["Subject"] = f"{mail.SUBJECT_PREFIX}Watchdog: {subject}"
    msg.set_content(body + f"\n\nHost {socket.gethostname()} (172.20.119.99), {time.strftime('%Y-%m-%d %H:%M:%S IST')}."
                           "\nWatchdog: /opt/isp/zabbix/watchdog.py, log /var/log/zabbix/watchdog.log")
    try:
        with smtplib.SMTP("smtp.office365.com", 587, timeout=60) as s:
            s.starttls()
            s.login(mail.SENDER, base.read(mail.PASSWORD_FILE))
            s.send_message(msg)
    except Exception as e:
        log(f"e-mail failed ({subject}): {e}")


def main():
    os.makedirs(os.path.dirname(STATE), exist_ok=True)
    try:
        st = json.load(open(STATE))
    except Exception:
        st = {}
    st.setdefault("strikes", {})
    st.setdefault("open", {})       # problem key -> {"since", "mailed", "text"}
    may_fix = not os.path.exists(DISABLE_FLAG) and not apt_running()
    problems = {}

    # 1. services that are not running at all
    for svc in SERVICES:
        if not active(svc):
            text = f"service {svc} was not running"
            if may_fix:
                if svc == "zabbix-server" and not active("mariadb"):
                    text += " (waiting for mariadb)"
                else:
                    restart(svc, "start")
                    text += " - started it" if active(svc) else " - START FAILED"
            if not active(svc):
                problems[f"svc:{svc}"] = text
            else:   # fixed on the spot: one information e-mail, no open problem
                log(text)
                send(f"started stopped service {svc}", f"The watchdog found {svc} not running and started it.")

    # 2. zabbix-server alive but not collecting
    if active("mariadb") and active("zabbix-server"):
        age = last_internal_value_age()
        if age is not None and age > STALL_SECONDS:
            st["strikes"]["stall"] = st["strikes"].get("stall", 0) + 1
            if st["strikes"]["stall"] >= 2:
                text = f"zabbix-server running but no new data for {age // 60} min"
                if may_fix:
                    restart("zabbix-server")
                    st["strikes"]["stall"] = 0
                    text += " - restarted it"
                problems["stall"] = text
        else:
            st["strikes"]["stall"] = 0

    # 3. web UI
    if active("apache2"):
        if web_ok():
            st["strikes"]["web"] = 0
        else:
            st["strikes"]["web"] = st["strikes"].get("web", 0) + 1
            if st["strikes"]["web"] >= 2:
                text = "Zabbix web UI not answering"
                if may_fix:
                    restart("apache2")
                    st["strikes"]["web"] = 0
                    text += " - restarted apache2" + (" (OK now)" if web_ok() else " (STILL DOWN)")
                problems["web"] = text

    # 4. warnings only
    du = shutil.disk_usage("/")
    pct = 100 * du.used / du.total
    if pct > DISK_MAX_PCT:
        problems["disk"] = f"root disk {pct:.0f}% full ({du.free / 1e9:.0f} GB free)"
    if "yes" not in sh("timedatectl", "show", "-p", "NTPSynchronized", "--value").stdout:
        st["strikes"]["ntp"] = st["strikes"].get("ntp", 0) + 1
        if st["strikes"]["ntp"] >= 15:   # ~30 min, so a short NTP hiccup is ignored
            problems["ntp"] = "system clock not synchronised to NTP (172.20.119.37 / .38)"
    else:
        st["strikes"]["ntp"] = 0

    now = time.time()
    for key, text in problems.items():
        o = st["open"].get(key)
        if o is None or now - o["mailed"] >= REMIND_SECONDS:
            log(f"PROBLEM {text}")
            send(f"PROBLEM: {text}", f"The watchdog detected: {text}." + ("" if may_fix else
                 "\nNo automatic fix attempted (maintenance flag or package upgrade running)."))
            st["open"][key] = {"since": (o or {}).get("since", now), "mailed": now, "text": text}
    for key in [k for k in st["open"] if k not in problems]:
        o = st["open"].pop(key)
        log(f"RESOLVED {o['text']}")
        send(f"RESOLVED: {o['text']}", f"Resolved after {int((now - o['since']) // 60)} min: {o['text']}.")

    json.dump(st, open(STATE + ".tmp", "w"))
    os.replace(STATE + ".tmp", STATE)


if __name__ == "__main__":
    main()
