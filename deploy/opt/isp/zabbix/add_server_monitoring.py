#!/usr/bin/env python3
"""Full monitoring of the monitoring server itself (Zabbix host "Zabbix server", 172.20.119.99). Idempotent.

On top of "Linux by Zabbix agent" + "Zabbix server health" (+ SSL / backup items from their own scripts):
  MariaDB     "MySQL by Zabbix agent 2" (read-only local user zbx_monitor, password /root/.credentials/
              zabbix_mysql_monitor) + size of the big Zabbix tables (history*, trends*, events, alerts, auditlog)
  Apache      "Apache by Zabbix agent" (mod_status on http://127.0.0.1/server-status, local only)
  Services    "Systemd by Zabbix agent 2", limited to the services this tool needs (SERVICES)
  Web UI      web scenario: Zabbix login page, /reports, SmokePing (expects its 401 login prompt)
  Cron jobs   every job in /etc/cron.d/zabbix-* and pi-netmon-watchdog runs through cron_run.py, which records
              exit code / duration / end time; alerts when a job fails or stops running (backup has its own items)
  E-mail      alerts that failed to send or are stuck unsent; SMTP server smtp.office365.com:587 reachable
  Time        NTP synchronised, both NTP servers answering
  OS          reboot required, pending (security) updates, watchdog paused (/etc/pi-netmon-watchdog.disable)
Dashboard "Monitoring Server" (build_dashboard()). Re-run after adding a cron job.
"""
import glob
import os
import re
import secrets
import subprocess

import build_dashboard as d
import build_switch_dashboard as sw
import click_to_graph
import coverage_pages as cp
import setup_isp_links as base

HOST = "Zabbix server"
DASHBOARD = "Monitoring Server"
MYSQL_USER = "zbx_monitor"
MYSQL_PW_FILE = "/root/.credentials/zabbix_mysql_monitor"
MYSQL_CNF = "/etc/zabbix/pidc-mysql-monitor.cnf"
AGENT_CONF = "/etc/zabbix/zabbix_agent2.d/pidc-server.conf"
CRON_FILES = sorted(glob.glob("/etc/cron.d/zabbix-*")) + ["/etc/cron.d/pi-netmon-watchdog"]
CRON_STATUS = "/var/lib/pi-netmon/cron"
TEMPLATES = ["MySQL by Zabbix agent 2", "Apache by Zabbix agent", "Systemd by Zabbix agent 2"]
SERVICES = ["zabbix-server", "zabbix-agent2", "zabbix-web-service", "mariadb", "apache2", "smokeping", "cron",
            "systemd-timesyncd", "rsyslog", "ssh"]
TABLES = ["history", "history_uint", "history_str", "history_text", "history_log", "trends", "trends_uint",
          "events", "event_recovery", "problem", "alerts", "auditlog"]
NTP_SERVERS = ["172.20.119.37", "172.20.119.38"]
WEB = "Zabbix web UI"
WEB_STEPS = [("Zabbix login page", "https://isp.picloud.in/zabbix/index.php", "200", "Zabbix"),
             ("Reports login page", "https://isp.picloud.in/reports/", "200", "Reports"),
             ("SmokePing (login prompt)", "https://isp.picloud.in/smokeping/", "401", "")]
AGENT, SIMPLE, DEPENDENT, CALCULATED = 0, 3, 18, 15
FLOAT, CHAR, UINT, TEXT = 0, 1, 3, 4
JSONPATH, REGEX, JS, DISCARD, DISCARD_HB = 12, 5, 21, 19, 20
AVG, WARN, INFO, HIGH = 3, 2, 1, 4

USER_PARAMETERS = f"""# Managed by /opt/isp/zabbix/add_server_monitoring.py - local checks of the monitoring server itself.
UserParameter=pidc.ntp.synced,timedatectl show -p NTPSynchronized --value
UserParameter=pidc.apt.updates,/usr/lib/update-notifier/apt-check 2>&1
UserParameter=pidc.db.tables,mysql --defaults-file={MYSQL_CNF} -N -B -e "SELECT JSON_OBJECTAGG(table_name, data_length + index_length) FROM information_schema.tables WHERE table_schema = 'zabbix' AND table_name IN ({", ".join(f"'{t}'" for t in TABLES)})"
UserParameter=pidc.alerts,mysql --defaults-file={MYSQL_CNF} -N -B -e "SELECT JSON_OBJECT('failed', COALESCE(SUM(status = 2 AND clock > UNIX_TIMESTAMP() - 3600), 0), 'stuck', COALESCE(SUM(status IN (0, 3) AND clock < UNIX_TIMESTAMP() - 600), 0), 'sent', COALESCE(SUM(status = 1 AND clock > UNIX_TIMESTAMP() - 3600), 0)) FROM zabbix.alerts WHERE clock > UNIX_TIMESTAMP() - 86400 AND alerttype = 0"
"""


# ======================================================================================= system side
def sh(cmd, inp=None):
    return subprocess.run(cmd, input=inp, text=True, check=True, capture_output=True).stdout


def mysql_monitor_user():
    if not os.path.exists(MYSQL_PW_FILE):
        with open(os.open(MYSQL_PW_FILE, os.O_WRONLY | os.O_CREAT, 0o600), "w") as fh:
            fh.write(secrets.token_urlsafe(24))
    pw = open(MYSQL_PW_FILE).read().strip()
    grants = "".join(f"GRANT SELECT ON zabbix.{t} TO '{MYSQL_USER}'@'localhost';\n" for t in TABLES)
    sh(["mysql"], f"""CREATE USER IF NOT EXISTS '{MYSQL_USER}'@'localhost' IDENTIFIED BY '{pw}';
ALTER USER '{MYSQL_USER}'@'localhost' IDENTIFIED BY '{pw}';
GRANT USAGE, REPLICATION CLIENT, SLAVE MONITOR, PROCESS, SHOW DATABASES, SHOW VIEW ON *.* TO '{MYSQL_USER}'@'localhost';
{grants}FLUSH PRIVILEGES;
""")
    with open(os.open(MYSQL_CNF, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o640), "w") as fh:
        fh.write(f"[client]\nuser={MYSQL_USER}\npassword={pw}\nhost=localhost\n")
    os.chmod(MYSQL_CNF, 0o640)
    os.chown(MYSQL_CNF, 0, int(sh(["getent", "group", "zabbix"]).split(":")[2]))
    return pw


def agent_conf():
    old = open(AGENT_CONF).read() if os.path.exists(AGENT_CONF) else ""
    if old != USER_PARAMETERS:
        with open(AGENT_CONF, "w") as fh:
            fh.write(USER_PARAMETERS)
        sh(["systemctl", "restart", "zabbix-agent2"])


def interval(spec):
    """Seconds between runs for the simple cron schedules used here."""
    minute, hour = spec.split()[:2]
    if hour != "*":
        return 86400
    if minute == "*":
        return 60
    if minute.startswith("*/"):
        return int(minute[2:]) * 60
    return 3600


def cron_jobs():
    """Route every enabled job through cron_run.py; returns [(job, seconds between runs)]."""
    jobs = []
    for path in CRON_FILES:
        lines, changed = open(path).read().split("\n"), False
        for n, line in enumerate(lines):
            if not line.strip() or line.lstrip().startswith("#") or "cd /opt/isp/zabbix && " not in line:
                continue
            m = re.search(r"cron_run\.py (\S+) -- ", line)
            if m:
                name = m.group(1)
            else:
                script = re.search(r"python3 (\w+)\.py( --\w+)?", line)
                name = script.group(1) + (script.group(2).replace(" --", "_") if script.group(2) else "")
                lines[n] = line.replace("cd /opt/isp/zabbix && ",
                                        f"cd /opt/isp/zabbix && /usr/bin/python3 cron_run.py {name} -- ", 1)
                changed = True
            jobs.append((name, interval(" ".join(line.split()[:5]))))
        if changed:
            with open(path, "w") as fh:
                fh.write("\n".join(lines))
    os.makedirs(CRON_STATUS, mode=0o755, exist_ok=True)
    return jobs


# ======================================================================================= Zabbix side
class Host:
    def __init__(self, z):
        self.z = z
        h = z.call("host.get", {"filter": {"host": [HOST]}, "output": ["hostid"], "selectInterfaces": ["interfaceid", "type"],
                                "selectParentTemplates": ["host"]})[0]
        self.hid = h["hostid"]
        self.ifid = next(i["interfaceid"] for i in h["interfaces"] if i["type"] == "1")
        self.templates = {t["host"] for t in h["parentTemplates"]}
        self.items = {i["key_"]: i["itemid"] for i in z.call("item.get", {"hostids": self.hid, "output": ["key_"]})}
        self.triggers = {t["description"] for t in z.call("trigger.get", {"hostids": self.hid, "output": ["description"]})}
        self.n = {"items": 0, "triggers": 0}

    def item(self, key, name, **kw):
        if key in self.items:
            return self.items[key]
        kw.setdefault("value_type", UINT)
        kw.setdefault("history", "90d")
        kw.setdefault("trends", "730d" if kw["value_type"] in (FLOAT, UINT) else "0")
        if kw.get("type", AGENT) in (AGENT, SIMPLE):
            kw.setdefault("interfaceid", self.ifid)
        kw.setdefault("type", AGENT)
        self.items[key] = self.z.call("item.create", {"hostid": self.hid, "key_": key, "name": name, **kw})["itemids"][0]
        self.n["items"] += 1
        return self.items[key]

    def dep(self, master, key, name, steps, **kw):
        return self.item(key, name, type=DEPENDENT, master_itemid=master, preprocessing=base.pp(*steps), **kw)

    def trigger(self, description, expression, priority, component, comments="", **kw):
        if description in self.triggers:
            return
        self.z.call("trigger.create", {"description": description, "expression": expression, "priority": priority,
                                       "comments": comments, "tags": [{"tag": "component", "value": component}], **kw})
        self.triggers.add(description)
        self.n["triggers"] += 1

    def macro(self, macro, value, secret=False, description=""):
        have = {m["macro"]: m for m in self.z.call("usermacro.get", {"hostids": self.hid, "output": ["macro", "value", "type"]})}
        params = {"macro": macro, "value": value, "type": 1 if secret else 0, "description": description}
        if macro not in have:
            self.z.call("usermacro.create", {"hostid": self.hid, **params})
        elif secret or have[macro]["value"] != value:
            self.z.call("usermacro.update", {"hostmacroid": have[macro]["hostmacroid"], **params})

    def k(self, key):
        return f"/{HOST}/{key}"


def tag(component):
    return [{"tag": "component", "value": component}]


def setup_zabbix(z, mysql_pw, jobs):
    h = Host(z)
    # ---- stock templates
    missing = [t for t in TEMPLATES if t not in h.templates]
    if missing:
        tids = [t["templateid"] for t in z.call("template.get", {"filter": {"host": missing}, "output": ["templateid"]})]
        z.call("host.massadd", {"hosts": [{"hostid": h.hid}], "templates": [{"templateid": t} for t in tids]})
    h.macro("{$MYSQL.DSN}", "tcp://localhost:3306")
    h.macro("{$MYSQL.USER}", MYSQL_USER)
    h.macro("{$MYSQL.PASSWORD}", mysql_pw, secret=True, description="see " + MYSQL_PW_FILE)
    h.macro("{$SYSTEMD.NAME.SERVICE.MATCHES}", "^(" + "|".join(re.escape(s) for s in SERVICES) + r")\.service$",
            description="services this monitoring tool depends on")
    h.macro("{$SYSTEMD.NAME.SOCKET.MATCHES}", "^$", description="sockets not monitored")

    # ---- time
    ntp = h.item("pidc.ntp.synced", "NTP: clock synchronised", value_type=UINT, delay="1m", trends="0",
                 preprocessing=base.pp((JS, "return value.trim() === 'yes' ? 1 : 0;")), tags=tag("ntp"),
                 valuemapid=valuemap(z, h.hid, "PIDC yes/no", [(0, "no"), (1, "yes")]))
    h.trigger("Server clock not synchronised to NTP for 15 min", f"max({h.k('pidc.ntp.synced')},15m)=0", AVG, "ntp",
              "Alert, graph and report times drift. Check systemd-timesyncd and the NTP servers " + ", ".join(NTP_SERVERS) + ".")
    for ip in NTP_SERVERS:
        key = f"net.udp.service[ntp,{ip},123]"
        h.item(key, f"NTP server {ip}: answering", type=SIMPLE, delay="5m", trends="0", tags=tag("ntp"))
    h.trigger("Neither NTP server answers", " and ".join(f"max({h.k(f'net.udp.service[ntp,{ip},123]')},15m)=0"
                                                    for ip in NTP_SERVERS), AVG, "ntp")

    # ---- OS
    h.item("vfs.file.exists[/var/run/reboot-required]", "OS: reboot required (updates installed)", delay="15m",
           trends="0", tags=tag("os"))
    h.trigger("Server needs a reboot to finish installing updates",
              f"last({h.k('vfs.file.exists[/var/run/reboot-required]')})=1", INFO, "os")
    apt = h.item("pidc.apt.updates", "OS: apt-check raw", value_type=TEXT, delay="1h", timeout="60s", history="1d",
                 tags=tag("os"))
    h.dep(apt, "pidc.apt.pending", "OS: updates pending", [(REGEX, r"^(\d+);\d+" + "\n\\1")], tags=tag("os"))
    h.dep(apt, "pidc.apt.security", "OS: security updates pending", [(REGEX, r"^\d+;(\d+)" + "\n\\1")], tags=tag("os"))
    h.trigger("Security updates pending for 3 days ({ITEM.LASTVALUE})", f"min({h.k('pidc.apt.security')},3d)>0", WARN, "os")
    # The stock 'High swap space usage' (<50 % free) is only a Warning, so it did not e-mail on 2026-10-13: a PDF
    # render filled RAM + swap at 22:20, MariaDB stalled from 23:40 and cron jobs failed until a reboot at 00:26.
    h.trigger("Swap almost full ({ITEM.LASTVALUE} free) - server running out of memory",
              f"max({h.k('system.swap.size[,pfree]')},5m)<10 and last({h.k('system.swap.size[,total]')})>0", HIGH, "memory",
              "RAM and swap are nearly used up: the database will stall and cron jobs / alerts start failing. Find the "
              "process holding memory (ps -eo pid,rss,etime,cmd --sort=-rss | head) and stop it before it gets worse.")
    h.trigger("Available memory below 10% for 10 min ({ITEM.LASTVALUE})",
              f"max({h.k('vm.memory.size[pavailable]')},10m)<10", HIGH, "memory",
              "Less than 10 % of RAM is available (free + reclaimable cache). Find the process holding memory "
              "(ps -eo pid,rss,etime,cmd --sort=-rss | head).")
    h.item("vfs.file.exists[/etc/pi-netmon-watchdog.disable]", "Watchdog paused (/etc/pi-netmon-watchdog.disable)",
           delay="5m", trends="0", tags=tag("cron"))
    h.trigger("Self-healing watchdog paused for over 1 hour",
              f"min({h.k('vfs.file.exists[/etc/pi-netmon-watchdog.disable]')},1h)=1", WARN, "cron",
              "Stopped services are not restarted automatically. Remove /etc/pi-netmon-watchdog.disable when done.")

    # ---- database tables
    tables = h.item("pidc.db.tables", "MariaDB: Zabbix table sizes (raw)", value_type=TEXT, delay="1h", timeout="30s",
                    history="1d", tags=tag("database"))
    for t in TABLES:
        h.dep(tables, f"pidc.db.table.size[{t}]", f"MariaDB: table {t} size", [(JSONPATH, f"$.{t}")], units="B",
              tags=tag("database"))

    # ---- e-mail delivery
    al = h.item("pidc.alerts", "E-mail alerts (raw)", value_type=TEXT, delay="1m", history="1d", tags=tag("email"))
    h.dep(al, "pidc.alerts.failed", "E-mail alerts failed (last hour)", [(JSONPATH, "$.failed")], tags=tag("email"))
    h.dep(al, "pidc.alerts.stuck", "E-mail alerts unsent for over 10 min", [(JSONPATH, "$.stuck")], tags=tag("email"))
    h.dep(al, "pidc.alerts.sent", "E-mail alerts sent (last hour)", [(JSONPATH, "$.sent")], tags=tag("email"))
    h.trigger("E-mail alerts failing to send ({ITEM.LASTVALUE} in the last hour)", f"last({h.k('pidc.alerts.failed')})>0",
              HIGH, "email", "Alert e-mails are not reaching compute@ / network@. Check Office365 SMTP, the sender "
                             "mailbox/password (/root/.credentials/smtp_sender, smtp_password) and Reports > Action log.",
              recovery_mode=1, recovery_expression=f"last({h.k('pidc.alerts.failed')})=0")
    h.trigger("E-mail alerts stuck unsent ({ITEM.LASTVALUE})", f"min({h.k('pidc.alerts.stuck')},5m)>0", HIGH, "email")
    h.item("net.tcp.service[tcp,smtp.office365.com,587]", "SMTP server smtp.office365.com:587 reachable", type=SIMPLE,
           delay="5m", trends="0", tags=tag("email"))
    h.trigger("SMTP server smtp.office365.com:587 unreachable for 15 min",
              f"max({h.k('net.tcp.service[tcp,smtp.office365.com,587]')},15m)=0", HIGH, "email")

    # ---- cron jobs
    for job, every in jobs:
        f = f"{CRON_STATUS}/{job}.json"
        m = h.item(f"vfs.file.contents[{f}]", f"Cron {job}: status (raw)", value_type=TEXT, delay="1m", history="1d",
                   tags=tag("cron"))
        h.dep(m, f"pidc.cron.rc[{job}]", f"Cron {job}: exit code", [(JSONPATH, "$.rc")], trends="0", tags=tag("cron"))
        h.dep(m, f"pidc.cron.duration[{job}]", f"Cron {job}: run time", [(JSONPATH, "$.duration")], value_type=FLOAT,
              units="s", tags=tag("cron"))
        h.dep(m, f"pidc.cron.end[{job}]", f"Cron {job}: last finished", [(JSONPATH, "$.end"), (DISCARD, "")],
              units="unixtime", trends="0", tags=tag("cron"))
        stale = every + 7200 if every >= 86400 else max(3 * every + 300, 900)   # daily jobs: alert after one missed day
        h.trigger(f"Cron job {job} has not finished in {stale // 60} min",
                  f"nodata({h.k(f'pidc.cron.end[{job}]')},{stale}s)=1", AVG, "cron",
                  f"Runs every {every // 60} min from /etc/cron.d. Check the log in /var/log/zabbix/ and that cron runs.")
        h.trigger(f"Cron job {job} failed (exit code {{ITEM.LASTVALUE}})", f"last({h.k(f'pidc.cron.rc[{job}]')})<>0",
                  AVG, "cron", "The job crashed: see its log in /var/log/zabbix/.")

    # ---- web UI
    if not z.call("httptest.get", {"hostids": h.hid, "filter": {"name": [WEB]}, "output": ["httptestid"]}):
        z.call("httptest.create", {
            "name": WEB, "hostid": h.hid, "delay": "1m", "retries": 2,
            "tags": tag("web"),
            "steps": [{"no": n + 1, "name": s, "url": u, "status_codes": c, "required": r, "timeout": "15s",
                       "follow_redirects": 0} for n, (s, u, c, r) in enumerate(WEB_STEPS)]})
    h.trigger("Web UI not working: step {ITEM.LASTVALUE} failed ({ITEM.VALUE2})",
              f"min({h.k(f'web.test.fail[{WEB}]')},3m)>0 and length(last({h.k(f'web.test.error[{WEB}]')}))>=0", HIGH, "web",
              "Steps: 1 Zabbix login page, 2 /reports, 3 SmokePing. Check apache2 / php and the Apache error log.")
    return h


def valuemap(z, hostid, name, pairs):
    have = z.call("valuemap.get", {"hostids": hostid, "filter": {"name": [name]}, "output": ["valuemapid"]})
    if have:
        return have[0]["valuemapid"]
    return z.call("valuemap.create", {"hostid": hostid, "name": name, "mappings": [
        {"value": str(v), "newvalue": t} for v, t in pairs]})["valuemapids"][0]


# ======================================================================================= dashboard
def build_dashboard(z, h):
    its = z.call("item.get", {"hostids": h.hid, "output": ["name", "key_", "value_type"], "webitems": True})
    names = {i["name"]: i["itemid"] for i in its} | {"key:" + i["key_"]: i["itemid"] for i in its}

    def named(*key_prefixes):   # item names of the stock MySQL / Apache templates (they carry no "MySQL:" prefix)
        return sorted({i["name"] for i in its if i["key_"].startswith(key_prefixes) and i["value_type"] in ("0", "3")})

    def numeric(*patterns):   # navigators feed follow graphs: text items there make the PDF print view time out
        return sorted({i["name"] for i in its if i["value_type"] in ("0", "3") and any(
            re.fullmatch(p.replace("*", ".*"), i["name"]) for p in patterns)})
    me, ids = [HOST], [h.hid]

    def tile(label, item, x, y, w=8, decimals=0, th=(), size=20):
        if item not in names:
            return []
        return [sw.tile(label, names[item], x, y, label, w=w, decimals=decimals, th=th, value_size=size)]

    ok01 = ((0, d.RED), (1, d.GREEN))
    bad_if_any = ((0, d.GREEN), (1, d.RED))
    ov = []
    specs = [  # label, item, decimals, thresholds
        ("CPU %", "CPU utilization", 1, sw.PCT_TH), ("memory %", "Memory utilization", 1, sw.PCT_TH),
        ("disk / used %", "FS [/]: Space: Used, in %", 1, sw.PCT_TH),
        ("backup NFS free %", "Backup NFS: free space %", 0, ((0, d.RED), (15, d.AMBER), (30, d.GREEN))),
        ("values / s", "Number of processed values per second", 0, ()),
        ("queue > 10 min", "Queue over 10 minutes", 0,
         ((0, d.GREEN), (1, d.AMBER), (100, d.RED))),
        ("NTP synced", "NTP: clock synchronised", 0, ok01),
        ("web UI failed step", f"key:web.test.fail[{WEB}]", 0, bad_if_any),
        ("mails failed (1 h)", "E-mail alerts failed (last hour)", 0, bad_if_any),
        ("mails sent (1 h)", "E-mail alerts sent (last hour)", 0, ()),
        ("SMTP reachable", "SMTP server smtp.office365.com:587 reachable", 0, ok01),
        ("MariaDB up", 'key:mysql.ping["{$MYSQL.DSN}","{$MYSQL.USER}","{$MYSQL.PASSWORD}"]', 0, ok01),
        ("uptime", "key:system.uptime", 0, ()), ("security updates", "OS: security updates pending", 0,
                                                 ((0, d.GREEN), (1, d.AMBER))),
        ("reboot required", "OS: reboot required (updates installed)", 0, ((0, d.GREEN), (1, d.AMBER))),
        ("cert days left", "SSL isp.picloud.in: days until expiry", 0, ((0, d.RED), (14, d.AMBER), (21, d.GREEN))),
        ("backup result", "Backup: last result", 0, ()),
        ("DB size", 'key:mysql.db.size["{$MYSQL.DSN}","{$MYSQL.USER}","{$MYSQL.PASSWORD}","zabbix"]', 1, ()),
    ]
    for n, (label, item, dec, th) in enumerate(specs):
        ov += tile(label, item, (n % 9) * 8, (n // 9) * 3, decimals=dec, th=th, size=16)
    y = 6
    ov += [
        cp.hmap("Services (green active / red not active) - click one", 0, y, 36, 4, ids, ["*: Active state"],
                '{{ITEM.NAME}.regsub("^(.+)\\.service: Active state", "\\1")}', ((1, d.GREEN), (2, d.RED), (3, d.RED),
                                                                                    (4, d.AMBER), (5, d.AMBER)), "SRVMP", False),
        cp.hmap("Cron jobs: last exit code (green 0 = OK) - click one", 36, y, 36, 4, ids, ["Cron *: exit code"],
                '{{ITEM.NAME}.regsub("^Cron (.+): exit code", "\\1")}', ((0, d.GREEN), (1, d.RED)), "CRNMP", False),
        sw.follow_graph("History of the service clicked above", 0, y + 4, 36, 4, "SRVMP"),
        sw.follow_graph("History of the cron job clicked above", 36, y + 4, 36, 4, "CRNMP"),
    ]
    y += 8
    ov += [
        sw.svg("CPU and memory %", 0, y, 24, 6, me, [
            {"items": ["CPU utilization"], "color": "2563EB", "label": "CPU"},
            {"items": ["Memory utilization"], "color": "7C3AED", "label": "memory"}], extra=[d.f(d.INT, "lefty_max", 100)]),
        sw.svg("Disk sda: utilisation % and await", 24, y, 24, 6, me, [
            {"items": ["sda: Disk utilization"], "color": "F59E0B", "label": "util %"},
            {"items": ["sda: Disk write request avg waiting time (w_await)"], "color": d.RED, "label": "write await",
             "axisy": 1},
            {"items": ["sda: Disk read request avg waiting time (r_await)"], "color": "0EA5E9", "label": "read await",
             "axisy": 1}]),
        sw.svg("Zabbix values processed per second", 48, y, 24, 6, me, [
            {"items": ["Number of processed values per second"], "color": "2E9E5B", "label": "values/s"}]),
    ]
    y += 6
    ov.append(sw.problems("Monitoring server problems", 0, y, 72, 5, hostid=h.hid))

    db = [
        sw.svg("Queries per second", 0, 0, 36, 6, me, [
            {"items": ["Queries per second"], "color": "2563EB", "label": "queries/s"},
            {"items": ["Command Insert per second"], "color": "2E9E5B", "label": "inserts/s"},
            {"items": ["Command Delete per second"], "color": d.RED, "label": "deletes/s"}]),
        sw.svg("Connections and threads", 36, 0, 36, 6, me, [
            {"items": ["Threads connected"], "color": "7C3AED", "label": "connected"},
            {"items": ["Threads running"], "color": "F59E0B", "label": "running"}]),
        sw.svg("InnoDB buffer pool utilisation % / efficiency %", 0, 6, 36, 6, me, [
            {"items": ["Buffer pool utilization"], "color": "0EA5E9", "label": "used %"},
            {"items": ["Buffer pool efficiency"], "color": "2E9E5B", "label": "hit %"}],
            extra=[d.f(d.INT, "lefty_max", 100)]),
        sw.svg("Zabbix table sizes (history + trends drive disk growth)", 36, 6, 36, 6, me, [
            {"items": [f"MariaDB: table {t} size"], "color": c, "label": t}
            for t, c in zip(TABLES, cp.PALETTE)], legend_lines=6),
        cp.nav("MariaDB: every metric - click to graph", 0, 12, 36, 14, ids, named("mysql.") + numeric("MariaDB*"), [],
               "DBNAV"),
        sw.follow_graph("Graph of the database item selected on the left", 36, 12, 36, 14, "DBNAV"),
    ]
    web = [
        sw.svg("Web UI response time per step", 0, 0, 36, 6, me, [
            {"items": [f"Response time for step \"{s}\" of scenario \"{WEB}\"."], "color": c, "label": s}
            for (s, _, _, _), c in zip(WEB_STEPS, cp.PALETTE)]),
        sw.svg("Apache requests per second and busy workers", 36, 0, 36, 6, me, [
            {"items": ["Requests per second"], "color": "2563EB", "label": "requests/s"},
            {"items": ["Total workers busy"], "color": d.RED, "label": "busy workers", "axisy": 1}]),
        cp.nav("Apache, web UI, services, e-mail, NTP, OS, cron jobs - click to graph", 0, 6, 36, 16, ids,
               named("apache.") + numeric("*scenario*", "*.service:*", "E-mail*", "SMTP*", "NTP*", "OS:*", "Cron*",
                                         "Watchdog*"), [],
               "WBNAV"),
        sw.follow_graph("Graph of the item selected on the left", 36, 6, 36, 16, "WBNAV"),
    ]
    pages = [{"name": "Overview", "widgets": ov}, {"name": "Database (MariaDB)", "widgets": db},
             {"name": "Web, e-mail, jobs", "widgets": web}]
    click_to_graph.link_pages(pages, DASHBOARD, z=z)
    dash = z.call("dashboard.get", {"filter": {"name": [DASHBOARD]}, "output": ["dashboardid"]})
    params = {"name": DASHBOARD, "display_period": 60, "auto_start": 0, "pages": pages}
    if dash:
        z.call("dashboard.update", {"dashboardid": dash[0]["dashboardid"], **params})
        print(f'Updated dashboard "{DASHBOARD}" ({dash[0]["dashboardid"]})')
    else:
        print(f'Created dashboard "{DASHBOARD}" ({z.call("dashboard.create", params)["dashboardids"][0]})')


def main():
    pw = mysql_monitor_user()
    agent_conf()
    jobs = cron_jobs()
    print("cron jobs:", ", ".join(f"{j} ({s // 60} min)" for j, s in jobs))
    z = base.Zabbix()
    h = setup_zabbix(z, pw, jobs)
    print(f"{HOST}: {h.n['items']} new items, {h.n['triggers']} new triggers")
    if "--no-dashboard" not in os.sys.argv:
        build_dashboard(z, h)


if __name__ == "__main__":
    main()
