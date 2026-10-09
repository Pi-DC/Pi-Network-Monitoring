#!/usr/bin/env python3
"""Nightly backup of the Pi Network Monitoring tool (isp.picloud.in).

Runs from /etc/cron.d/pi-netmon-backup at 21:00 IST.

  GitHub  git@github.com:Pi-DC/Pi-Network-Monitoring.git, branch main - configuration and documentation only:
          every script and config file under deploy/ (secret values replaced by __REDACTED__; a scan stops the push
          if any secret is left in plain text), package / Apache / ownership lists, README, RESTORE, CHANGELOG and a
          generated docs/INVENTORY.md (devices, dashboards, alerting, scheduled jobs). Commit only when changed.
  NFS     172.16.95.5:/Repo_BDR/Pi-Network-Monitoring, mounted on /mnt/pi-netmon-nfs (automount, /etc/fstab):
          one folder per night, all files gpg AES-256 encrypted (the export is readable by any host):
            zabbix-full.sql.zst.gpg      whole Zabbix database incl. graph history
            zabbix-config.sql.zst.gpg    configuration only (no history) - small, quick to restore
            smokeping-data.tar.zst.gpg   SmokePing RRD data
            secrets.tar.zst.gpg          credentials, TLS keys, original config files with passwords
            MANIFEST.json                time, sizes, SHA-256, matching git commit
          Written as <name>.partial, renamed only after every file was copied and its checksum re-read.
          LATEST.txt names the newest complete backup. Kept KEEP_NFS_DAYS nights.
  Local   /var/backups/pi-network-monitoring: the same folder, last KEEP_LOCAL_DAYS nights (fast restore).

Every encrypted file is decrypted again and checked before it is copied anywhere. Any failure stops the run and
leaves the previous backups untouched; /var/lib/pi-netmon-backup/status/last-result ("OK ..." / "FAILED ...")
is read by Zabbix, which e-mails on failure or when no backup succeeded for 26 hours.
Passphrase: /root/.credentials/backup_passphrase (never in git; keep a copy outside the server).

Restore: RESTORE.md / restore.sh in the repository. Check run (nothing pushed or copied): backup.py --no-push
"""
import datetime
import glob
import grp
import hashlib
import json
import os
import pwd
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time

REPO_URL = "git@github.com:Pi-DC/Pi-Network-Monitoring.git"
WORK = "/var/lib/pi-netmon-backup"
CHECKOUT = f"{WORK}/repo"
STATUS = f"{WORK}/status"
NFS = "/mnt/pi-netmon-nfs"
NFS_SOURCE = "172.16.95.5:/Repo_BDR/Pi-Network-Monitoring"
LOCAL = "/var/backups/pi-network-monitoring"
KEEP_NFS_DAYS = 14
KEEP_LOCAL_DAYS = 3
PASSPHRASE = "/root/.credentials/backup_passphrase"
DB = "zabbix"
NO_DATA_TABLES = ["history", "history_uint", "history_str", "history_text", "history_log", "history_bin",
                  "trends", "trends_uint", "auditlog"]   # schema only in the configuration dump
DUMP = ["mysqldump", "--single-transaction", "--quick", "--routines", "--triggers", "--hex-blob",
        "--no-tablespaces", "--default-character-set=utf8mb4"]

# Deployment files (plain text in git after redaction). Globs; directories are copied recursively.
FILES = [
    "/opt/isp/zabbix/*.py", "/opt/isp/reports/index.php", "/opt/isp/reports/print-nolinks.js",
    "/opt/isp/smokeping-gui/index.php", "/opt/isp/ssl/*", "/opt/isp/backup/*",
    "/etc/zabbix/zabbix_server.conf", "/etc/zabbix/web/zabbix.conf.php", "/etc/zabbix/apache.conf",
    "/etc/zabbix/zabbix_agent2.conf", "/etc/zabbix/zabbix_agent2.d", "/etc/zabbix/zabbix_server.d",
    "/etc/zabbix/zabbix_web_service.conf",
    "/etc/apache2/sites-available/isp.picloud.in*.conf", "/etc/apache2/sites-available/000-default.conf",
    "/etc/apache2/conf-available/smokeping.conf", "/etc/apache2/conf-available/smokeping-gui.conf",
    "/etc/apache2/conf-available/zabbix-reports.conf", "/etc/apache2/conf-available/zabbix-print-nolinks.conf",
    "/etc/mysql/mariadb.conf.d/60-zabbix-tuning.cnf",
    "/etc/systemd/system/mariadb.service.d/oom.conf", "/etc/systemd/system/zabbix-server.service.d/oom.conf",
    "/etc/cron.d/zabbix-*", "/etc/cron.d/pi-netmon-backup",
    "/etc/smokeping/config", "/etc/smokeping/config.d/General", "/etc/smokeping/config.d/Targets",
    "/etc/smokeping/config.d/Targets.gui", "/etc/smokeping/config.d/Probes", "/etc/smokeping/config.d/Database",
    "/etc/smokeping/config.d/Presentation", "/etc/smokeping/config.d/Alerts", "/etc/smokeping/config.d/Slaves",
    "/etc/smokeping/config.d/pathnames", "/etc/smokeping/basepage.html",
    "/usr/local/sbin/smokeping-gui-apply", "/etc/sudoers.d/smokeping-gui", "/var/lib/smokeping-gui/devices.json",
    "/etc/letsencrypt/renewal/*.conf",
    "/etc/apt/sources.list.d/zabbix.sources", "/etc/apt/sources.list.d/zabbix-tools.sources",
    "/etc/apt/sources.list.d/google-chrome.sources",
]
SKIP = re.compile(r"(__pycache__|\.pyc$|\.bak|\.orig$|~$)")
ROOT_DOCS = ("README.md", "RESTORE.md", "CHANGELOG.md", "restore.sh")   # also copied to the top of the repo
# Secrets bundle (encrypted). Directories recursively.
SECRETS = ["/root/.credentials", "/etc/letsencrypt", "/etc/zabbix/zabbix_server.conf", "/etc/zabbix/web/zabbix.conf.php",
           "/etc/smokeping/smokeping_secrets", "/etc/smokeping/htpasswd"]
PACKAGES = r"^(zabbix|mariadb|apache2|libapache2-mod-php|php8|smokeping|fping|snmp|google-chrome|poppler-utils|certbot|zstd|gpg|nfs-common)"


def log(msg):
    print(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} {msg}", flush=True)


def run(cmd, **kw):
    kw.setdefault("check", True)
    return subprocess.run(cmd, **kw)


def git(*args, capture=False):
    r = run(["git", "-C", CHECKOUT, *args], capture_output=capture, text=True)
    return r.stdout.strip() if capture else None


GPG = ["gpg", "--batch", "--yes", "--quiet", "--pinentry-mode", "loopback", "--passphrase-file", PASSPHRASE]


def encrypt_stream(producer, dst, level=10):
    """producer (argv list or file path) | zstd | gpg AES-256 -> dst."""
    with open(dst, "wb") as out:
        src = subprocess.Popen(producer, stdout=subprocess.PIPE) if isinstance(producer, list) else None
        zs = subprocess.Popen(["zstd", "-q", f"-{level}", "-T0"] + ([] if src else ["-c", producer]),
                              stdin=src.stdout if src else None, stdout=subprocess.PIPE)
        if src:
            src.stdout.close()
        gp = subprocess.Popen(GPG + ["--symmetric", "--cipher-algo", "AES256", "--compress-algo", "none"],
                              stdin=zs.stdout, stdout=out)
        zs.stdout.close()
        if gp.wait() or zs.wait() or (src and src.wait()):
            raise RuntimeError(f"creating {os.path.basename(dst)} failed")


def verify(enc, kind):
    """Decrypt + decompress again: the stream must be intact; dumps must have completed; bundles must list."""
    gp = subprocess.Popen(GPG + ["--decrypt", enc], stdout=subprocess.PIPE)
    zs = subprocess.Popen(["zstd", "-q", "-d", "-c"], stdin=gp.stdout, stdout=subprocess.PIPE)
    gp.stdout.close()
    if kind == "sql":
        tail, size = b"", 0
        for chunk in iter(lambda: zs.stdout.read(1 << 20), b""):
            size += len(chunk)
            tail = (tail + chunk)[-400:]
        ok = b"Dump completed" in tail and size > 1_000_000
    else:
        names = run(["tar", "-tf", "-"], stdin=zs.stdout, capture_output=True, text=True).stdout.split("\n")
        ok = len(names) > 1 and (kind != "secrets" or any(n.endswith(".credentials/zabbix_db") for n in names))
    zs.stdout.close()
    if zs.wait() or gp.wait() or not ok:
        raise RuntimeError(f"verification of {os.path.basename(enc)} failed")


def sha256(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def secret_values():
    """Every secret string that must never appear in plain text in git."""
    vals = set()
    for f in glob.glob("/root/.credentials/*"):
        for line in open(f, errors="ignore"):
            if len(line.strip()) >= 6:
                vals.add(line.strip())
    php = run(["php", "-r", 'define("IMAGE_FORMAT_PNG","PNG"); $DB=[]; include "/etc/zabbix/web/zabbix.conf.php"; '
               'echo $DB["PASSWORD"];'], capture_output=True, text=True).stdout.strip()
    if php:
        vals.add(php)
    for line in open("/etc/zabbix/zabbix_server.conf"):
        if line.startswith("DBPassword="):
            vals.add(line.split("=", 1)[1].strip())
    for f in glob.glob("/etc/letsencrypt/*.json"):   # acme-dns account
        for k, v in json.load(open(f)).items():
            if k in ("password", "username") and len(str(v)) >= 6:
                vals.add(str(v))
    if os.path.exists("/etc/smokeping/smokeping_secrets"):
        for line in open("/etc/smokeping/smokeping_secrets"):
            if ":" in line and len(line.split(":", 1)[1].strip()) >= 6:
                vals.add(line.split(":", 1)[1].strip())
    return sorted((v for v in vals if v), key=len, reverse=True)


def copy_deploy(secrets):
    dest = f"{CHECKOUT}/deploy"
    shutil.rmtree(dest, ignore_errors=True)
    paths = []
    for pat in FILES:
        for p in sorted(glob.glob(pat)):
            if os.path.isdir(p):
                paths += [os.path.join(d, f) for d, _, fs in os.walk(p) for f in fs]
            else:
                paths.append(p)
    count, owners = 0, []
    for p in paths:
        if SKIP.search(p) or not os.path.isfile(p):
            continue
        st = os.stat(p)
        owners.append(f"{oct(st.st_mode & 0o7777)[2:]} {pwd.getpwuid(st.st_uid).pw_name} "
                      f"{grp.getgrgid(st.st_gid).gr_name} {p}")
        out = dest + p
        os.makedirs(os.path.dirname(out), exist_ok=True)
        data = open(p, "rb").read()
        for s in secrets:
            data = data.replace(s.encode(), b"__REDACTED__")
        open(out, "wb").write(data)
        shutil.copymode(p, out)
        count += 1
    pkg = f"{CHECKOUT}/packages"
    os.makedirs(pkg, exist_ok=True)
    open(f"{pkg}/ownership.txt", "w").write("\n".join(owners) + "\n")   # git keeps no owners
    pk = run(["dpkg-query", "-W", "-f", "${Package}=${Version}\n"], capture_output=True, text=True).stdout
    open(f"{pkg}/packages.txt", "w").write("".join(l + "\n" for l in pk.splitlines() if re.match(PACKAGES, l)))
    tz = run(["timedatectl", "show", "-p", "Timezone", "--value"], capture_output=True, text=True).stdout.strip()
    open(f"{pkg}/timezone.txt", "w").write(tz + "\n")
    with open(f"{pkg}/apache-enabled.txt", "w") as out:   # for a2enmod / a2enconf / a2ensite
        for kind, pat in (("mod", "mods-enabled/*.load"), ("conf", "conf-enabled/*.conf"), ("site", "sites-enabled/*.conf")):
            for f in sorted(glob.glob(f"/etc/apache2/{pat}")):
                out.write(f"{kind} {os.path.basename(f).rsplit('.', 1)[0]}\n")
    for f in ROOT_DOCS:
        if os.path.exists(f"/opt/isp/backup/{f}"):
            shutil.copy2(f"/opt/isp/backup/{f}", f"{CHECKOUT}/{f}")
    return count


def write_inventory():
    """docs/INVENTORY.md from the Zabbix API: only configuration (no live values), so it changes only with config."""
    sys.path.insert(0, "/opt/isp/zabbix")
    import setup_isp_links as base
    z = base.Zabbix()
    tag = lambda h, t: next((x["value"] for x in h["tags"] if x["tag"] == t), "")
    hosts = z.call("host.get", {"output": ["host", "name", "status"], "selectGroups": ["name"], "selectTags": ["tag", "value"],
                                "selectParentTemplates": ["host"], "selectInterfaces": ["ip", "type"]})
    out = ["# Inventory", "", "Generated nightly by `backup.py` from the Zabbix configuration. Do not edit by hand.", "",
           f"## Monitored devices ({sum(h['status'] == '0' for h in hosts)} enabled, {len(hosts)} total)", "",
           "| Group | Host | Name | IP | Model / vendor | Template | Status |", "|---|---|---|---|---|---|---|"]
    for h in sorted(hosts, key=lambda h: (h["groups"][0]["name"], h["host"].replace("-", "_"))):
        ip = next((i["ip"] for i in h["interfaces"]), "")
        model = tag(h, "model") or tag(h, "vendor")
        tpl = ", ".join(t["host"] for t in h["parentTemplates"])
        out.append(f"| {h['groups'][0]['name']} | {h['host']} | {h['name']} | {ip} | {model} | {tpl} | "
                   f"{'enabled' if h['status'] == '0' else '**disabled**'} |")
    reports = {r["dashboardid"] for r in z.call("report.get", {"output": ["dashboardid"]})}
    out += ["", "## Dashboards", "", "| ID | Name | Pages | Daily 08:00 PDF e-mail |", "|---|---|---|---|"]
    for d in z.call("dashboard.get", {"output": ["dashboardid", "name"], "selectPages": ["name"], "sortfield": "dashboardid"}):
        out.append(f"| {d['dashboardid']} | {d['name']} | {len(d['pages'])} | {'yes' if d['dashboardid'] in reports else 'no'} |")
    out += ["", "## E-mail alerting", ""]
    for a in z.call("action.get", {"output": ["name", "status"], "selectFilter": "extend", "filter": {"eventsource": 0}}):
        if a["status"] != "0":
            continue
        gm = {g["groupid"]: g["name"] for g in z.call("hostgroup.get", {"output": ["groupid", "name"]})}
        hm = {x["hostid"]: x["host"] for x in z.call("host.get", {"output": ["hostid", "host"]})}
        scope = [gm.get(c["value"]) or hm.get(c["value"]) for c in a["filter"]["conditions"] if c["conditiontype"] in ("0", "1")]
        if scope:
            out.append(f"- **{a['name']}**: severity Average and above on {', '.join(sorted(filter(None, scope)))}")
    out += ["", "Default thresholds: CPU 75 %, memory 85 % (`set_default_thresholds.py`); per-device exceptions are host macros.",
            "", "## Scheduled jobs (`/etc/cron.d`)", ""]
    for f in sorted(glob.glob("/etc/cron.d/zabbix-*") + ["/etc/cron.d/pi-netmon-backup"]):
        for line in open(f):
            if line.strip() and not line.startswith("#"):
                out.append(f"- `{os.path.basename(f)}`: `{line.strip()}`")
    out += ["", "## Backups", "",
            f"- Configuration and documentation: this repository (branch `main`).",
            f"- Data: NFS `{NFS_SOURCE}` (mounted on `{NFS}`), one encrypted folder per night, {KEEP_NFS_DAYS} nights kept.",
            f"- Local copy: `{LOCAL}`, {KEEP_LOCAL_DAYS} nights.", ""]
    os.makedirs(f"{CHECKOUT}/docs", exist_ok=True)
    open(f"{CHECKOUT}/docs/INVENTORY.md", "w").write("\n".join(out))


def scan_for_secrets(secrets):
    """Abort if any secret value is in a file that would be pushed."""
    for d, _, fs in os.walk(CHECKOUT):
        if "/.git" in d:
            continue
        for f in fs:
            data = open(os.path.join(d, f), "rb").read()
            for s in secrets:
                if s.encode() in data:
                    raise RuntimeError(f"secret value found in plain text in {os.path.join(d, f)[len(CHECKOUT) + 1:]}"
                                       " - push aborted")


def ensure_checkout():
    if not os.path.isdir(f"{CHECKOUT}/.git"):
        os.makedirs(WORK, exist_ok=True)
        run(["git", "clone", "-q", REPO_URL, CHECKOUT])
    git("config", "user.name", "Pi Network Monitoring backup (isp.picloud.in)")
    git("config", "user.email", "backup@isp.picloud.in")
    git("fetch", "-q", "--prune", "origin")
    git("checkout", "-q", "-B", "main", "origin/main")


def nfs_ready():
    """The share must be mounted (automount) and writable within 60 s - a hung NFS server must not hang the run."""
    try:
        run(["timeout", "60", "sh", "-c", f"ls {NFS} >/dev/null && touch {NFS}/.probe && rm -f {NFS}/.probe"])
    except subprocess.CalledProcessError:
        raise RuntimeError(f"NFS {NFS_SOURCE} not reachable or not writable on {NFS}")
    if run(["findmnt", "-n", "-t", "nfs", NFS], capture_output=True, check=False).returncode:
        raise RuntimeError(f"{NFS} is not an NFS mount - refusing to write backups to the local disk")


def publish(src_dir, root, keep_days, name):
    """Copy a finished backup folder to root/<name>: copy as .partial, re-read every checksum, then rename."""
    os.makedirs(root, exist_ok=True)
    part = f"{root}/{name}.partial"
    shutil.rmtree(part, ignore_errors=True)
    os.makedirs(part)
    manifest = json.load(open(f"{src_dir}/MANIFEST.json"))
    for f in os.listdir(src_dir):
        shutil.copyfile(f"{src_dir}/{f}", f"{part}/{f}")   # copyfile: NFS maps root to nobody, no chown
    for f, meta in manifest["files"].items():
        if sha256(f"{part}/{f}") != meta["sha256"]:
            raise RuntimeError(f"checksum mismatch after copying {f} to {root}")
    os.rename(part, f"{root}/{name}")
    open(f"{root}/LATEST.txt", "w").write(f"{name}\n")
    cutoff = time.time() - keep_days * 86400
    for old in sorted(glob.glob(f"{root}/20*")):
        base_name = os.path.basename(old)
        if base_name == name:
            continue
        if old.endswith(".partial") or os.path.getmtime(old) < cutoff:
            shutil.rmtree(old, ignore_errors=True)


def write_status(ok, text):
    os.makedirs(STATUS, exist_ok=True)
    msg = f"{'OK' if ok else 'FAILED'} {datetime.datetime.now():%Y-%m-%d %H:%M:%S} {text}\n"
    open(f"{STATUS}/last-result", "w").write(msg)
    if ok:
        open(f"{STATUS}/last-success", "w").write(msg)
    for f in glob.glob(f"{STATUS}/*"):
        os.chmod(f, 0o644)   # read by the Zabbix agent (no secrets in these files)


def main():
    started = time.time()
    stamp = datetime.datetime.now().strftime("%Y-%m-%d_%H%M")
    dry = "--no-push" in sys.argv
    os.umask(0o077)
    tmp = tempfile.mkdtemp(prefix="pi-netmon-backup-", dir="/var/tmp")
    out = f"{tmp}/{stamp}"
    os.makedirs(out)
    try:
        # 1. configuration + documentation -> git (main)
        ensure_checkout()
        secrets = secret_values()
        n = copy_deploy(secrets)
        write_inventory()
        scan_for_secrets(secrets)
        log(f"deployment tree: {n} files + inventory, no secrets in plain text")
        if not dry:
            nfs_ready()   # check before the long dumps, so a dead NFS fails fast

        # 2. encrypted data files
        sec_tar = f"{tmp}/secrets.tar"
        with tarfile.open(sec_tar, "w") as t:
            for p in SECRETS:
                if os.path.exists(p):
                    t.add(p)
        encrypt_stream(sec_tar, f"{out}/secrets.tar.zst.gpg")
        os.remove(sec_tar)
        ign = [f"--ignore-table={DB}.{t}" for t in NO_DATA_TABLES]
        cfg_sql = f"{tmp}/config.sql"
        with open(cfg_sql, "wb") as f:
            run(DUMP + ign + [DB], stdout=f)
            run(DUMP + ["--no-data", DB] + NO_DATA_TABLES, stdout=f)
        encrypt_stream(cfg_sql, f"{out}/zabbix-config.sql.zst.gpg", level=15)
        os.remove(cfg_sql)
        encrypt_stream(DUMP + [DB], f"{out}/zabbix-full.sql.zst.gpg", level=3)
        # SmokePing updates its RRD files every few seconds: archive a quick copy, not the live files
        snap = f"{tmp}/rrd"
        run(["cp", "-a", "/var/lib/smokeping", snap])
        encrypt_stream(["tar", "-C", snap, "--transform", "s,^\\.,smokeping,", "-cf", "-", "."],
                       f"{out}/smokeping-data.tar.zst.gpg", level=3)
        shutil.rmtree(snap)
        for f, kind in (("secrets.tar.zst.gpg", "secrets"), ("zabbix-config.sql.zst.gpg", "sql"),
                        ("zabbix-full.sql.zst.gpg", "sql"), ("smokeping-data.tar.zst.gpg", "tar")):
            verify(f"{out}/{f}", kind)
        sizes = {f: os.path.getsize(f"{out}/{f}") for f in os.listdir(out)}
        log("encrypted + verified: " + ", ".join(f"{f} {s / 1e6:.1f} MB" for f, s in sorted(sizes.items())))
        if dry:
            git("add", "-A")
            log("--no-push: nothing pushed or copied. Staged in git:\n" + (git("status", "--short", capture=True) or "(no changes)"))
            return

        # 3. git: commit only when configuration / docs changed
        git("add", "-A")
        if git("status", "--porcelain", capture=True):
            git("commit", "-q", "-m", f"Configuration snapshot {stamp}")
        git("push", "-q", "origin", "main")
        rev = git("rev-parse", "HEAD", capture=True)

        # 4. manifest, then NFS (verified copy) and local
        manifest = {
            "created": datetime.datetime.now().isoformat(timespec="seconds"), "host": os.uname().nodename,
            "git_commit_main": rev, "zabbix_version": run(["zabbix_server", "-V"], capture_output=True,
                                                         text=True).stdout.splitlines()[0],
            "encryption": "gpg --symmetric AES256 over zstd; passphrase /root/.credentials/backup_passphrase (not stored here)",
            "files": {f: {"bytes": os.path.getsize(f"{out}/{f}"), "sha256": sha256(f"{out}/{f}")} for f in sorted(sizes)},
        }
        open(f"{out}/MANIFEST.json", "w").write(json.dumps(manifest, indent=2) + "\n")
        nfs_ready()
        publish(out, NFS, KEEP_NFS_DAYS, stamp)
        publish(out, LOCAL, KEEP_LOCAL_DAYS, stamp)
        total = sum(sizes.values()) / 1e9
        write_status(True, f"backup {stamp}: git {rev[:7]}, NFS {NFS_SOURCE}/{stamp} ({total:.2f} GB), "
                           f"{time.time() - started:.0f}s")
        log(f"done: git main {rev[:7]}, NFS + local folder {stamp} ({total:.2f} GB)")
    except Exception as e:
        if not dry:   # a check run must not raise or clear the Zabbix backup alert
            write_status(False, f"backup {stamp}: {str(e)[:300]}")
        log(f"FAILED: {e}")
        raise
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
