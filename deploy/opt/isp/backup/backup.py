#!/usr/bin/env python3
"""Nightly backup of the Pi Network Monitoring tool (isp.picloud.in) to GitHub + local disk.

Runs from /etc/cron.d/pi-netmon-backup at 21:00 IST. Steps (any failure stops the run; GitHub is then left as it was):

 1. Deployment tree (all scripts and configuration, see FILES) is copied into the git checkout under deploy/,
    every known secret value replaced by __REDACTED__, and a scan proves no secret is left in plain text.
 2. Secrets bundle (credentials, DB/SMTP passwords, SNMP communities, TLS keys, SmokePing logins, original
    config files) -> tar -> zstd -> gpg AES-256 with the passphrase in /root/.credentials/backup_passphrase.
 3. Zabbix configuration database (everything except metric history/trends and the audit log) -> mysqldump ->
    zstd -> gpg. This holds every host, template, item, trigger, dashboard, user, alert rule and report.
 4. Each encrypted file is decrypted again and checked (zstd integrity, dump completed) before anything is pushed.
 5. GitHub: branch "main" gets a commit when the deployment tree changed; branch "backups" is replaced by a single
    commit holding only this run's encrypted files (only the last successful backup is kept, as requested).
 6. Local (not in git, too large): full database dump incl. metric history + SmokePing RRD data, kept 14 days in
    /var/backups/pi-network-monitoring.
 7. Status for Zabbix: /var/lib/pi-netmon-backup/status/last-result ("OK ..." or "FAILED ...") and last-success.

Restore: see RESTORE.md in the repository (restore.sh). Check run without pushing: backup.py --no-push
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
LOCAL = "/var/backups/pi-network-monitoring"
KEEP_LOCAL_DAYS = 14
PASSPHRASE = "/root/.credentials/backup_passphrase"
DB = "zabbix"
NO_DATA_TABLES = ["history", "history_uint", "history_str", "history_text", "history_log", "history_bin",
                  "trends", "trends_uint", "auditlog"]   # schema only in the GitHub dump (data is far too large)

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
# Secrets bundle (encrypted). Directories recursively.
SECRETS = ["/root/.credentials", "/etc/letsencrypt", "/etc/zabbix/zabbix_server.conf", "/etc/zabbix/web/zabbix.conf.php",
           "/etc/smokeping/smokeping_secrets", "/etc/smokeping/htpasswd"]
PACKAGES = r"^(zabbix|mariadb|apache2|libapache2-mod-php|php8|smokeping|fping|snmp|google-chrome|poppler-utils|certbot|zstd|gpg)"


def log(msg):
    print(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} {msg}", flush=True)


def run(cmd, **kw):
    kw.setdefault("check", True)
    return subprocess.run(cmd, **kw)


def git(*args, capture=False):
    r = run(["git", "-C", CHECKOUT, *args], capture_output=capture, text=True)
    return r.stdout.strip() if capture else None


def gpg_encrypt(src, dst):
    run(["gpg", "--batch", "--yes", "--quiet", "--pinentry-mode", "loopback", "--passphrase-file", PASSPHRASE,
         "--symmetric", "--cipher-algo", "AES256", "--compress-algo", "none", "-o", dst, src])


def gpg_decrypt(src, dst):
    run(["gpg", "--batch", "--yes", "--quiet", "--pinentry-mode", "loopback", "--passphrase-file", PASSPHRASE,
         "--decrypt", "-o", dst, src])


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
    count = 0
    owners = []
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
    os.makedirs(f"{CHECKOUT}/packages", exist_ok=True)
    open(f"{CHECKOUT}/packages/ownership.txt", "w").write("\n".join(owners) + "\n")   # git keeps no owners
    # package versions + apt keys needed for the repos
    pk = run(["dpkg-query", "-W", "-f", "${Package}=${Version}\n"], capture_output=True, text=True).stdout
    os.makedirs(f"{CHECKOUT}/packages", exist_ok=True)
    open(f"{CHECKOUT}/packages/packages.txt", "w").write(
        "".join(l + "\n" for l in pk.splitlines() if re.match(PACKAGES, l)))
    tz = run(["timedatectl", "show", "-p", "Timezone", "--value"], capture_output=True, text=True).stdout.strip()
    open(f"{CHECKOUT}/packages/timezone.txt", "w").write(tz + "\n")
    with open(f"{CHECKOUT}/packages/apache-enabled.txt", "w") as out:   # for a2enmod / a2enconf / a2ensite
        for kind, pat in (("mod", "mods-enabled/*.load"), ("conf", "conf-enabled/*.conf"), ("site", "sites-enabled/*.conf")):
            for f in sorted(glob.glob(f"/etc/apache2/{pat}")):
                out.write(f"{kind} {os.path.basename(f).rsplit('.', 1)[0]}\n")
    for f in ("README.md", "RESTORE.md", "restore.sh"):   # restore guide at the top of the repository
        if os.path.exists(f"/opt/isp/backup/{f}"):
            shutil.copy2(f"/opt/isp/backup/{f}", f"{CHECKOUT}/{f}")
    return count


def scan_for_secrets(secrets):
    """Abort if any secret value is in a plain-text file that would be pushed."""
    for d, _, fs in os.walk(CHECKOUT):
        if "/.git" in d:
            continue
        for f in fs:
            p = os.path.join(d, f)
            if p.endswith(".gpg"):
                continue
            data = open(p, "rb").read()
            for s in secrets:
                if s.encode() in data:
                    raise RuntimeError(f"secret value found in plain text in {p[len(CHECKOUT) + 1:]} - push aborted")


def dump_config_db(path):
    ign = [f"--ignore-table={DB}.{t}" for t in NO_DATA_TABLES]
    base = ["mysqldump", "--single-transaction", "--quick", "--routines", "--triggers", "--hex-blob",
            "--no-tablespaces", "--default-character-set=utf8mb4"]
    with open(path, "wb") as out:
        run(base + ign + [DB], stdout=out)
        run(base + ["--no-data", DB] + NO_DATA_TABLES, stdout=out)


def zstd(src, dst, level=10):
    run(["zstd", "-q", "-f", f"-{level}", "-T0", src, "-o", dst])


def verify(enc, kind, tmp):
    """Decrypt + decompress the encrypted file again and check it is complete."""
    dec = f"{tmp}/verify.zst"
    gpg_decrypt(enc, dec)
    run(["zstd", "-q", "-t", dec])
    raw = f"{tmp}/verify.raw"
    run(["zstd", "-q", "-d", "-f", dec, "-o", raw])
    if kind == "sql":
        tail = open(raw, "rb").read()[-400:]
        if b"Dump completed" not in tail or os.path.getsize(raw) < 1_000_000:
            raise RuntimeError("database dump incomplete")
    else:
        with tarfile.open(raw) as t:
            if not any(n.endswith(".credentials/zabbix_db") for n in t.getnames()):
                raise RuntimeError("secrets bundle incomplete")
    os.remove(dec)
    os.remove(raw)


def sha256(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def ensure_checkout():
    if not os.path.isdir(f"{CHECKOUT}/.git"):
        os.makedirs(WORK, exist_ok=True)
        run(["git", "clone", "-q", REPO_URL, CHECKOUT])
    git("config", "user.name", "Pi Network Monitoring backup (isp.picloud.in)")
    git("config", "user.email", "backup@isp.picloud.in")
    git("fetch", "-q", "origin")
    remote_main = run(["git", "-C", CHECKOUT, "rev-parse", "-q", "--verify", "origin/main"],
                      capture_output=True, check=False).returncode == 0
    if remote_main:
        git("checkout", "-q", "-B", "main", "origin/main")
    else:
        git("checkout", "-q", "--orphan", "main") if not git("branch", "--list", "main", capture=True) else \
            git("checkout", "-q", "main")


def local_backup(stamp, cfg_enc, sec_enc):
    d = f"{LOCAL}/{stamp}"
    os.makedirs(d, exist_ok=True)
    shutil.copy2(cfg_enc, d)
    shutil.copy2(sec_enc, d)
    # full DB incl. history (local only), compressed; unencrypted on purpose: the directory is root-only (0700)
    with open(f"{d}/zabbix-full.sql.zst", "wb") as out:
        p1 = subprocess.Popen(["mysqldump", "--single-transaction", "--quick", "--routines", "--triggers",
                               "--hex-blob", "--no-tablespaces", "--default-character-set=utf8mb4", DB],
                              stdout=subprocess.PIPE)
        p2 = subprocess.Popen(["zstd", "-q", "-3", "-T0"], stdin=p1.stdout, stdout=out)
        p1.stdout.close()
        if p2.wait() or p1.wait():
            raise RuntimeError("full database dump failed")
    run(["tar", "-C", "/var/lib", "-I", "zstd -q -T0", "-cf", f"{d}/smokeping-data.tar.zst", "smokeping"])
    for old in sorted(glob.glob(f"{LOCAL}/20*")):
        if os.path.getmtime(old) < time.time() - KEEP_LOCAL_DAYS * 86400:
            shutil.rmtree(old)
    return d


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
    os.umask(0o077)
    tmp = tempfile.mkdtemp(prefix="pi-netmon-backup-", dir="/var/tmp")
    try:
        ensure_checkout()
        secrets = secret_values()
        n = copy_deploy(secrets)
        scan_for_secrets(secrets)
        log(f"deployment tree: {n} files, no secrets in plain text")

        sec_tar = f"{tmp}/secrets.tar"
        with tarfile.open(sec_tar, "w") as t:
            for p in SECRETS:
                if os.path.exists(p):
                    t.add(p)
        zstd(sec_tar, sec_tar + ".zst")
        sec_enc = f"{tmp}/secrets.tar.zst.gpg"
        gpg_encrypt(sec_tar + ".zst", sec_enc)
        verify(sec_enc, "tar", tmp)

        sql = f"{tmp}/zabbix-config.sql"
        dump_config_db(sql)
        zstd(sql, sql + ".zst", level=15)
        cfg_enc = f"{tmp}/zabbix-config.sql.zst.gpg"
        gpg_encrypt(sql + ".zst", cfg_enc)
        verify(cfg_enc, "sql", tmp)
        log(f"encrypted + verified: config DB {os.path.getsize(cfg_enc) / 1e6:.1f} MB, "
            f"secrets {os.path.getsize(sec_enc) / 1e3:.0f} kB")

        if "--no-push" in sys.argv:   # check run: build and verify everything, push nothing
            git("add", "-A")
            log("--no-push: staged files:\n" + git("status", "--short", capture=True))
            return
        # main branch: deployment tree, commit only when something changed
        git("add", "-A")
        if git("status", "--porcelain", capture=True):
            git("commit", "-q", "-m", f"Deployment snapshot {stamp}")
        git("push", "-q", "origin", "main")
        main_rev = git("rev-parse", "HEAD", capture=True)

        # backups branch: exactly one commit with this (verified) run only, replacing the previous backup
        bdir = f"{tmp}/backups-branch"
        run(["git", "-C", CHECKOUT, "worktree", "add", "-q", "--detach", bdir], capture_output=True)
        try:
            run(["git", "-C", bdir, "checkout", "-q", "--orphan", "backups-new"])
            run(["git", "-C", bdir, "rm", "-rq", "--cached", "."], check=False, capture_output=True)
            for f in os.listdir(bdir):
                if f != ".git":
                    p = f"{bdir}/{f}"
                    shutil.rmtree(p) if os.path.isdir(p) else os.remove(p)
            shutil.copy2(cfg_enc, bdir)
            shutil.copy2(sec_enc, bdir)
            manifest = {
                "created": datetime.datetime.now().isoformat(timespec="seconds"), "host": os.uname().nodename,
                "deployment_commit_on_main": main_rev, "zabbix_version": run(
                    ["zabbix_server", "-V"], capture_output=True, text=True).stdout.splitlines()[0],
                "files": {f: {"bytes": os.path.getsize(f"{bdir}/{f}"), "sha256": sha256(f"{bdir}/{f}")}
                          for f in ("zabbix-config.sql.zst.gpg", "secrets.tar.zst.gpg")},
                "encryption": "gpg --symmetric AES256, passphrase /root/.credentials/backup_passphrase (not in git)",
            }
            open(f"{bdir}/MANIFEST.json", "w").write(json.dumps(manifest, indent=2) + "\n")
            open(f"{bdir}/README.md", "w").write(
                "# Latest successful backup\n\nOnly the last successful nightly backup is kept on this branch "
                "(force-pushed each night after verification). Restore instructions: RESTORE.md on branch main.\n")
            run(["git", "-C", bdir, "add", "-A"])
            run(["git", "-C", bdir, "commit", "-q", "-m", f"Backup {stamp}"])
            run(["git", "-C", bdir, "push", "-q", "-f", "origin", "HEAD:refs/heads/backups"])
        finally:
            run(["git", "-C", CHECKOUT, "worktree", "remove", "--force", bdir], check=False, capture_output=True)
            run(["git", "-C", CHECKOUT, "branch", "-D", "backups-new"], check=False, capture_output=True)
        log("pushed to GitHub: main + backups (latest only)")

        d = local_backup(stamp, cfg_enc, sec_enc)
        size = sum(os.path.getsize(p) for p in glob.glob(f"{d}/*")) / 1e9
        write_status(True, f"backup {stamp} pushed to GitHub, local copy {d} ({size:.2f} GB), "
                           f"{time.time() - started:.0f}s")
        log(f"done: local copy {d} ({size:.2f} GB)")
    except Exception as e:
        write_status(False, f"backup {stamp}: {str(e)[:300]}")
        log(f"FAILED: {e}")
        raise
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
