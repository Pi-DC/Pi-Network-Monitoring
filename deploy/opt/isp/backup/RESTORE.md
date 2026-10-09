# Restore guide

Three situations, from small to large. All need **root** on the server.

| Situation | What to do | Graph history |
|---|---|---|
| A. A file or script was changed by mistake | [Restore single files](#a-restore-single-files-from-git) from `main` | kept |
| B. Zabbix configuration damaged (hosts, dashboards, alert rules deleted) but the server is fine | [Restore the database](#b-restore-the-zabbix-database-on-the-same-server) | from the local full backup: kept; from GitHub: lost |
| C. Server lost / rebuilt | [Full restore](#c-full-restore-on-a-new-server) on a fresh Ubuntu 24.04 VM | only if a local backup folder survived |

You always need the **backup passphrase** (kept outside the server; on a working server it is in
`/root/.credentials/backup_passphrase`).

---

## A. Restore single files from git

```bash
cd /var/lib/pi-netmon-backup/repo && git fetch origin
git log --oneline -- deploy/opt/isp/zabbix/build_fabric_dashboard.py      # pick a version
git show <commit>:deploy/opt/isp/zabbix/build_fabric_dashboard.py > /opt/isp/zabbix/build_fabric_dashboard.py
```
Files containing passwords (`zabbix_server.conf`, `zabbix.conf.php`) are redacted in git - take those from the
secrets bundle (section B, step 2) or edit only the lines you need.

---

## B. Restore the Zabbix database on the same server

1. **Pick the backup.** Local (has graph history): `ls /var/backups/pi-network-monitoring/` (last 14 nights).
   GitHub (configuration only): branch `backups`.
2. **Get the files** (GitHub case):
   ```bash
   cd /var/lib/pi-netmon-backup/repo && git fetch origin backups
   git show origin/backups:zabbix-config.sql.zst.gpg > /var/tmp/zabbix-config.sql.zst.gpg
   gpg --batch --pinentry-mode loopback --passphrase-file /root/.credentials/backup_passphrase \
       --decrypt -o /var/tmp/zabbix-config.sql.zst /var/tmp/zabbix-config.sql.zst.gpg
   ```
   (Secrets bundle the same way: `secrets.tar.zst.gpg` → `tar -I zstd -tvf` to list, `-xpf ... -C /` to restore.)
3. **Stop Zabbix and replace the database** (MariaDB and Zabbix are restarted in separate commands):
   ```bash
   systemctl stop zabbix-server
   mysql -e "DROP DATABASE zabbix; CREATE DATABASE zabbix CHARACTER SET utf8mb4 COLLATE utf8mb4_bin;"
   # either the local full backup (with history):
   zstd -d -c /var/backups/pi-network-monitoring/<date>/zabbix-full.sql.zst | mysql zabbix
   # or the GitHub configuration backup (no history):
   zstd -d -c /var/tmp/zabbix-config.sql.zst | mysql zabbix
   systemctl start zabbix-server
   ```
4. Check https://isp.picloud.in/zabbix (dashboards, hosts), then `rm /var/tmp/zabbix-config.sql*`.

---

## C. Full restore on a new server

Needs: a fresh **Ubuntu 24.04** VM (24 GB RAM, 8 vCPU, 500 GB disk like the original), internet access to
GitHub, repo.zabbix.com and dl.google.com, and the backup passphrase.

1. **GitHub access for the new server**
   ```bash
   ssh-keygen -t ed25519 -N "" -f /root/.ssh/id_ed25519
   cat /root/.ssh/id_ed25519.pub        # add as a deploy key (write access) on Pi-DC/Pi-Network-Monitoring
   printf 'Host github.com\n    Hostname ssh.github.com\n    Port 443\n    User git\n' > /root/.ssh/config
   ```
2. **Clone and run the restore**
   ```bash
   apt-get update && apt-get install -y git
   git clone git@github.com:Pi-DC/Pi-Network-Monitoring.git /var/lib/pi-netmon-backup/repo
   install -m 600 /dev/null /root/backup_passphrase && nano /root/backup_passphrase     # paste the passphrase
   /var/lib/pi-netmon-backup/repo/restore.sh --passphrase-file /root/backup_passphrase
   ```
   If a nightly folder from the old server's `/var/backups/pi-network-monitoring/` survived (VM snapshot,
   copy), copy it over and add `--local-backup /path/to/<date>` to get the graph history and SmokePing data back.

   `restore.sh` does: installs Zabbix 7.0 / MariaDB / Apache+PHP / SmokePing / Chrome / tools → puts every
   configuration file and script back (real passwords from the encrypted bundle, owners and modes as before) →
   MariaDB tuning, `zabbix` database and user → imports the database → SmokePing data (if given) → enables the
   Apache modules / sites → starts all services and prints their state.
3. **After the restore**
   - Same IP (172.20.119.99) is easiest. Otherwise point `isp.picloud.in` (internal DNS) at the new IP, and
     allow SNMP from the new IP on every device (A10, routers, switches have SNMP ACLs).
   - Open https://isp.picloud.in/zabbix (Admin account as before), /reports and /smokeping.
   - Within ~2 minutes data arrives again (Monitoring → Latest data); the 15-minute queue should be empty.
   - The TLS certificate comes back from the bundle; renewal works as before (acme-dns).
   - `rm /root/backup_passphrase` (the passphrase now lives in `/root/.credentials/backup_passphrase`).
   - Run one backup by hand: `/opt/isp/backup/backup.py` (the 21:00 cron job is restored too).

---

## Checking that backups work

- Last result: `cat /var/lib/pi-netmon-backup/status/last-result` (also in Zabbix: host *Zabbix server*,
  item *Backup: last result*; e-mail alert if a backup fails or none succeeded for 26 h).
- Log: `/var/log/pi-netmon-backup.log`
- GitHub: branch `backups` → `MANIFEST.json` shows the time of the last successful backup.
- Test that a backup opens (no changes to the system):
  ```bash
  cd /var/lib/pi-netmon-backup/repo && git fetch -q origin backups
  git show origin/backups:zabbix-config.sql.zst.gpg | gpg --batch --pinentry-mode loopback \
    --passphrase-file /root/.credentials/backup_passphrase -d | zstd -d | tail -1      # "-- Dump completed ..."
  ```

## Changing the passphrase

Write the new one to `/root/.credentials/backup_passphrase` (mode 600), run `/opt/isp/backup/backup.py`, store the
new passphrase outside the server. The `backups` branch only ever holds the latest backup, so the old passphrase
is no longer needed after that run.
