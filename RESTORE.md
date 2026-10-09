# Restore guide

Scope: the Zabbix tool (Zabbix, /reports, Apache / HTTPS, MariaDB, cron jobs). SmokePing is not backed up.

Configuration comes from this git repository; data (database, graph history, secrets) from the
encrypted nightly backups on NFS `172.16.95.5:/Repo_BDR/Pi-Network-Monitoring` (mounted on `/mnt/pi-netmon-nfs`;
14 nights; no copy is kept on the server itself). All commands as **root**.

You always need the **backup passphrase** (kept outside the server; on a working server it is
`/root/.credentials/backup_passphrase`).

| Situation | What to do | Graph history |
|---|---|---|
| A. A script or config file was changed by mistake | [Restore files from git](#a-restore-files-from-git) | kept |
| B. Zabbix configuration damaged (hosts, dashboards, alert rules deleted), server fine | [Restore the database](#b-restore-the-database-on-the-same-server) | back to the backup night |
| C. Server lost or rebuilt | [Full restore](#c-full-restore-on-a-new-server) on a fresh Ubuntu 24.04 VM | back to the backup night |

Backup folders (newest first): `ls -1r /mnt/pi-netmon-nfs/ | head` - each has `MANIFEST.json`; `LATEST.txt` names the newest.

| File in a backup folder | Contents |
|---|---|
| `zabbix-full.sql.zst.gpg` | Whole Zabbix database incl. graph history |
| `zabbix-config.sql.zst.gpg` | Configuration only (hosts, templates, items, triggers, dashboards, users, alerts, reports) - small |
| `secrets.tar.zst.gpg` | `/root/.credentials`, `/etc/letsencrypt` (TLS keys), original `zabbix_server.conf` / `zabbix.conf.php` |

Helper used below (decrypt + decompress to stdout):
```bash
dec() { gpg --batch --quiet --pinentry-mode loopback --passphrase-file /root/.credentials/backup_passphrase -d "$1" | zstd -q -d -c; }
```

---

## A. Restore files from git

```bash
cd /var/lib/pi-netmon-backup/repo && git fetch -q origin
git log --oneline -- deploy/opt/isp/zabbix/build_fabric_dashboard.py           # pick a version
git show <commit>:deploy/opt/isp/zabbix/build_fabric_dashboard.py > /opt/isp/zabbix/build_fabric_dashboard.py
```
Files with passwords (`zabbix_server.conf`, `zabbix.conf.php`) are redacted in git: take those from the secrets
bundle, e.g. `dec /mnt/pi-netmon-nfs/<date>/secrets.tar.zst.gpg | tar -xpf - -C / etc/zabbix/zabbix_server.conf`.

---

## B. Restore the database on the same server

```bash
B=/mnt/pi-netmon-nfs/$(cat /mnt/pi-netmon-nfs/LATEST.txt)     # or another night's folder
systemctl stop zabbix-server
mysql -e "DROP DATABASE zabbix; CREATE DATABASE zabbix CHARACTER SET utf8mb4 COLLATE utf8mb4_bin;"
dec $B/zabbix-full.sql.zst.gpg | mysql zabbix                   # with graph history
#   or: dec $B/zabbix-config.sql.zst.gpg | mysql zabbix          # configuration only, much faster
systemctl start zabbix-server                                   # MariaDB and Zabbix: restart separately, never together
```
Then check https://isp.picloud.in/zabbix.

---

## C. Full restore on a new server

Needs: fresh **Ubuntu 24.04** VM (24 GB RAM, 8 vCPU, 500 GB disk), access to GitHub, repo.zabbix.com,
dl.google.com and the NFS server 172.16.95.5, and the backup passphrase.

1. **GitHub access**
   ```bash
   ssh-keygen -t ed25519 -N "" -f /root/.ssh/id_ed25519
   cat /root/.ssh/id_ed25519.pub     # add as a deploy key with write access on Pi-DC/Pi-Network-Monitoring
   printf 'Host github.com\n    Hostname ssh.github.com\n    Port 443\n    User git\n' > /root/.ssh/config
   ```
2. **Clone and restore**
   ```bash
   apt-get update && apt-get install -y git
   git clone git@github.com:Pi-DC/Pi-Network-Monitoring.git /var/lib/pi-netmon-backup/repo
   install -m 600 /dev/null /root/backup_passphrase && nano /root/backup_passphrase    # paste the passphrase
   /var/lib/pi-netmon-backup/repo/restore.sh --passphrase-file /root/backup_passphrase
   ```
   Options: `--backup-dir /mnt/pi-netmon-nfs/<date>` for an older night; `--config-only` to skip graph history.

   `restore.sh`: mounts the NFS share (fstab automount) and checks the backup's checksums → installs Zabbix 7.0,
   MariaDB, Apache + PHP, Chrome and tools → puts every script and config file back (real passwords from
   the secrets bundle, owners and modes as recorded) → MariaDB tuning, `zabbix` database and user → imports the
   database → Apache modules / sites → starts everything and prints the service states.
3. **After the restore**
   - Same IP (172.20.119.99) is easiest. Otherwise point `isp.picloud.in` (internal DNS) at the new IP and allow
     SNMP from it on every device (A10, routers and switches have SNMP ACLs).
   - Open https://isp.picloud.in/zabbix (same accounts) and /reports. Data arrives within ~2 minutes.
   - SmokePing is not part of the backup: install and configure it separately if it is wanted on the new server.
   - The TLS certificate comes from the bundle; renewal works as before.
   - `rm /root/backup_passphrase` (it is now in `/root/.credentials/backup_passphrase`).
   - Run one backup by hand: `/opt/isp/backup/backup.py`.

---

## Checking the backups

- Last result: `cat /var/lib/pi-netmon-backup/status/last-result` (also Zabbix → host *Zabbix server* →
  *Backup: last result*; e-mail if a backup fails or none succeeded for 26 h). Log: `/var/log/pi-netmon-backup.log`.
- Test that a backup opens, without changing anything:
  ```bash
  B=/mnt/pi-netmon-nfs/$(cat /mnt/pi-netmon-nfs/LATEST.txt); dec $B/zabbix-config.sql.zst.gpg | tail -1   # "-- Dump completed ..."
  ```

## Changing the passphrase

Write the new one to `/root/.credentials/backup_passphrase` (mode 600) and store it outside the server. Backups made
before keep the old passphrase - keep the old one until those have rotated out (14 nights).
