# Pi Network Monitoring (isp.picloud.in)

Zabbix 7.0 monitoring for the PIDC network: the A10 load balancer and the three ISP links (Airtel,
Jio, PowerGrid), the ASR edge routers, and the switch fabrics (WAN, PiSB cloud, VMware 100G, MMR / DH5
cross-connect, 1G colo). Runs on one Ubuntu 24.04 VM, 172.20.119.99 (24 GB RAM, 8 vCPU).

This repository holds the tool's **complete configuration, documentation and change history**. The data backups
(database, graph history, secrets) are on the **NFS share**, encrypted. To rebuild the tool: **[RESTORE.md](RESTORE.md)**.

**Scope: the Zabbix tool only.** SmokePing (/smokeping, /smokeping-admin) also runs on this server but is deliberately
not kept in this repository or in the backups; after a full restore it has to be set up again separately.

| Document | |
|---|---|
| [RESTORE.md](RESTORE.md) | How to restore: single files, the database, or the whole server |
| [CHANGELOG.md](CHANGELOG.md) | What was built and changed, by date |
| [docs/INVENTORY.md](docs/INVENTORY.md) | Every monitored device, dashboard, alert rule and scheduled job (generated nightly) |

## Web interfaces

| URL | What |
|---|---|
| https://isp.picloud.in/zabbix | Zabbix: dashboards, problems, configuration |
| https://isp.picloud.in/reports | Dashboard PDF (with per-port / per-item charts) and data reports (PDF / CSV) |

## Repository layout

| Path | Contents |
|---|---|
| `deploy/` | Every script and configuration file, at its path on the server (`deploy/opt/isp/...`, `deploy/etc/...`). **Passwords and SNMP communities are replaced by `__REDACTED__`**; the real values are only in the encrypted secrets bundle on NFS. |
| `packages/` | Installed package versions, enabled Apache modules / sites, file owners and modes, time zone |
| `docs/INVENTORY.md` | Generated nightly from Zabbix |
| `restore.sh` | Rebuilds the tool on a fresh Ubuntu 24.04 server |

## On the server

| Path | What |
|---|---|
| `/opt/isp/zabbix/` | Python scripts that build hosts, templates, alerts and dashboards through the Zabbix API: `add_*.py` (devices), `build_*dashboard.py`, `click_to_graph.py`, `set_default_thresholds.py`, `sync_daily_reports.py`, `setup_email_alerts.py`, `setup_backup_monitoring.py` |
| `/opt/isp/reports/` | The /reports site |
| `/opt/isp/ssl/` | Let's Encrypt (DNS-01 via acme-dns) scripts |
| `/opt/isp/backup/` | `backup.py`, `restore.sh`, these documents |
| `/etc/zabbix/`, `/etc/apache2/`, `/etc/mysql/mariadb.conf.d/60-zabbix-tuning.cnf` | Service configuration |
| `/etc/cron.d/` | `zabbix-click-to-graph` (10 min), `zabbix-daily-reports` (hourly), `zabbix-default-thresholds` (hourly), `pi-netmon-backup` (21:00) |
| `/root/.credentials/` | Passwords, SNMP communities, backup passphrase (root only; backed up only inside the encrypted bundle) |

## Nightly backup - 21:00 IST

`/etc/cron.d/pi-netmon-backup` runs `/opt/isp/backup/backup.py` (log: `/var/log/pi-netmon-backup.log`).

1. **Git** (this repository, branch `main`): copies every script and config file with secrets redacted, regenerates
   `docs/INVENTORY.md`, and refuses to push if any secret value is found in plain text. Commits only when something changed.
2. **Encrypted data files** (gpg AES-256): full Zabbix database incl. graph history, configuration-only database,
   secrets bundle. Each file is decrypted and checked again before it is copied anywhere.
3. **NFS** `172.16.95.5:/Repo_BDR/Pi-Network-Monitoring` (mounted on `/mnt/pi-netmon-nfs`): one folder per night,
   e.g. `2026-10-09_2100/`, with `MANIFEST.json` (sizes, SHA-256, matching git commit). A folder gets its final name
   only after every file was copied and its checksum re-read; `LATEST.txt` names the newest. **14 nights kept.**
4. **No local copy**: backups are kept only on NFS (and git), never on the server's own disk.
5. **Zabbix watches it**: host *Zabbix server*, items *Backup: last result* / *Backup: last success time*;
   High alert by e-mail if a backup fails or none succeeded for 26 hours.

Manual run: `sudo /opt/isp/backup/backup.py`. Check run that pushes and copies nothing: `--no-push`.

### The backup passphrase

All data files are encrypted with the passphrase in `/root/.credentials/backup_passphrase`. **Keep a copy outside the
server** (password manager). It is never stored in git or on NFS. Without it the backups cannot be opened.
