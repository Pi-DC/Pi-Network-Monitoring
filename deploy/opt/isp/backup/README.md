# Pi Network Monitoring (isp.picloud.in)

Zabbix 7.0 + SmokePing monitoring for the PIDC network: A10 load balancer and the three ISP links (Airtel, Jio,
PowerGrid), ASR edge routers, and the switch fabrics (WAN, PiSB cloud, VMware 100G, MMR / DH5 cross-connect,
1G colo). Runs on one Ubuntu 24.04 VM (172.20.119.99).

This repository is the **complete deployment and its nightly backup**. To rebuild the tool: **[RESTORE.md](RESTORE.md)**.

## Branches

| Branch | Contents | Updated |
|---|---|---|
| `main` | Every script and configuration file of the tool under `deploy/` (paths as on the server: `deploy/opt/isp/...`, `deploy/etc/...`), package list, Apache module list, file owners, `restore.sh`, this README and RESTORE.md. **Passwords and SNMP communities are replaced by `__REDACTED__`.** | Nightly, a commit only when something changed |
| `backups` | **Only the latest successful backup**: `zabbix-config.sql.zst.gpg` (Zabbix configuration database), `secrets.tar.zst.gpg` (all credentials, TLS keys, original config files), `MANIFEST.json` (time, sizes, SHA-256, matching `main` commit) | Replaced every night at 21:00 IST, only after the new backup was verified |

The two `.gpg` files are AES-256 encrypted with the **backup passphrase**, which is never stored in git. Keep a
copy of it outside the server (password manager): without it these files cannot be opened.

## What lives where

| Path on the server | What |
|---|---|
| `/opt/isp/zabbix/` | Python scripts that build hosts, templates, alerts and dashboards through the Zabbix API (`add_*.py`, `build_*dashboard.py`, `click_to_graph.py`, `set_default_thresholds.py`, `sync_daily_reports.py`, `setup_email_alerts.py`) |
| `/opt/isp/reports/` | https://isp.picloud.in/reports - dashboard PDF and data reports (PDF/CSV) |
| `/opt/isp/smokeping-gui/` | https://isp.picloud.in/smokeping-admin - SmokePing target editor |
| `/opt/isp/ssl/` | Let's Encrypt issue / DNS-01 hook scripts (acme-dns) |
| `/opt/isp/backup/` | `backup.py` (nightly), `restore.sh`, these docs |
| `/etc/zabbix/` | Zabbix server, agent 2, web service, frontend configuration |
| `/etc/apache2/` | `isp.picloud.in` HTTPS vhost, reports / print / SmokePing confs |
| `/etc/mysql/mariadb.conf.d/60-zabbix-tuning.cnf` | MariaDB sizing for the 24 GB VM |
| `/etc/cron.d/` | `zabbix-click-to-graph` (10 min), `zabbix-daily-reports` (hourly), `zabbix-default-thresholds` (hourly), `pi-netmon-backup` (21:00) |
| `/root/.credentials/` | All passwords / communities / the backup passphrase (only in the encrypted bundle) |

## Nightly backup (21:00 IST)

`/etc/cron.d/pi-netmon-backup` runs `/opt/isp/backup/backup.py`; log `/var/log/pi-netmon-backup.log`.

1. Copies the deployment into `main` with every secret redacted; a scan stops the push if any secret is left in plain text.
2. Encrypts the secrets bundle and the Zabbix configuration database, then decrypts both again and checks them.
3. Pushes `main` (if changed) and replaces `backups` with this run only.
4. Keeps a **local** copy for 14 days in `/var/backups/pi-network-monitoring/<date>/`: the two encrypted files plus the **full database with all graph history** and the **SmokePing data** (too large for git).
5. Writes `/var/lib/pi-netmon-backup/status/last-result`; Zabbix alerts by e-mail if a backup fails or none succeeded for 26 hours.

Run it by hand: `sudo /opt/isp/backup/backup.py`
