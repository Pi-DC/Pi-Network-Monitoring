# Changelog

Changes to the Pi Network Monitoring tool, newest first. Every configuration change is also visible in the git
history of `deploy/` (nightly "Configuration snapshot" commits).

## 2026-10-09

### Backups
- Scope reduced to the Zabbix tool: SmokePing (configuration, /smokeping-admin editor, data, logins) removed from
  the repository and from the backups; it keeps running on the server but is not backed up.
- Nightly backup at 21:00 IST (`/opt/isp/backup/backup.py`): configuration + documentation to this repository
  (secrets redacted, push blocked if any secret is found); encrypted data backups (full database incl. graph
  history, configuration database, secrets bundle) to NFS `172.16.95.5:/Repo_BDR/Pi-Network-Monitoring`
  (14 nights) and locally (3 nights). Zabbix alerts when a backup fails or none succeeded for 26 h.
- `restore.sh` and RESTORE.md for single files, the database, or a full rebuild on a new server.
- Zabbix database password rotated.

### Devices added
- **Pi VMware Fabric**: 100G spines 1/2 (Arista 7280CR-48), leaves 1/2 (Arista 7050SX3), 5/6 (Arista 7150S-24),
  leaf 7&8 (HPE 5820AF IRF). Leaf 3&4 (172.20.96.16) added disabled - not reachable by ping/SNMP; later the
  same day it answered and is now monitored: Huawei S6720S-26Q-EI-24S-AC 2-member iStack on
  *Huawei VRP by SNMP - PIDC*. `add_vmware_fabric.py` now also brings existing hosts in line with its switch list
  (name, template, vendor tag, enabled).
- *Huawei VRP by SNMP - PIDC*: power supply monitoring (hwPwrStatusTable): discovers only PSUs the switch names
  as installed (empty slots, which report "notSupply", are skipped), status per PSU, alert when not supplying
  power; feeds "Health: Power supplies not OK". S5720-LI has no such table (nothing discovered).
- **Uptime fixed on all SNMP devices**: sysUpTime / hrSystemUptime are 32-bit and wrap to 0 every 497.1 days, so
  17 devices showed 497 days too little (e.g. 10G-WAN-Switch02 98 days instead of 85 weeks). "Uptime (network)" /
  "Uptime (hardware)" are now calculated: raw value + 497.1 days x wraps, wraps derived from snmpEngineTime (raw
  values kept as "SNMP raw: ..." items). `fix_uptime_wrap.py`, hourly cron `/etc/cron.d/zabbix-uptime-wrap`, covers
  every SNMP template linked to a host (incl. stock "Generic by SNMP" used by the A10).
- **Pi 1G Colo Fabric**: added 1G-COLO-DH4-SW1 10.128.79.50 (DH4-AD39-Colo-SW1, Cisco Catalyst 3650-24TS,
  IOS-XE 16.12.7) on *Cisco Catalyst by SNMP - PIDC*, with its own dashboard page; `add_cross_connect_fabrics.py`
  switch entries may now override template and vendor (the group is otherwise Huawei).
- Pi 1G Colo Fabric: hosts 1G-COLO-SW1/SW2/SW3 renamed to 1G-COLO-DH5-SW1/SW2/SW3 (history kept).
- **Pi MMR Cross Connect Fabric**: MMR1 SW1-SW5 (Cisco Catalyst 2960 / 2960S / 4500 / 2960X).
- **Pi DH5 Cross Connect Fabric**: DH5 SW1-SW4 (Cisco Catalyst 2960 / 2960S / 4500).
- **Pi 1G Colo Fabric**: 1G-COLO SW1-SW3 (Huawei S5720).
- New tuned templates: *HPE Comware by SNMP - PIDC*, *Cisco Catalyst by SNMP - PIDC*, *Huawei VRP by SNMP - PIDC*
  (traffic every 10 s, status 30 s, errors 1 min, Port state); vendor-neutral "Health: ..." items on all switch
  templates (CPU, memory, hottest sensor, fans / PSUs not OK, all-port errors and discards).
- ASR routers (ASR_RTR-1 Airtel, ASR_RTR-2 Jio, Cisco ASR920): interfaces, sensors, PSU / fans, BGP peers;
  dashboard *ASR Routers*.

### Dashboards and reports
- Fabric dashboards (one per fabric): health table, port maps, per-switch pages; tiles for temperature, fans and
  PSUs only on switches that report them.
- Click-to-graph on every dashboard: each port map and item list has a graph of the clicked item; every page has an
  "Items on this page" list. Applied automatically every 10 minutes to new devices / dashboards (`click_to_graph.py`).
- /reports: Dashboard PDF gets per-port (traffic, errors, speed, time up) and per-item charts; Data report PDF/CSV;
  fix for an endless chart-axis loop on flat negative series (HTTP 500).
- Daily 08:00 PDF e-mail for every dashboard (`sync_daily_reports.py`); PDF links removed.

### Alerting and thresholds
- Default thresholds on every device: CPU 75 %, memory 85 % (`set_default_thresholds.py`, hourly);
  exceptions: 100G leaves 1/2 memory 99 %.
- E-mail alerts (Average and above) for the A10, all device groups and the Zabbix server itself.

### Platform
- VM raised to 24 GB: Zabbix caches (config 1 GB, value 1 GB, history 512 MB, ...), MariaDB buffer pool 8 GB,
  PHP 512 MB (frontend) / 2 GB (reports), OOM protection for MariaDB and the Zabbix server.
- History 180 days, trends 2 years.

## 2026-10-08

- Zabbix 7.0 + SmokePing server set up on 172.20.119.99 (time zone IST), served as https://isp.picloud.in
  (Let's Encrypt via acme-dns, auto-renewing; certificate expiry alerts).
- A10 LLB: the three ISP links (Airtel, Jio, PowerGrid) - port state, gateway reachability, A10 gateway status,
  utilisation, traffic every 5 s from the A10 private counters, LLB statistics; SLA / customer view (*ISP Link Status*).
- WAN switches (10G-WAN-Switch01/02) and PiSB cloud fabric (spines / leaves), Arista template tuning, Port state.
- SmokePing targets editor (/smokeping-admin), report downloader (/reports), e-mail alerts via Office 365.
