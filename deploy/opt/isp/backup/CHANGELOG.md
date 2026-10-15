# Changelog

Changes to the Pi Network Monitoring tool, newest first. Every configuration change is also visible in the git
history of `deploy/` (nightly "Configuration snapshot" commits).

## 2026-10-15

### SNMP fleet audit (switches, firewalls, routers, A10)
- Discovery: the old-style `discovery[]` LLD rules of 'Huawei VRP by SNMP - PIDC' and 'HPE Comware by SNMP - PIDC'
  (12 rules) are now `walk[]` + "SNMP walk to JSON" with a 15 s timeout (`zabbix/walk_discovery.py`). They timed out
  at the global 10 s about every other hour on the S5720-LI switches and the HPE 5820, so new ports/sensors could
  go undiscovered for hours. Same rule keys - no item, trigger or history lost (checked on all 7 hosts).
  10G_Leaf_SW-7-8 temperature discovery works again and is no longer disabled.
- Device quirks: the model-template relink of 2026-10-14 had re-enabled 22 items the devices cannot answer
  (stack ring on standalone switches, BRIDGE-MIB STP on PVST 3650s, SonicWall snmpEngineTime / FCS total,
  FortiGate free-disk % without a disk). `fix_snmp_quirks.py` lists them all again, and `model_templates.py` now
  re-applies the quirks whenever it moves a host.
- GE17-PiSB-Forti120G: IP-pool items (fg.ippool.walk/json/max/worst) disabled on the host again (user approved;
  they were disabled before and re-enabled by the relink). The 120G never answers that table, and the hanging
  15-min walk stalled its SNMP agent so ~511 CPU / dial-up VPN items went unsupported for ~25 s at :01/:16/:31/:46.
  This also removes that host's "IP pool over 90% used" trigger, which could never fire there.
- HPE 10G_Leaf_SW-7-8: both IRF members call their main board "Board", so CPU/memory items, triggers and graphs
  had the same name and LLD refused the second graph. module.discovery now adds the IRF member to duplicate names
  ("Board (member 1): CPU utilization"; `walk_discovery.module_names`). Keys unchanged, history kept.
- FortiGate Health tiles (fans not OK, PSUs not OK, highest temperature) work: sensors get a `sensor_type` tag from
  their name (fan / temp / psu / psu_reading / voltage / other), a numeric 'Sensor X: Reading' item comes from the
  same walk (the stock value item is text), and the Health formulas use them (`add_firewall_detail.sensor_health`);
  `build_fabric_dashboard.has_sensor` recognises the tags. PSU state counts sensors 'PSU [n]' / 'PSn Status' with a
  value other than 1 - Fortigate-300E shows 1 (PS2 reads -1 on every sensor).
- Alerts for everything (user request): every health/state item now has an e-mailed alert (>= Warning).
  - Reboot: "Device has been restarted (uptime ...)" (Warning, uptime < 10 min, from the device's own uptime) on
    the Cisco Catalyst, Cisco ASR920, Huawei VRP, HPE Comware, Juniper and SonicWall templates - 25 devices had no
    reboot alert. `device_uptime.restart_trigger`, run by the hourly `--setup`, so new vendor templates get it too.
  - FortiGate: "Power supply not OK" (Average) from Health: PSUs not OK - fires on Fortigate-300E (PS2 reports
    nothing; the FortiGate's own alarm flag stays off).
  - Temperature sensors (`add_alert_coverage.py`): Arista sensor nonoperational (Warning); Cisco Catalyst
    temperature state warning (Warning) / critical, shutdown, not functioning (High).
  - Remaining items without a trigger are counters, rates, inventory text or companions of items that alert
    (checked per category); SonicWall and A10 report no fan/PSU/temperature data over SNMP.
- FortiGate BGP flapping summary (user request after the 120G SD-WAN hub showed 337 branch peer drops in 24 h;
  `add_model_items.fortigate_bgp_flapping`): bgpPeerFsmEstablishedTransitions added to the BGP walk; per peer
  'session resets (counter)' + 'resets in the last hour / 5 minutes' (changecount of increases, so counter restarts
  of re-created dynamic peers don't count; also catches resets shorter than the 1-minute state poll). Summary items
  'BGP: peers flapping', 'BGP: session resets in the last hour', 'BGP: peers reset in the last 5 minutes'. Alerts:
  "Branch BGP flapping: N peer(s) reset {$BGP.FLAP.MAX}(3)+ times in the last hour" (Warning) and "Mass BGP reset:
  N peers reset within 5 minutes" (>= {$BGP.MASS.RESET.MIN} = 10, Average). Per-peer alerts unchanged.
- Management ports: Huawei MEth (10G_Leaf_SW-3-4, H1-SPINE3-4) and Juniper bme0 are now discovered
  (`{$NET.IF.IFNAME.NOT_MATCHES}` / Juniper `{$NET.IF.IFNAME.MATCHES}`); the A10 management port gained admin status,
  speed, errors/discards and a link-down trigger (`add_a10_full.py`).

## 2026-10-13

### E-mail: subject tag, sender and recipients
- Every e-mail subject now starts with `[Network-Monitoring]` (Zabbix alert / recovery / update templates of the
  Office365 media type, daily PDF reports, watchdog, SSL renewal hook, disabled native "Daily:" reports), so
  mailboxes can filter all monitoring mail with one rule. `setup_email_alerts.SUBJECT_PREFIX`, applied by
  `apply_subject_prefix()`.
- One sender for every mailer: `/root/.credentials/smtp_sender` + `smtp_password` (`setup_email_alerts.SENDER_FILE`
  / `PASSWORD_FILE`, `apply_sender()` updates the media type); daily reports, watchdog and the SSL hook read the
  same files. Sender stays alerts@pidatacenters.com: switching to monitoring@ was tested and cancelled (Office365
  rejected every send with 554 5.2.2 MessagesPerFolderCount quota on that mailbox).
- Recipients: alerts (ISP link, SSL certificate, disk space) -> compute@ + network@ (disk: compute@) +
  monitoring@pidatacenters.com (Pi-Monitoring user, alerts only). Daily PDF reports, watchdog and SSL renewal
  mails -> compute@ + network@ only.
- backup.py: `--message` for a descriptive commit title on manual runs; `smtp_sender` is not treated as a secret.

### Fleet audit (all 44 enabled hosts) and fixes (`fix_snmp_quirks.py`, idempotent)
- Checked every host: interfaces available (only 1G-VDOM-SW waits for SNMP), no stale items (heartbeats taken
  into account), never-filled items only the SNMP-trap fallbacks (no traps configured), 52 unsupported items and
  6 discovery-rule timeouts -> now 0 unsupported.
- Catalyst 2960+ (DH5_CC_SW1, MMR1_CC_SW1): model / serial read from entPhysical index {$ENT.CHASSIS.INDEX}
  (template default 1, these hosts 1001) - they were unsupported.
- Global SNMP agent timeout 3 s -> 10 s: old-style discovery[] rules (no per-item timeout) timed out on the stacked
  10G_Leaf_SW-3-4 / 7-8. 10G_Leaf_SW-7-8 temp.discovery disabled on the host (HPE agent stalls in entPhysicalDescr;
  temperatures still come from the health items).
- Disabled on the hosts only (the device does not report them): management-port broadcast / multicast counters,
  stack-ring state on standalone 2960s, BRIDGE-MIB STP on per-VLAN-STP switches, the unused half of the 2960X
  dual-purpose uplinks (MMR1_CC_SW5 Gi1/0/49, Te1/0/2), Zabbix server self-monitoring of processes that are not
  configured. These items had written ~670 log lines each per day.
- Reports verified: daily PDF dry run of all 17 dashboards, /reports CSV time series + summary + data PDF and
  Dashboard PDF (Pi Firewall Fabric, 22 pages + detail charts = 278 pages, 63 s) as the read-only user; no
  Zabbix / Apache / PHP / MariaDB / web-service crashes, no OOM.

### Fortigate-300E added (172.16.32.127, community in `fortigate_300e_snmp_community`)
- Was 172.16.132.127 (unreachable); upgraded to 'FortiGate by SNMP - PIDC' with all detail items; HA active-passive
  pair Pi-AMR-Forti-2 (primary, polled) / Pi-AMR-Forti-1. 'Free disk percentage' disabled on the host (no disk).
- Template fix: the stock FortiAP items read the WTP session table, which the AP walk did not include (every AP item
  failed); the walk now covers it. {$WC.ID.NOT_MATCHES} filters the FortiOS factory sample AP 'AP-11N-SERIAL-0001'.

### Firewalls: detailed monitoring (`add_firewall_detail.py`, called by `add_firewalls.py`)
- FortiGate (all counters over every VDOM; the stock IPS / SSL VPN items read VDOM 1 only and the VDOM-1 IPS items
  are disabled): IPsec per phase-2 selector (status, traffic, phase-1 / peer / VDOM) and per phase-1 tunnel (state,
  selectors up, traffic) + totals; dial-up clients per gateway + client list; SSL VPN users / tunnels / web sessions,
  connected-user list (text, 180 d) and per-user sessions / traffic; FortiGuard contracts (days to expiry, alerts at
  60 / 15 / 0 d), definition packages (version, age; alerts for AV / IPS / botnet / URL / app definitions), hours since
  the last update check; IPS / AV / web filter / VoIP / P2P per minute per VDOM and total; session setup rate, NPU and
  ephemeral session tables, conserve-mode memory alert (88%), reboot reason, configuration revision / last change,
  DHCP / IP-pool use, log devices (sent / failed / dropped, alerts; FortiGuard cloud log 'fds' excluded), policy
  audit (no traffic since boot, idle 30 / 90 d, list), HA members / failover / sync alerts, hardware sensor alarms.
- The stock 'Tunnel down' trigger cleared itself one poll after firing; it now alerts when a selector that was up
  in the last 24 h is down 5 min and stays open until it is up again.
- SonicWall: per VPN policy SAs / peers / traffic, SA list, syslog messages per minute (alert when none for 15 min),
  content filter state, DPI-SSL peak, security services per zone.
- Dashboard 'Pi Firewall Fabric': new pages '<FortiGate> – VPN & users', '<FortiGate> – security & FortiGuard',
  '<SonicWall> – VPN & security'; Overview table adds IPsec tunnels down, SSL VPN users, FortiGuard days left.
- Firewall walk items use a 15 s timeout (3 s timed out on the 120G when walks overlapped). Text items are tagged
  'value: text' and excluded from navigators that feed follow graphs (keeps the dashboard PDF working).
- 120G: IP-pool walk disabled on the host (FortiOS 7.6 agent never answers that table).
- `add_firewall_detail.py --rediscover` re-runs the stock discovery rules on the hosts at once (they otherwise pick up
  new prototypes only on their 1 h heartbeat).
- Load: ~700 -> ~970 values/s.

### Pi Firewall Fabric: TZ500 GNOC, FortiGate 120G and 200F now fully monitored
- Sonicwall-TZ500-GNOC moved to 10.128.16.22 (community updated in `/root/.credentials/sonicwall_tz500_snmp_community`);
  it, GE17-PiSB-Forti120G and Fortigate-200F now answer SNMP and were upgraded from ICMP only to their full templates.
- `add_firewalls.py`: existing hosts now follow IP / community changes in `DEVICES` or the credential file
  (`sync_address`); 'FortiGate by SNMP - PIDC' gets `system.net.uptime[sysUpTime.0]` (the stock template only has
  fgSysUpTime), which `device_uptime.py --setup` turns into the 'Uptime (network)' trapper used by the tiles.
- Disabled on the hosts only (always unsupported): TZ500 'Health: Outbound discards, all ports' and
  'SNMP raw: snmpEngineTime' (also on both NSA4600s); 'Free disk percentage' on Forti120G and 200F (no local disk).
- Still pending: Fortigate-300E (no ping), 1G-VDOM-SW (ping only, SNMP silent).

## 2026-10-12

### Daily report e-mails re-enabled
- `/etc/cron.d/zabbix-daily-reports`: the 08:00 IST `send_daily_reports.py` job (paused this morning) runs again,
  through `cron_run.py`, so Zabbix alerts if it fails or has not finished for 26 h. Native "Daily:" Zabbix reports
  stay disabled (no duplicate e-mails).
- `send_daily_reports.py` retries a PDF render twice (30 s apart) before reporting it failed: the dry run after
  re-enabling hit one transient "dashboard failed to get ready" on Global view that rendered fine on retry.

### Fix: Dashboard PDF of WAN Switches / Monitoring Server failed (500, "dashboard failed to get ready")
- The click-to-graph graph next to an item list graphs the list's first item; on the new "Links, optics & stack"
  page that was a text item (an LLDP neighbour name), which cannot be graphed, so the print view never finished and
  the PDF timed out after ~45 s. Item lists that feed a graph now contain numeric items only (`coverage_pages.py`,
  `add_server_monitoring.py`, and `click_to_graph.py` page lists skip text items). All 13 dashboards render again.

### Monitoring server: complete monitoring of the Zabbix server itself
- New `add_server_monitoring.py` (idempotent) on host "Zabbix server", new dashboard **Monitoring Server**
  (Overview / Database / Web, e-mail, jobs):
  - **MariaDB**: "MySQL by Zabbix agent 2" (read-only local user `zbx_monitor`, password
    `/root/.credentials/zabbix_mysql_monitor`, host macro secret) + size of every big Zabbix table (history*,
    trends*, events, alerts, auditlog) for storage planning.
  - **Apache**: "Apache by Zabbix agent" (mod_status, local only). **Services**: "Systemd by Zabbix agent 2" for
    zabbix-server / agent2 / web-service, mariadb, apache2, smokeping, cron, timesyncd, rsyslog.
  - **Web UI** scenario every minute: Zabbix login page, /reports, SmokePing login prompt (High if it fails 3 min).
  - **Cron jobs**: every job in `/etc/cron.d/zabbix-*` and the watchdog now runs through `cron_run.py`, which records
    exit code / run time / end time in `/var/lib/pi-netmon/cron/`; alerts when a job crashes or stops running.
  - **E-mail delivery**: alerts that failed (last hour) or are stuck unsent (High), SMTP smtp.office365.com:587
    reachable. **Time**: NTP synchronised, NTP servers answering. **OS**: reboot required, pending / security
    updates, watchdog paused.
  - Agent checks in `/etc/zabbix/zabbix_agent2.d/pidc-server.conf`, DB login in `/etc/zabbix/pidc-mysql-monitor.cnf`
    (root:zabbix 0640, not in git).

### ASR routers and all network switches: complete monitoring
- New `add_full_coverage.py` (idempotent) adds to all six PIDC device templates, so every current and future device
  of that model gets it: per-port broadcast / multicast and Ethernet errors (FCS/CRC, alignment, symbol, late
  collisions); LLDP neighbours (CDP on Catalyst); LACP member bundled / partner in sync; STP topology changes and root;
  stacking (Cisco StackWise, HPE IRF, Juniper Virtual Chassis, Huawei iStack); transceiver Rx / Tx power with the
  module's own thresholds; config changed / not saved; flash / storage, PoE, NTP sync, IP SLA, VRFs, IP statistics.
  ASR only: BGP IPv4 **and IPv6** from CISCO-BGP4-MIB (state, last error text, flaps, prefixes accepted / denied /
  advertised / withdrawn, UPDATEs), VRRP groups, QoS per class (offered / delivered / dropped), hardware alarm counts.
  ~6,300 new items, +5% values/s.
- Optics alarms fire only while the optic's port is up (a dark / unused port reads ~-40 dBm and is covered by the
  port's link-down alert); extra lanes of 40/100G optics map to their port; the low-warning trigger is suppressed
  while the low-alarm one is active. iStack ports alert only when a port that was up goes down (chain stacks always
  have unused ports). Not monitored because always false: Juniper read-only package mounts (/dev/mdN, devfs, jail),
  ASR920 PoE table (reports 480 W used of 180 W), management VRFs (Mgmt-vrf / Mgmt-intf).
- The old IPv4-only BGP triggers from `add_routers.py` were removed (the new BGP triggers replace them; the old
  items stay for history).
- New `coverage_pages.py`: page "Links, optics & stack" on WAN Switches, PiSB Cloud Fabric, Pi VMware Fabric, Pi MMR /
  DH Cross Connect, Pi 1G Colo Fabric and ASR Routers (LACP, optics, stack maps, neighbours / LACP / STP / stack and
  optics / config / NTP / flash lists with click-to-graph, related problems); ASR Routers also get
  "RTR-n: BGP, VRRP, QoS & IP SLA" per router.
- Found at setup: 1G-WAN-SW IP SLA 10 / 20 (172.18.156.2 / .10) and ASR_RTR-2 IP SLA 10 (4.2.2.2) timing out;
  LACP members configured but not bundled (PiSB SP1 Et34, SP2 Et33, 1G-WAN-SW Gi3/1/1, 1G-COLO-DH4-SW1 Gi1/1/4,
  10G_Leaf_SW-7-8 Te1/0/18 + Te2/0/18, ASR_RTR-2 Te0/0/14 in Po40); ASR_RTR-2 VRRP 40 (Po40) stuck in initialize;
  DH5_CC_SW4 NTP not synchronised; MMR1_CC_SW4 running config not saved.

### A10 LLB: complete monitoring (BGP and everything else the A10 exposes)
- New `add_a10_full.py` (idempotent; discovery rules, so new peers / ports / gateways appear by themselves):
  - **BGP**, IPv4 and IPv6 (A10 BGP MIB 22610.2.5; BGP4-MIB showed only IPv4): per session state, admin state,
    remote AS / router ID, time in state, flaps, last error (decoded), updates / messages per minute, time since last
    UPDATE, hold / keepalive, received prefixes; local AS 135133, router ID, our 16 advertised networks.
    Alerts: session down (High), flapped (Average), up but no prefixes (Average), no own networks originated (High).
  - **All ports** e1-e11, ve150 (A10 1 s counters, 10 s poll) + management port: status, admin, speed, duplex, MTU,
    flow control, bits, packets, multicast, errors, drops, collisions, utilisation % of port speed. Alerts: link went
    down (only ports that were up), errors / drops (macros `{$A10.IF.ERRORS.WARN}` 2/s, `{$A10.IF.DROPS.WARN}` 100/s),
    half duplex.
  - **LACP trunk 2** (e6 Router-2 + e10 Router-1): status, traffic, errors, drops, member bundled status.
  - **SLB**: every gateway incl. IPv6 (health, connections, new conn/s, upload / download, peak), service groups,
    group members (status, response time), virtual servers and virtual ports.
  - **Sessions / drops / forwarding**: session table by type, new connections (L4 / L7 / NAT / SSL), total throughput,
    every axNetStat / axNetStatExt / axSwitchStats counter per second; alerts for no-route drops, source-NAT failures,
    no-resource drops, server-selection failures, buffer drops, hardware DDoS drops.
  - **System**: data / control-plane CPU, disk, software on both disks, boot image, serial, HA, ARP, routes.
  - Not available on this A10 (BareMetal): temperature / fan / PSU (OIDs return 0); OSPF, HA and LLDP not in use.
- Dashboard "A10 LLB & ISP Links": new pages BGP, A10 Ports & Trunk, A10 SLB, A10 Sessions & Drops; BGP and port
  maps on NOC Overview; system information on A10 Health (`build_dashboard.py`).
- Found at setup: PowerGrid BGP IPv4 + IPv6 down (A10 Ethernet 4 admin-disabled; IPv6 last error 2/7 OPEN /
  unsupported capability, never established); trunk 2 member e6 (Router-2) up but not in the LACP bundle.

### Devices renamed
- Pi VMware Fabric leaves: 100G_Leaf_SW-1/2 -> 25G_Leaf_SW-1/2; 100G_Leaf_SW-5/6 -> 10G_Leaf_SW-5/6;
  100G_Leaf_SW-3&4 -> 10G_Leaf_SW-3&4; 100G-Leaf_SW-7&8 -> 10G-Leaf_SW-7&8 (technical host names use 3-4 / 7-8, Zabbix
  does not allow '&'). Same hosts, history and alerts kept; Leaf 1/2 memory exception (99 %) kept. Dashboard rebuilt;
  `add_vmware_fabric.py` updated; fabric pages now ordered by short name (spines, then Leaf 1, 2, 3-4, ...).
- Cross-connect switches: MMR1_SW1..SW4 and MMR1-SW5 -> MMR1_CC_SW1..SW5, DH5_SW1..SW4 -> DH5_CC_SW1..SW4 (host and
  visible name; the part in brackets is unchanged). Same hosts, so history, graphs and alerts carry on. Dashboards
  rebuilt; `add_cross_connect_fabrics.py` updated.

### Alerting
- New e-mail rule "Disk space alerts" -> compute@pidatacenters.com only: monitoring server disk space low (80 %) /
  critically low (90 %) and inodes running out on / and /boot, and the backup NFS share under 15 % free; all
  severities plus recovery. Sent through the new frontend-less user `disk-alerts`. These are no longer part of
  "ISP link alerts" (so network@ does not get them). `setup_email_alerts.py`.

### Reports
- Daily 08:00 PDF e-mails PAUSED at user request until further notice: the `send_daily_reports.py` line in
  `/etc/cron.d/zabbix-daily-reports` is commented out (uncomment to resume). Native Zabbix scheduled reports stay
  disabled.

## 2026-10-10

### Stability / self-healing
- Time sync: the clock was never synchronised (internet NTP blocked, 7 s behind). Now NTP 172.20.119.37 / .38
  (`/etc/systemd/timesyncd.conf.d/pidc-ntp.conf`).
- All core services (zabbix-server, mariadb, apache2, zabbix-web-service, zabbix-agent2) restart after ANY failure,
  10 s delay, never give up (`restart.conf` drop-ins); before, MariaDB/Apache restarted only on some crash types.
- `zabbix/watchdog.py` every 2 min (`/etc/cron.d/pi-netmon-watchdog`): starts stopped services, restarts a stuck
  zabbix-server (no new data for 10 min) or a hung web UI, warns on disk > 90 % / NTP lost; e-mails directly via
  Office365 (works when Zabbix itself is down). Pause: `touch /etc/pi-netmon-watchdog.disable`.
- `zabbix/disable_dead_items.py` hourly: disables management-port traffic items without 64-bit counters (Gi0, Fa1,
  Gi0/0 ...) - they wrote ~160k log lines in 2 days.
- Kernel panic -> automatic reboot after 10 s (`/etc/sysctl.d/91-pidc-autorecover.conf`); log rotation for the
  helper-script logs (`/etc/logrotate.d/pi-netmon`) and a 500 MB cap on zabbix_server.log.

### Daily report e-mails: every port and every item
- The 08:00 IST daily e-mails (one per dashboard, previous day) are now sent by `zabbix/send_daily_reports.py`
  instead of Zabbix's native scheduled reports, which print only what fits on the dashboard screen. Each PDF is
  the /reports "Dashboard PDF" with "all ports, plus all items" (`zabbix/daily_pdf.php`): every dashboard page
  followed by a panel per port (traffic in/out, errors/discards, speed, % up, state) and a chart per item.
  If a PDF would exceed 20 MB, ports without traffic that day are left out (none do today; largest 9.4 MB).
- Native "Daily: <dashboard>" scheduled reports are kept but disabled (`sync_daily_reports.py`, STATUS = 1).
- Log: /var/log/zabbix/daily-reports.log. Test/resend: `send_daily_reports.py --only "<dashboard>" --date YYYY-MM-DD [--to addr]`.

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
- **WAN Switches**: added 1G-WAN-SW 10.128.16.21 (AMRPiDC-WANSW001, Catalyst 3650-24TS-S 3-member stack, IOS-XE
  16.3.7) on *Cisco Catalyst by SNMP - PIDC* (`add_cross_connect_fabrics.py`, group may now set its role tag).
  The WAN Switches dashboard keeps the Arista 10G pair pages unchanged and adds, for any other switch in the
  group, the vendor-neutral switch page plus an Overview health table and port map. `build_fabric_dashboard.py`:
  the per-switch page is now the reusable `switch_page()` (fabric dashboards unchanged).
- **WAN Switches**: added 1G-WAN-Extension-SW 10.128.4.197 (SNMP-JUN-Switch-Azure, Juniper EX3400-24T 2-member
  Virtual Chassis, Junos 15.1X53-D57.3). New template *Juniper by SNMP - PIDC* (stock copy: traffic 10 s, status
  30 s, errors 1 min, Port state; "Health: ..." items count fans / PSUs in state 6 = down, since running, full
  speed and standby are all fine); Juniper hosts discover physical ports, ae bundles and me0 only. At setup the
  switch reported 1 major (red) + 1 minor (yellow) chassis alarm -> "System status is in critical state".
- Dashboard and host group "Pi DH5 Cross Connect Fabric" renamed to **"Pi DH Cross Connect Fabric"** (same IDs:
  e-mail alerts and the daily PDF report carry over; report renamed by `sync_daily_reports.py`).
- **Uptime now comes from the devices themselves**, not the SNMP agent: Huawei hwEntityUpTime (main board, seconds,
  never wraps), else hrSystemUptime (OS uptime: Arista, Juniper, A10), else sysUpTime (Cisco IOS/IOS-XE and HPE
  Comware, which count it from the last reload). 497.1-day roll-overs of the 32-bit counters are counted as they
  happen by `device_uptime.py` (every minute, `/etc/cron.d/zabbix-device-uptime`), which sends "Uptime (network)" /
  "Uptime (hardware)" (now trapper items, history kept); any other drop = reboot. Roll-overs from before monitoring:
  host macro `{$UPTIME.WRAPS}` (after checking the CLI), else snmpEngineTime as a lower bound only.
  Replaces `fix_uptime_wrap.py` (removed with its cron).
- **Pi 1G Colo Fabric**: added 1G-COLO-DH5-SW5 172.18.127.209 (1G-COLO-SW-5, Cisco Catalyst 3650-48FQ, IOS-XE
  16.12.8, 2x 1025 W PSU) on *Cisco Catalyst by SNMP - PIDC*, with its own dashboard page.
- **Memory safety (24 GB VM)**: checked with 34 hosts / 26k items - Zabbix caches 1.5-5 % used, MariaDB 4.2 of 8 GB
  buffer pool, no OOM kills. Added: Apache limited to 40 workers (recycled after 1000 requests,
  `pidc-memory.conf`) and capped at 5 GB high / 6 GB max, zabbix-web-service (Chrome PDFs) at 2 / 3 GB, so heavy
  reports can never starve MariaDB or zabbix-server (both also OOMScoreAdjust -600); `vm.swappiness` 10,
  `vm.min_free_kbytes` 256 MB. `StartPingers` 1 -> 4 (the single ICMP pinger was 71 % busy).
- Backup: a `--no-push` check run left its changes staged, which made the next real run fail at the git rebase
  (no push, no NFS copy). The checkout is now cleaned before syncing and the check run unstages again.
- Backup: **no local copy any more** (user request) - data backups go to NFS only; the 3-night local copy in
  `/var/backups/pi-network-monitoring` was removed (every folder was verified to exist on NFS first).
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
- Overview port maps sized so every port shows its name, not only its colour (Zabbix drops a honeycomb label when
  the cell gets too small): big switches (spines, 100+ ports) get a full-width map, the others stay in pairs
  (`build_switch_dashboard.overview_map_size`). Pi VMware Fabric Overview now has room for only 2 click-to-graph
  panels; the per-switch pages keep theirs.

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
