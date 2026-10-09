#!/usr/bin/env bash
# Restore the Pi Network Monitoring tool (Zabbix 7.0 + SmokePing + reports, isp.picloud.in) on a fresh
# Ubuntu 24.04 server from the GitHub backup. Run as root. Full guide: RESTORE.md.
#
#   restore.sh --passphrase-file FILE [--local-backup DIR] [--repo DIR]
#
#   --passphrase-file  file holding the backup passphrase (the one kept outside the server)
#   --local-backup     optional: a nightly folder from /var/backups/pi-network-monitoring/<date> (copied from the
#                      old server). Restores the FULL database incl. graph history, and SmokePing data.
#                      Without it the configuration database from GitHub is restored (no past graph data).
#   --repo             existing checkout of the repository (default: the directory of this script)
set -euo pipefail

PASS=""; LOCAL=""; REPO="$(cd "$(dirname "$0")" && pwd)"
while [ $# -gt 0 ]; do
  case "$1" in
    --passphrase-file) PASS="$2"; shift 2 ;;
    --local-backup) LOCAL="$2"; shift 2 ;;
    --repo) REPO="$2"; shift 2 ;;
    *) echo "unknown option $1"; exit 1 ;;
  esac
done
[ "$(id -u)" = 0 ] || { echo "run as root"; exit 1; }
[ -s "$PASS" ] || { echo "--passphrase-file is required"; exit 1; }
grep -q 'VERSION_ID="24.04"' /etc/os-release || echo "WARNING: written for Ubuntu 24.04"
step() { echo; echo "=== $*"; }
WORK=$(mktemp -d /var/tmp/pi-netmon-restore.XXXX); trap 'rm -rf "$WORK"' EXIT
dec() { gpg --batch --yes --quiet --pinentry-mode loopback --passphrase-file "$PASS" --decrypt -o "$2" "$1"; }

step "1/9 Backup files from the 'backups' branch"
git -C "$REPO" fetch -q origin backups
git -C "$REPO" show origin/backups:MANIFEST.json | tee "$WORK/MANIFEST.json"
for f in zabbix-config.sql.zst.gpg secrets.tar.zst.gpg; do
  git -C "$REPO" show "origin/backups:$f" > "$WORK/$f"
done
apt-get update -q && apt-get install -y -q gpg zstd git wget ca-certificates
dec "$WORK/secrets.tar.zst.gpg" "$WORK/secrets.tar.zst"         # fails here if the passphrase is wrong
dec "$WORK/zabbix-config.sql.zst.gpg" "$WORK/zabbix-config.sql.zst"

step "2/9 Time zone and package repositories (Zabbix 7.0, Google Chrome)"
timedatectl set-timezone "$(cat "$REPO/packages/timezone.txt")"
wget -q -O "$WORK/zabbix-release.deb" \
  https://repo.zabbix.com/zabbix/7.0/ubuntu/pool/main/z/zabbix-release/zabbix-release_latest_7.0+ubuntu24.04_all.deb
dpkg -i "$WORK/zabbix-release.deb"
wget -q -O "$WORK/chrome.deb" https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb
apt-get update -q

step "3/9 Packages"
PKGS=$(cut -d= -f1 "$REPO/packages/packages.txt" | grep -vE '^(zabbix-release|google-chrome-stable)$' | tr '\n' ' ')
DEBIAN_FRONTEND=noninteractive apt-get install -y -q $PKGS python3 "$WORK/chrome.deb"
systemctl stop zabbix-server zabbix-web-service smokeping apache2 || true

step "4/9 Configuration files and scripts"
cp -a "$REPO/deploy/." /                                         # passwords in here are __REDACTED__ ...
tar -C / -I zstd -xpf "$WORK/secrets.tar.zst"                    # ... and the real files come from the bundle
while read -r mode owner group path; do                          # owners / modes recorded at backup time
  [ -e "$path" ] && chown "$owner:$group" "$path" && chmod "$mode" "$path"
done < "$REPO/packages/ownership.txt"
grep -rl "__REDACTED__" /etc /opt/isp /usr/local/sbin 2>/dev/null && { echo "redacted value left in a live file"; exit 1; } || true
mkdir -p /var/lib/pi-netmon-backup/status /var/backups/pi-network-monitoring
chmod 700 /var/backups/pi-network-monitoring; chmod 755 /var/lib/pi-netmon-backup /var/lib/pi-netmon-backup/status
systemctl daemon-reload

step "5/9 MariaDB (tuning, database, user)"
systemctl restart mariadb
DBPW=$(cat /root/.credentials/zabbix_db)
mysql <<SQL
CREATE DATABASE IF NOT EXISTS zabbix CHARACTER SET utf8mb4 COLLATE utf8mb4_bin;
CREATE USER IF NOT EXISTS 'zabbix'@'localhost' IDENTIFIED BY '$DBPW';
ALTER USER 'zabbix'@'localhost' IDENTIFIED BY '$DBPW';
GRANT ALL PRIVILEGES ON zabbix.* TO 'zabbix'@'localhost';
SET GLOBAL log_bin_trust_function_creators = 1;
SQL

step "6/9 Zabbix database"
if [ -n "$LOCAL" ] && [ -s "$LOCAL/zabbix-full.sql.zst" ]; then
  echo "full database incl. graph history from $LOCAL (can take a while)"
  zstd -q -d -c "$LOCAL/zabbix-full.sql.zst" | mysql zabbix
else
  echo "configuration database from GitHub (no past graph data)"
  zstd -q -d -c "$WORK/zabbix-config.sql.zst" | mysql zabbix
fi
mysql -e "SET GLOBAL log_bin_trust_function_creators = 0;"

step "7/9 SmokePing data"
if [ -n "$LOCAL" ] && [ -s "$LOCAL/smokeping-data.tar.zst" ]; then
  tar -C /var/lib -I zstd -xpf "$LOCAL/smokeping-data.tar.zst"
else
  echo "no local backup given: SmokePing starts with empty graphs"
fi

step "8/9 Apache modules / confs / sites"
while read -r kind name; do
  case "$kind" in mod) a2enmod -q "$name" ;; conf) a2enconf -q "$name" ;; site) a2ensite -q "$name" ;; esac
done < "$REPO/packages/apache-enabled.txt"
apache2ctl configtest

step "9/9 Start services (MariaDB already running; Zabbix server started on its own)"
systemctl enable -q zabbix-server zabbix-agent2 zabbix-web-service apache2 smokeping mariadb cron
systemctl restart zabbix-server
sleep 5
systemctl restart zabbix-agent2 zabbix-web-service apache2 smokeping cron
for s in mariadb zabbix-server zabbix-agent2 zabbix-web-service apache2 smokeping cron; do
  printf "%-20s %s\n" "$s" "$(systemctl is-active "$s")"
done
cat <<'EOF'

Restore finished. Next (see RESTORE.md, "After the restore"):
  - point isp.picloud.in (internal DNS) at this server if its IP changed, and check https://isp.picloud.in/zabbix
  - devices must allow SNMP from this server's IP (the A10, switches, routers have SNMP ACLs)
  - add this server's SSH key to GitHub so the nightly backup can push (/opt/isp/backup/backup.py)
  - store the backup passphrase in /root/.credentials/backup_passphrase (already done if it was in the bundle)
EOF
