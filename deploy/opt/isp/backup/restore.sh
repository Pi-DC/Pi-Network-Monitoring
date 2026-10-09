#!/usr/bin/env bash
# Restore the Pi Network Monitoring tool (Zabbix 7.0 + SmokePing + reports, isp.picloud.in) on a fresh
# Ubuntu 24.04 server: configuration from this git repository, data from the NFS backup share. Run as root.
# Full guide: RESTORE.md.
#
#   restore.sh --passphrase-file FILE [--backup-dir DIR] [--config-only]
#
#   --passphrase-file  file holding the backup passphrase (the copy kept outside the server)
#   --backup-dir       a nightly backup folder; default: the newest one on the NFS share (LATEST.txt)
#   --config-only      import the small configuration database (no graph history) instead of the full one
set -euo pipefail

NFS_SOURCE="172.16.95.5:/Repo_BDR/Pi-Network-Monitoring"; NFS=/mnt/pi-netmon-nfs
PASS=""; BACKUP=""; CONFIG_ONLY=0; REPO="$(cd "$(dirname "$0")" && pwd)"
while [ $# -gt 0 ]; do
  case "$1" in
    --passphrase-file) PASS="$2"; shift 2 ;;
    --backup-dir) BACKUP="$2"; shift 2 ;;
    --config-only) CONFIG_ONLY=1; shift ;;
    *) echo "unknown option $1"; exit 1 ;;
  esac
done
[ "$(id -u)" = 0 ] || { echo "run as root"; exit 1; }
[ -s "$PASS" ] || { echo "--passphrase-file is required"; exit 1; }
grep -q 'VERSION_ID="24.04"' /etc/os-release || echo "WARNING: written for Ubuntu 24.04"
step() { echo; echo "=== $*"; }
WORK=$(mktemp -d /var/tmp/pi-netmon-restore.XXXX); trap 'rm -rf "$WORK"' EXIT
GPG=(gpg --batch --yes --quiet --pinentry-mode loopback --passphrase-file "$PASS")
dec() { "${GPG[@]}" --decrypt "$1" | zstd -q -d -c; }        # decrypt + decompress to stdout

step "1/10 Tools and the NFS backup share"
apt-get update -q && apt-get install -y -q gpg zstd git wget ca-certificates nfs-common
mkdir -p "$NFS"
grep -q "pi-netmon-nfs" /etc/fstab || cat >> /etc/fstab <<EOF
# Pi Network Monitoring nightly backups (encrypted) - /opt/isp/backup/backup.py. Automount: boot does not wait for it.
$NFS_SOURCE $NFS nfs vers=3,proto=tcp,hard,timeo=600,retrans=3,_netdev,nofail,x-systemd.automount,x-systemd.mount-timeout=30,x-systemd.idle-timeout=0 0 0
EOF
systemctl daemon-reload; systemctl restart remote-fs.target
if [ -z "$BACKUP" ]; then BACKUP="$NFS/$(cat "$NFS/LATEST.txt")"; fi
echo "backup: $BACKUP"; cat "$BACKUP/MANIFEST.json"
( cd "$BACKUP" && python3 -c "
import json,hashlib,sys
m=json.load(open('MANIFEST.json'))
for f,meta in m['files'].items():
    h=hashlib.sha256(open(f,'rb').read()).hexdigest()
    sys.exit(f'checksum mismatch: {f}') if h!=meta['sha256'] else print('checksum ok:',f)" )
dec "$BACKUP/secrets.tar.zst.gpg" > "$WORK/secrets.tar"            # fails here if the passphrase is wrong

step "2/10 Time zone and package repositories (Zabbix 7.0, Google Chrome)"
timedatectl set-timezone "$(cat "$REPO/packages/timezone.txt")"
wget -q -O "$WORK/zabbix-release.deb" \
  https://repo.zabbix.com/zabbix/7.0/ubuntu/pool/main/z/zabbix-release/zabbix-release_latest_7.0+ubuntu24.04_all.deb
dpkg -i "$WORK/zabbix-release.deb"
wget -q -O "$WORK/chrome.deb" https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb
apt-get update -q

step "3/10 Packages"
PKGS=$(cut -d= -f1 "$REPO/packages/packages.txt" | grep -vE '^(zabbix-release|google-chrome-stable)$' | tr '\n' ' ')
DEBIAN_FRONTEND=noninteractive apt-get install -y -q $PKGS python3 "$WORK/chrome.deb"
systemctl stop zabbix-server zabbix-web-service smokeping apache2 || true

step "4/10 Configuration files and scripts"
cp -a "$REPO/deploy/." /                                         # passwords in here are __REDACTED__ ...
tar -C / -xpf "$WORK/secrets.tar"                                # ... the real files come from the bundle
while read -r mode owner group path; do                          # owners / modes recorded at backup time
  [ -e "$path" ] && chown "$owner:$group" "$path" && chmod "$mode" "$path"
done < "$REPO/packages/ownership.txt"
if grep -rl "__REDACTED__" /etc /opt/isp /usr/local/sbin 2>/dev/null; then echo "redacted value left in a live file"; exit 1; fi
mkdir -p /var/lib/pi-netmon-backup/status /var/backups/pi-network-monitoring
chmod 700 /var/backups/pi-network-monitoring; chmod 755 /var/lib/pi-netmon-backup /var/lib/pi-netmon-backup/status
systemctl daemon-reload

step "5/10 MariaDB (tuning, database, user)"
systemctl restart mariadb
DBPW=$(cat /root/.credentials/zabbix_db)
mysql <<SQL
CREATE DATABASE IF NOT EXISTS zabbix CHARACTER SET utf8mb4 COLLATE utf8mb4_bin;
CREATE USER IF NOT EXISTS 'zabbix'@'localhost' IDENTIFIED BY '$DBPW';
ALTER USER 'zabbix'@'localhost' IDENTIFIED BY '$DBPW';
GRANT ALL PRIVILEGES ON zabbix.* TO 'zabbix'@'localhost';
SET GLOBAL log_bin_trust_function_creators = 1;
SQL

step "6/10 Zabbix database"
if [ "$CONFIG_ONLY" = 1 ]; then
  echo "configuration database (no graph history)"; dec "$BACKUP/zabbix-config.sql.zst.gpg" | mysql zabbix
else
  echo "full database incl. graph history (can take a while)"; dec "$BACKUP/zabbix-full.sql.zst.gpg" | mysql zabbix
fi
mysql -e "SET GLOBAL log_bin_trust_function_creators = 0;"

step "7/10 SmokePing data"
dec "$BACKUP/smokeping-data.tar.zst.gpg" | tar -C /var/lib -xpf -

step "8/10 Apache modules / confs / sites"
while read -r kind name; do
  case "$kind" in mod) a2enmod -q "$name" ;; conf) a2enconf -q "$name" ;; site) a2ensite -q "$name" ;; esac
done < "$REPO/packages/apache-enabled.txt"
apache2ctl configtest

step "9/10 Git checkout for the nightly backup"
if [ "$REPO" != /var/lib/pi-netmon-backup/repo ] && [ ! -d /var/lib/pi-netmon-backup/repo/.git ]; then
  git clone -q "$REPO" /var/lib/pi-netmon-backup/repo
  git -C /var/lib/pi-netmon-backup/repo remote set-url origin git@github.com:Pi-DC/Pi-Network-Monitoring.git
fi

step "10/10 Start services (MariaDB already running; Zabbix server started on its own)"
systemctl enable -q zabbix-server zabbix-agent2 zabbix-web-service apache2 smokeping mariadb cron
systemctl restart zabbix-server
sleep 5
systemctl restart zabbix-agent2 zabbix-web-service apache2 smokeping cron
for s in mariadb zabbix-server zabbix-agent2 zabbix-web-service apache2 smokeping cron; do
  printf "%-20s %s\n" "$s" "$(systemctl is-active "$s")"
done
cat <<'EOF'

Restore finished. Next (RESTORE.md, "After the restore"):
  - point isp.picloud.in (internal DNS) at this server if its IP changed; check https://isp.picloud.in/zabbix
  - devices must allow SNMP from this server's IP (the A10, switches and routers have SNMP ACLs)
  - add this server's SSH key to GitHub so the nightly backup can push its configuration snapshot
  - run one backup by hand: /opt/isp/backup/backup.py
EOF
