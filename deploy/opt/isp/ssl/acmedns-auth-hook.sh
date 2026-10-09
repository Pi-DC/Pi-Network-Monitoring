#!/bin/bash
# certbot DNS-01 hook for isp.picloud.in via acme-dns (fully automatic renewal).
# _acme-challenge.isp.picloud.in is a CNAME on Windows DNS pointing at our acme-dns record, so this hook
# only has to set the TXT value through the acme-dns API (credentials in a root-only file; the account
# only accepts updates from this server's internet address). If acme-dns fails, it falls back to the
# manual hook, which emails the value to the NOC.
CREDS=/etc/letsencrypt/acmedns-isp.picloud.in.json
WAIT_SECONDS=600

if ! python3 - "$CREDS" "$CERTBOT_VALIDATION" <<'PY'
import json, sys, urllib.request
d = json.load(open(sys.argv[1]))
req = urllib.request.Request("https://auth.acme-dns.io/update",
                             json.dumps({"subdomain": d["subdomain"], "txt": sys.argv[2]}).encode(),
                             {"X-Api-User": d["username"], "X-Api-Key": d["password"],
                              "Content-Type": "application/json"})
with urllib.request.urlopen(req, timeout=30) as r:
    if json.load(r).get("txt") != sys.argv[2]:
        sys.exit(1)
PY
then
  echo "acme-dns update failed - falling back to the manual (email) hook"
  exec /opt/isp/ssl/manual-auth-hook.sh
fi

# Wait until the value is visible through the CNAME on public DNS (what Let's Encrypt queries).
deadline=$(( $(date +%s) + WAIT_SECONDS ))
while [ "$(date +%s)" -lt "$deadline" ]; do
  for r in 8.8.8.8 1.1.1.1; do
    dig +short TXT "_acme-challenge.$CERTBOT_DOMAIN" @"$r" | tr -d '"' | grep -qx "$CERTBOT_VALIDATION" || continue 2
  done
  echo "acme-dns TXT visible via CNAME on public DNS"; sleep 10; exit 0
done
echo "Timed out waiting for the TXT value to appear through the CNAME"; exit 1
