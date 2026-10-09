#!/bin/bash
# Issue a Let's Encrypt certificate for isp.picloud.in via DNS-01 (RFC2136 key on ns3.picloud.in),
# switch Apache to it, and prove automatic renewal works.
# Prerequisite: /etc/letsencrypt/rfc2136-picloud.ini filled in with the key from the DNS admin.
set -euo pipefail

DOMAIN=isp.picloud.in
CREDS=/etc/letsencrypt/rfc2136-picloud.ini
VHOST=/etc/apache2/sites-available/isp.picloud.in-ssl.conf
EMAIL=network@pidatacenters.com

grep -q REPLACE "$CREDS" && { echo "Fill in the TSIG key name/secret in $CREDS first."; exit 1; }

certbot certonly --non-interactive --agree-tos -m "$EMAIL" \
  --dns-rfc2136 --dns-rfc2136-credentials "$CREDS" --dns-rfc2136-propagation-seconds 90 \
  -d "$DOMAIN"

LIVE=/etc/letsencrypt/live/$DOMAIN
cp -n "$VHOST" "$VHOST.private-ca"            # keep the private-CA version as a fallback
sed -i -e "s|^\(\s*SSLCertificateFile\s\+\).*|\1$LIVE/fullchain.pem|" \
       -e "s|^\(\s*SSLCertificateKeyFile\s\+\).*|\1$LIVE/privkey.pem|" "$VHOST"

if apache2ctl configtest; then
  systemctl reload apache2
else
  echo "Apache config test failed - restoring the private-CA certificate"; cp "$VHOST.private-ca" "$VHOST"; exit 1
fi

echo "--- served certificate:"
echo | openssl s_client -connect 127.0.0.1:443 -servername "$DOMAIN" 2>/dev/null | openssl x509 -noout -subject -issuer -enddate
echo "--- renewal dry run:"
certbot renew --dry-run --cert-name "$DOMAIN"
systemctl list-timers certbot.timer --no-pager | sed -n 2p
