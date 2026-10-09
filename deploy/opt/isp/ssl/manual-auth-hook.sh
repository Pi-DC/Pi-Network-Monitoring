#!/bin/bash
# certbot manual DNS-01 hook for isp.picloud.in (picloud.in is on Windows DNS, no dynamic updates).
# 1. Saves the new TXT value and emails it to the NOC so someone can put it in DNS.
# 2. Waits (up to 12 h) until both authoritative servers serve it, then lets Let's Encrypt validate.
# certbot renews from ~30 days before expiry, twice a day, so a missed window just retries later.
VALUE_FILE=/opt/isp/ssl/pending-txt-value
WAIT_SECONDS=$((12 * 3600))
NAMESERVERS="103.210.73.180 103.210.73.181"

echo "$CERTBOT_VALIDATION" > "$VALUE_FILE"

python3 - "$CERTBOT_DOMAIN" "$CERTBOT_VALIDATION" "$WAIT_SECONDS" <<'PY' || echo "warning: could not send the email"
import smtplib, ssl, sys, datetime
from email.message import EmailMessage
domain, value, wait = sys.argv[1], sys.argv[2], int(sys.argv[3])
deadline = (datetime.datetime.now() + datetime.timedelta(seconds=wait)).strftime("%Y-%m-%d %H:%M")
msg = EmailMessage()
msg["From"] = "alerts@pidatacenters.com"
msg["To"] = "compute@pidatacenters.com, network@pidatacenters.com"
msg["Subject"] = f"ACTION: update DNS TXT for {domain} certificate renewal (by {deadline} IST)"
msg.set_content(f"""The SSL certificate for https://{domain} is being renewed (Let's Encrypt).

Please update this record on BOTH Windows DNS servers (ns3 103.210.73.180 and ns4 103.210.73.181):

  Zone:        picloud.in
  Record name: _acme-challenge.{domain.removesuffix('.picloud.in')}
  Type:        TXT
  Text:        {value}

PowerShell (on ns3, then replicate / repeat on ns4):
  Get-DnsServerResourceRecord -ZoneName "picloud.in" -Name "_acme-challenge.isp" -RRType Txt |
    Remove-DnsServerResourceRecord -ZoneName "picloud.in" -Force
  Add-DnsServerResourceRecord -ZoneName "picloud.in" -Name "_acme-challenge.isp" -Txt `
    -DescriptiveText "{value}" -TimeToLive 00:01:00

The monitoring server checks every minute and finishes the renewal automatically once both servers
return the value. It waits until {deadline} IST; if missed, it tries again with a new value later.
""")
with smtplib.SMTP("smtp.office365.com", 587, timeout=30) as s:
    s.starttls(context=ssl.create_default_context())
    s.login("alerts@pidatacenters.com", open("/root/.credentials/smtp_alerts_password").read().strip())
    s.send_message(msg)
print("renewal TXT value emailed to compute@ and network@")
PY

deadline=$(( $(date +%s) + WAIT_SECONDS ))
while [ "$(date +%s)" -lt "$deadline" ]; do
  ok=0
  for ns in $NAMESERVERS; do
    dig +short TXT "_acme-challenge.$CERTBOT_DOMAIN" @"$ns" | tr -d '"' | grep -qx "$CERTBOT_VALIDATION" && ok=$((ok+1))
  done
  if [ "$ok" -eq 2 ]; then echo "TXT value found on ns3 and ns4"; sleep 20; exit 0; fi
  sleep 60
done
echo "Timed out waiting for the TXT value"; exit 1
