#!/usr/bin/env python3
"""After every reboot: check that the whole monitoring server came back, and e-mail the result (cron @reboot,
/etc/cron.d/pi-netmon-boot-check, 5 min after boot so everything has had time to start).

Checks: core services active, no failed systemd units, Zabbix collecting new data, Zabbix web UI and API, reports
page, MariaDB buffer pool reloaded, running kernel = newest installed, pending package updates. Anything not OK is
listed first in the e-mail subject. Log: /var/log/zabbix/boot-check.log
"""
import json
import subprocess
import time
import urllib.request

import watchdog as wd

SERVICES = wd.SERVICES + ["cron", "ssh.socket", "systemd-timesyncd"]


def http_ok(url, data=None, expect=None):
    try:
        req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json-rpc"} if data else {})
        with urllib.request.urlopen(req, timeout=30) as r:
            body = r.read().decode(errors="replace")
            return r.status == 200 and (expect is None or expect in body), body[:200]
    except Exception as e:
        return False, str(e)


def main():
    bad, good = [], []

    def check(ok, text):
        (good if ok else bad).append(text)

    up = int(time.time() - wd.boot_time())
    for svc in SERVICES:
        check(wd.active(svc), f"service {svc}: {wd.sh('systemctl', 'is-active', svc).stdout.strip()}")
    failed = wd.sh("systemctl", "--failed", "--no-legend", "--plain").stdout.split("\n")
    failed = [f.split()[0] for f in failed if f.strip()]
    check(not failed, "failed systemd units: " + (", ".join(failed) or "none"))

    age = None
    for _ in range(10):   # Zabbix may still be loading its configuration cache
        age = wd.last_internal_value_age()
        if age is not None and age < 300:
            break
        time.sleep(30)
    check(age is not None and age < 300, f"Zabbix collecting data: last internal value {age} s ago")
    check(wd.web_ok(), "Zabbix web UI answers")
    ok, body = http_ok("http://127.0.0.1/zabbix/api_jsonrpc.php",
                       json.dumps({"jsonrpc": "2.0", "method": "apiinfo.version", "params": {}, "id": 1}).encode(),
                       '"result"')
    check(ok, "Zabbix API answers" + ("" if ok else f" ({body})"))
    check('name="username"' in wd.sh("curl", "-sk", "-m", "30", "https://isp.picloud.in/reports/").stdout,
          "reports login page answers")
    st = wd.sh("mysql", "-N", "-e", "SHOW GLOBAL STATUS LIKE 'Innodb_buffer_pool_load_status'").stdout.strip()
    check("completed" in st, "MariaDB buffer pool reload: " + (st.split("\t")[-1] or "?"))

    running = wd.sh("uname", "-r").stdout.strip()
    newest = wd.sh("sh", "-c", "ls /boot/vmlinuz-* | sed 's|/boot/vmlinuz-||' | sort -V | tail -1").stdout.strip()
    check(running == newest, f"kernel {running}" + ("" if running == newest else f" (newest installed: {newest})"))
    pend = [l.split("/")[0] for l in wd.sh("apt", "list", "--upgradable").stdout.splitlines()[1:] if "/" in l]
    good.append(f"pending package updates: {len(pend)}" + (f" ({', '.join(pend[:15])})" if pend else ""))
    reboot_req = wd.sh("test", "-f", "/var/run/reboot-required").returncode == 0
    check(not reboot_req, "reboot required flag: " + ("SET" if reboot_req else "not set"))

    lines = ["NOT OK:"] + [f"  - {b}" for b in bad] + [""] if bad else []
    lines += ["OK:"] + [f"  - {g}" for g in good]
    body = f"The monitoring server was rebooted (up {up // 60} min).\n\n" + "\n".join(lines)
    wd.log(("PROBLEM " if bad else "OK ") + "; ".join(bad or ["all checks passed"]))
    print(body, flush=True)
    wd.send(f"server rebooted - {len(bad)} problem(s): " + "; ".join(bad) if bad else
            "server rebooted - all services up", body)
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
