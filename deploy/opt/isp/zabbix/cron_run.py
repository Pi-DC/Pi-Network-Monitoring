#!/usr/bin/env python3
"""Run one cron job and record how it ended, for Zabbix (add_server_monitoring.py watches the status files).

    cron_run.py <job name> -- <command> [args...]

Writes /var/lib/pi-netmon/cron/<job name>.json = {"rc": exit code, "duration": seconds, "end": unix time} after the
command finishes; the command's output passes through to cron's redirect as before.
"""
import json
import os
import subprocess
import sys
import time

STATUS_DIR = "/var/lib/pi-netmon/cron"


def main():
    if len(sys.argv) < 4 or sys.argv[2] != "--":
        sys.exit(__doc__)
    name, cmd = sys.argv[1], sys.argv[3:]
    start = time.time()
    try:
        rc = subprocess.call(cmd)
    except OSError as e:
        print(f"cron_run: {e}", file=sys.stderr)
        rc = 127
    os.makedirs(STATUS_DIR, mode=0o755, exist_ok=True)
    tmp = f"{STATUS_DIR}/.{name}.tmp"
    with open(tmp, "w") as fh:
        json.dump({"rc": rc, "duration": round(time.time() - start, 1), "end": int(time.time())}, fh)
    os.chmod(tmp, 0o644)
    os.replace(tmp, f"{STATUS_DIR}/{name}.json")
    sys.exit(rc)


if __name__ == "__main__":
    main()
