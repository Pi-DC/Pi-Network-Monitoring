#!/usr/bin/env python3
"""Disable discovered interface traffic items that can never work (cron hourly, /etc/cron.d/zabbix-disable-dead-items).

Management ports (Gi0, Fa1, Gi0/0 on Cisco ASR/Catalyst) have no 64-bit ifHC counters, so their "Bits sent/received"
items are permanently unsupported. Their error text quotes the live counter walk, so Zabbix logged a "changed" error
line on every 10 s poll (~160k lines in 2 days, 2026-10-10). Disabling them stops that; new devices are covered
automatically. Only discovered items (flags 4) named "Interface ...: Bits sent/received" whose error is "no data was
found" AND whose port is a management port (MGMT_PORT) are touched - data ports are never disabled. An item re-enabled by hand is disabled again on the next run only if it still fails that way.
"""
import re

import setup_isp_links as base

ERROR = "no data was found"
# Cisco ASR Gi0, Catalyst Fa1 / Gi0/0, plus generic mgmt names (Juniper me0, Arista Management1, Huawei MEth0/0/1)
MGMT_PORT = re.compile(r"^Interface (Gi0|Fa1|Gi0/0|me0|Management\d*|MEth[\d/]*|mgmt\d*)\(", re.I)


def main():
    z = base.Zabbix()
    items = z.call("item.get", {"output": ["itemid", "name", "error"], "selectHosts": ["host"],
                                "filter": {"status": 0, "state": 1, "flags": 4},
                                "search": {"name": "Interface *: Bits *"}, "searchWildcardsEnabled": True})
    dead = [i for i in items if ERROR in i["error"] and i["name"].endswith(("Bits sent", "Bits received"))
            and MGMT_PORT.match(i["name"])]
    for i in dead:
        z.call("item.update", {"itemid": i["itemid"], "status": 1})
        print(f"disabled {i['hosts'][0]['host']}: {i['name']}")


if __name__ == "__main__":
    main()
