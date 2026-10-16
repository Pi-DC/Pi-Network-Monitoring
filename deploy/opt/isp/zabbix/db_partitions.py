#!/usr/bin/env python3
"""Zabbix history / trends tables partitioned by time, so old data goes by dropping a partition (2026-10-16).

Why: 6 months of history for every device is ~760 GB at ~1,040 values/s. The Zabbix housekeeper would delete ~90 M
rows a day from it with DELETE - slow and hard on the VM disk (~12 ms per read). Dropping a day partition takes
seconds. Retention is NOT changed: it is still the one set in Zabbix (Administration > Housekeeping, override
180d history / 730d trends) - this script reads it from the API on every run and only drops partitions that are
completely older than it (whole days / months, so data is kept slightly longer, never shorter).

  history, history_uint, history_str, history_text, history_log, history_bin   one partition per day   pYYYYMMDD
  trends, trends_uint                                                          one partition per month pYYYYMM
  plus p_before (anything before FIRST) and pmax (catch-all, so an insert can never fail for want of a partition)

  db_partitions.py                daily (cron /etc/cron.d/zabbix-db-partitions via cron_run.py): add partitions
                                  AHEAD_DAYS / AHEAD_MONTHS ahead, drop the ones older than the Zabbix retention
  db_partitions.py --dry-run      show what it would do
  db_partitions.py --convert T..  one-time conversion of live tables, no downtime and no gap:
        1. <T>_part = same table, partitioned
        2. copy every row in itemid chunks (READ COMMITTED: no locks on the live table; resumable, state in STATE)
        3. RENAME TABLE T TO T_old, T_part TO T - atomic, gives up after 10 s instead of stalling Zabbix
        4. copy what arrived in T meanwhile (clock >= copy start - 1 h, per item through the primary key)
        5. compare row counts per item for a sample of items
     T_old is kept until it is dropped by hand (--drop-old T) after checking graphs.
  db_partitions.py --housekeeper-off   after all tables are converted: Zabbix housekeeping of history / trends off
                                       (override periods stay set - they are the retention this script applies)
"""
import datetime
import json
import os
import random
import re
import subprocess
import sys
import time

import setup_isp_links as base

DB = "zabbix"
DAILY = ["history", "history_uint", "history_str", "history_text", "history_log", "history_bin"]
MONTHLY = ["trends", "trends_uint"]
FIRST = datetime.date(2026, 10, 1)   # oldest data is from 2026-10-08; anything older goes to p_before
AHEAD_DAYS, AHEAD_MONTHS = 14, 3
MIN_KEEP_DAYS = 90                   # never drop below this, whatever the API returns
CHUNK = 250                          # itemids per copy statement (~1.4 M history_uint rows)
STATE = "/var/lib/pi-netmon/partition-convert.json"


def sql(q, rows=True):
    r = subprocess.run(["mysql", "-N", "-B", DB, "-e", q], capture_output=True, text=True)
    if r.returncode:
        raise RuntimeError(f"mysql: {r.stderr.strip()} [{q[:200]}]")
    return [line.split("\t") for line in r.stdout.splitlines()] if rows else r.stdout


def midnight(d):
    return int(time.mktime(d.timetuple()))


def month_start(d, add=0):
    m = d.month - 1 + add
    return datetime.date(d.year + m // 12, m % 12 + 1, 1)


def wanted(table, upto):
    """[(name, upper bound)] from FIRST to `upto`, without p_before / pmax."""
    out = []
    if table in DAILY:
        d = FIRST
        while d <= upto:
            n = d + datetime.timedelta(days=1)
            out.append((f"p{d:%Y%m%d}", midnight(n)))
            d = n
    else:
        d = month_start(FIRST)
        while d <= upto:
            n = month_start(d, 1)
            out.append((f"p{d:%Y%m}", midnight(n)))
            d = n
    return out


def horizon(table):
    today = datetime.date.today()
    return today + datetime.timedelta(days=AHEAD_DAYS) if table in DAILY else month_start(today, AHEAD_MONTHS)


def partitions(table):
    """[(name, upper bound or None for MAXVALUE)] in order; [] when not partitioned."""
    rows = sql(f"SELECT partition_name, partition_description FROM information_schema.partitions WHERE "
               f"table_schema = '{DB}' AND table_name = '{table}' AND partition_name IS NOT NULL "
               f"ORDER BY partition_ordinal_position")
    return [(n, None if d == "MAXVALUE" else int(d)) for n, d in rows]


def definition(table):
    parts = [f"PARTITION p_before VALUES LESS THAN ({midnight(FIRST)})"]
    parts += [f"PARTITION {n} VALUES LESS THAN ({b})" for n, b in wanted(table, horizon(table))]
    return "PARTITION BY RANGE (clock) (" + ", ".join(parts + ["PARTITION pmax VALUES LESS THAN MAXVALUE"]) + ")"


# ---------------------------------------------------------------- daily maintenance
def retention_days():
    """Days to keep per table group, from the Zabbix housekeeping settings - with the global override on that is the
    override; without it the longest period of any item (so no item ever loses data it should keep)."""
    z = base.Zabbix()
    hk = z.call("housekeeping.get", {"output": "extend"})
    days = lambda s: int(s[:-1]) * {"d": 1, "w": 7, "h": 1 / 24}[s[-1]] if s[-1] in "dwh" else int(s) / 86400
    out = {}
    for group, field in (("history", "history"), ("trends", "trends")):
        if hk[f"hk_{group}_global"] == "1":
            out[group] = days(hk[f"hk_{group}"])
        else:
            vals = {i[field] for i in z.call("item.get", {"output": [field], "templated": False})}
            out[group] = max(days(v) for v in vals if not v.startswith("{") and v != "0") + 1
    return out


def maintain(dry):
    keep = retention_days()
    for table in DAILY + MONTHLY:
        have = partitions(table)
        if not have:
            print(f"{table}: not partitioned - skipped")
            continue
        names = {n for n, _ in have}
        new = [(n, b) for n, b in wanted(table, horizon(table)) if n not in names and b > max(x for _, x in have if x)]
        if new:
            q = (f"ALTER TABLE {table} REORGANIZE PARTITION pmax INTO (" + ", ".join(
                f"PARTITION {n} VALUES LESS THAN ({b})" for n, b in new) + ", PARTITION pmax VALUES LESS THAN MAXVALUE)")
            print(f"{table}: + {len(new)} partition(s) {new[0][0]}..{new[-1][0]}")
            if not dry:
                sql(q)
        days = keep["history" if table in DAILY else "trends"]
        if days < MIN_KEEP_DAYS:
            print(f"{table}: retention {days} d is below {MIN_KEEP_DAYS} d - nothing dropped, check Housekeeping")
            continue
        cutoff = time.time() - days * 86400
        old = [n for n, b in have if b is not None and b <= cutoff and n != "pmax"]
        if old:
            print(f"{table}: - {len(old)} partition(s) entirely older than {days:g} d: {', '.join(old)}")
            if not dry:
                sql(f"ALTER TABLE {table} DROP PARTITION {', '.join(old)}")


# ---------------------------------------------------------------- one-time conversion
def load_state():
    try:
        return json.load(open(STATE))
    except (OSError, ValueError):
        return {}


def save_state(s):
    os.makedirs(os.path.dirname(STATE), exist_ok=True)
    json.dump(s, open(STATE + ".tmp", "w"))
    os.replace(STATE + ".tmp", STATE)


def item_ids():
    return [int(r[0]) for r in sql("SELECT itemid FROM items ORDER BY itemid")]


def convert(table):
    state = load_state()
    st = state.setdefault(table, {})
    part = f"{table}_part"
    if partitions(table):
        print(f"{table}: already partitioned")
        return
    if not sql(f"SHOW TABLES LIKE '{part}'"):
        sql(f"CREATE TABLE {part} LIKE {table}")
        sql(f"ALTER TABLE {part} {definition(table)}")
        st.clear()
        print(f"{table}: {part} created with {len(partitions(part))} partitions")
    if "t0" not in st:
        st.update(t0=int(time.time()), next=0)
        save_state(state)
    top = max(int(sql(f"SELECT COALESCE(MAX(itemid), 0) FROM items")[0][0]), 0) + 1
    rc = "SET SESSION TRANSACTION ISOLATION LEVEL READ COMMITTED; "
    started, copied = time.time(), 0
    while st["next"] < top:   # 2. bulk copy by primary-key prefix
        a, b = st["next"], st["next"] + CHUNK
        n = int(sql(rc + f"INSERT IGNORE INTO {part} SELECT * FROM {table} WHERE itemid >= {a} AND itemid < {b}; "
                         "SELECT ROW_COUNT()")[0][0])
        copied += n
        st["next"] = b
        st["rows"] = st.get("rows", 0) + n
        save_state(state)
        if (b // CHUNK) % 40 == 0:
            print(f"{table}: itemid {b}/{top}, {st['rows']:,} rows, {copied / max(time.time() - started, 1):,.0f} rows/s",
                  flush=True)
    # also rows of items deleted with an itemid above the current maximum cannot exist (ids only grow)
    print(f"{table}: bulk copy done, {st['rows']:,} rows")
    # 3. swap - fail fast instead of queueing Zabbix behind a metadata lock
    sql(f"SET SESSION lock_wait_timeout = 10; RENAME TABLE {table} TO {table}_old, {part} TO {table}")
    swapped = int(time.time())
    print(f"{table}: swapped at {datetime.datetime.fromtimestamp(swapped):%H:%M:%S}", flush=True)
    # 4. delta: everything written to the old table since the copy started (late values included: -1 h)
    since, ids, delta = st["t0"] - 3600, item_ids(), 0
    for i in range(0, len(ids), 1000):
        chunk = ",".join(map(str, ids[i:i + 1000]))
        delta += int(sql(rc + f"INSERT IGNORE INTO {table} SELECT * FROM {table}_old WHERE itemid IN ({chunk}) "
                              f"AND clock >= {since}; SELECT ROW_COUNT()")[0][0])
    print(f"{table}: {delta:,} rows written meanwhile copied")
    # 5. check a sample of items: same rows up to the swap
    sample, bad = random.sample(ids, min(200, len(ids))), []
    for itemid in sample:
        q = f"SELECT COUNT(*) FROM {{}} WHERE itemid = {itemid} AND clock < {swapped}"
        if sql(q.format(f"{table}_old"))[0][0] != sql(q.format(table))[0][0]:
            bad.append(itemid)
    st.update(done=swapped, delta=delta, sample_bad=bad)
    save_state(state)
    print(f"{table}: sample check {'OK' if not bad else 'MISMATCH ' + str(bad[:10])} ({len(sample)} items); "
          f"{table}_old kept - drop it with --drop-old {table} after checking")
    if bad:
        raise SystemExit(1)


def drop_old(table):
    if not partitions(table):
        raise SystemExit(f"{table} is not partitioned - {table}_old is still needed")
    sql(f"DROP TABLE {table}_old")
    print(f"{table}_old dropped")


def housekeeper_off():
    for t in DAILY + MONTHLY:
        if not partitions(t):
            raise SystemExit(f"{t} is not partitioned yet - housekeeping stays on")
    z = base.Zabbix()
    z.call("housekeeping.update", {"hk_history_mode": 0, "hk_trends_mode": 0})
    hk = z.call("housekeeping.get", {"output": ["hk_history_mode", "hk_trends_mode", "hk_history_global",
                                                "hk_history", "hk_trends_global", "hk_trends"]})
    print("housekeeping:", hk)


def main():
    args = sys.argv[1:]
    if "--convert" in args:
        for t in args[args.index("--convert") + 1:]:
            convert(t)
    elif "--drop-old" in args:
        drop_old(args[args.index("--drop-old") + 1])
    elif "--housekeeper-off" in args:
        housekeeper_off()
    else:
        maintain("--dry-run" in args)


if __name__ == "__main__":
    main()
