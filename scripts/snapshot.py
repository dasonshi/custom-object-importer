#!/usr/bin/env python3
"""Append (or rebuild) user_activity_history.csv from users.csv.

Usage:
  scripts/snapshot.py            # append today's snapshot if not already present
  scripts/snapshot.py --rebuild  # regenerate full weekly history from users.csv
"""
import csv
import sys
from datetime import date, timedelta
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parent.parent
USERS_CSV = PROJECT_DIR / "users.csv"
HISTORY_CSV = PROJECT_DIR / "user_activity_history.csv"
WINDOW_DAYS = 30
FIELDS = ["snapshot_date", "total_installs", "active_30d",
          "churned_total", "new_installs_30d", "retention_pct"]


def load_users():
    with open(USERS_CSV) as f:
        users = list(csv.DictReader(f))
    for u in users:
        u["first_seen"] = date.fromisoformat(u["first_seen"])
        u["last_activity"] = date.fromisoformat(u["last_activity"])
        u["is_dev"] = u["is_dev_account"].lower() == "true"
    return users


def snapshot(users, snap_date):
    cutoff = snap_date - timedelta(days=WINDOW_DAYS)
    cohort = [u for u in users if u["first_seen"] <= snap_date and not u["is_dev"]]
    active = [u for u in cohort if u["last_activity"] >= cutoff]
    new_installs = [u for u in cohort if u["first_seen"] >= cutoff]
    return {
        "snapshot_date": snap_date.isoformat(),
        "total_installs": len(cohort),
        "active_30d": len(active),
        "churned_total": len(cohort) - len(active),
        "new_installs_30d": len(new_installs),
        "retention_pct": round(100 * len(active) / len(cohort), 1) if cohort else 0,
    }


def write_rows(rows):
    with open(HISTORY_CSV, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        w.writeheader()
        for r in rows:
            w.writerow(r)


def rebuild():
    users = load_users()
    project_start = min(u["first_seen"] for u in users)
    today = date.today()
    # Snap on Mondays
    start = project_start + timedelta(days=(7 - project_start.weekday()) % 7)
    rows, d = [], start
    while d <= today:
        rows.append(snapshot(users, d))
        d += timedelta(days=7)
    if not rows or rows[-1]["snapshot_date"] != today.isoformat():
        rows.append(snapshot(users, today))
    write_rows(rows)
    print(f"Rebuilt {len(rows)} snapshots in {HISTORY_CSV.name}")


def append_today():
    today = date.today()
    users = load_users()
    rows = []
    if HISTORY_CSV.exists():
        with open(HISTORY_CSV) as f:
            rows = list(csv.DictReader(f))
        if rows and rows[-1]["snapshot_date"] == today.isoformat():
            print(f"Snapshot for {today} already present; nothing to do.")
            return
    rows.append(snapshot(users, today))
    write_rows(rows)
    s = rows[-1]
    print(f"Appended {today}: total={s['total_installs']} "
          f"active_30d={s['active_30d']} churned={s['churned_total']} "
          f"new_30d={s['new_installs_30d']} ret={s['retention_pct']}%")


if __name__ == "__main__":
    if "--rebuild" in sys.argv:
        rebuild()
    else:
        append_today()
