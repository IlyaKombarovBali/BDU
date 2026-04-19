"""
Copy tables that exist in site.db (dev) but not in oldbd/site.db (prod copy).

Creates a timestamped backup of the prod DB file first, then CREATE + INSERT.
Safe to re-run: skips if prod already has the table.
"""
from __future__ import annotations

import shutil
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path


def list_tables(conn: sqlite3.Connection) -> list[str]:
    cur = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
    )
    return [r[0] for r in cur.fetchall()]


def quote_ident(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    prod_path = root / "oldbd" / "site.db"
    dev_path = root / "site.db"
    if not prod_path.is_file():
        print("Missing:", prod_path, file=sys.stderr)
        return 1
    if not dev_path.is_file():
        print("Missing:", dev_path, file=sys.stderr)
        return 1

    prod_conn = sqlite3.connect(str(prod_path))
    try:
        prod_tables = set(list_tables(prod_conn))
        dev_conn = sqlite3.connect(str(dev_path))
        try:
            dev_tables = set(list_tables(dev_conn))
        finally:
            dev_conn.close()

        missing = sorted(dev_tables - prod_tables)
        if not missing:
            print("Nothing to do: prod already has all dev tables.")
            return 0

        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        backup = prod_path.with_suffix(f".db.bak-{ts}")
        shutil.copy2(prod_path, backup)
        print("Backup:", backup)

        prod_conn.execute("ATTACH DATABASE ? AS dev", (str(dev_path.resolve()),))

        for name in missing:
            row = prod_conn.execute(
                "SELECT sql FROM dev.sqlite_master WHERE type='table' AND name=?",
                (name,),
            ).fetchone()
            if not row or not row[0]:
                print("Skip (no DDL):", name)
                continue
            ddl = row[0]
            print("CREATE:", name)
            prod_conn.execute(ddl)
            qn = quote_ident(name)
            n = prod_conn.execute(f"SELECT COUNT(*) FROM dev.{qn}").fetchone()[0]
            prod_conn.execute(f"INSERT INTO main.{qn} SELECT * FROM dev.{qn}")
            print(f"  inserted {n} rows")

        prod_conn.commit()
        print("Done. Tables added:", ", ".join(missing))
        return 0
    finally:
        prod_conn.close()


if __name__ == "__main__":
    sys.exit(main())
