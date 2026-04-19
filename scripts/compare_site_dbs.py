"""Compare oldbd/site.db (prod copy) vs site.db; print schema diff."""
import sqlite3
from pathlib import Path


def tables(path: str):
    c = sqlite3.connect(path)
    cur = c.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
    )
    t = [r[0] for r in cur.fetchall()]
    c.close()
    return t


def table_sql(path: str, name: str):
    c = sqlite3.connect(path)
    row = c.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name=?",
        (name,),
    ).fetchone()
    c.close()
    return row[0] if row else None


def row_count(path: str, name: str):
    c = sqlite3.connect(path)
    n = c.execute(f'SELECT COUNT(*) FROM "{name}"').fetchone()[0]
    c.close()
    return n


def main():
    root = Path(__file__).resolve().parents[1]
    prod = str(root / "oldbd" / "site.db")
    dev = str(root / "site.db")
    sp = set(tables(prod))
    sd = set(tables(dev))
    only_dev = sorted(sd - sp)
    only_prod = sorted(sp - sd)
    common = sorted(sp & sd)
    print("=== PROD (oldbd/site.db) ===", tables(prod))
    print("=== DEV (site.db) ===", tables(dev))
    print("\nOnly in DEV (missing on prod):", only_dev)
    print("Only in PROD:", only_prod)
    print("\n--- Row counts (common tables) ---")
    for t in common:
        cp, cd = row_count(prod, t), row_count(dev, t)
        if cp != cd:
            print(f"  {t}: prod={cp} dev={cd}")
    print("\n--- CREATE for tables only in DEV ---")
    for t in only_dev:
        print(table_sql(dev, t))


if __name__ == "__main__":
    main()
