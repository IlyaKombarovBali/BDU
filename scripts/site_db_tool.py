#!/usr/bin/env python3
"""
Утилита для site.db: полная структура, сравнение с эталоном, миграции auth.

Примеры (из каталога BDU):
  python scripts/site_db_tool.py inspect oldbd/site.db
  python scripts/site_db_tool.py compare oldbd/site.db site.db
  python scripts/site_db_tool.py migrate-auth oldbd/site.db
"""
from __future__ import annotations

import argparse
import sqlite3
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def _connect(path: Path) -> sqlite3.Connection:
    con = sqlite3.connect(str(path))
    con.row_factory = sqlite3.Row
    return con


def list_tables(con: sqlite3.Connection) -> list[str]:
    rows = con.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
    ).fetchall()
    return [r[0] for r in rows]


def quote_ident(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def pragma_table_info(con: sqlite3.Connection, table: str) -> list[sqlite3.Row]:
    return list(con.execute(f"PRAGMA table_info({quote_ident(table)})"))


def list_indexes(con: sqlite3.Connection) -> list[str]:
    rows = con.execute(
        "SELECT name, tbl_name, sql FROM sqlite_master WHERE type='index' AND name NOT LIKE 'sqlite_%' ORDER BY tbl_name, name"
    ).fetchall()
    return rows


def inspect_db(path: Path) -> str:
    lines: list[str] = []
    lines.append(f"=== {path} ===\n")
    con = _connect(path)
    try:
        for t in list_tables(con):
            lines.append(f"\n-- TABLE {t}")
            for row in pragma_table_info(con, t):
                cid, name, col_type, notnull, default, pk = (
                    row[0],
                    row[1],
                    row[2],
                    row[3],
                    row[4],
                    row[5],
                )
                nn = " NOT NULL" if notnull else ""
                pk_s = " PRIMARY KEY" if pk else ""
                d = f" DEFAULT {default}" if default is not None else ""
                lines.append(f"  {name}: {col_type or 'TEXT'}{nn}{pk_s}{d}")
        lines.append("\n-- INDEXES")
        for name, tbl, sql in list_indexes(con):
            lines.append(f"  [{tbl}] {name}")
            if sql:
                lines.append(f"    {sql}")
    finally:
        con.close()
    return "\n".join(lines)


def column_names(con: sqlite3.Connection, table: str) -> list[str]:
    return [r[1] for r in pragma_table_info(con, table)]


def compare_dbs(old_p: Path, new_p: Path) -> str:
    lines: list[str] = []
    co = _connect(old_p)
    cn = _connect(new_p)
    try:
        to_old = set(list_tables(co))
        to_new = set(list_tables(cn))
        only_new = sorted(to_new - to_old)
        only_old = sorted(to_old - to_new)
        common = sorted(to_old & to_new)

        if only_new:
            lines.append("Таблицы есть в NEW, нет в OLD (нужно добавить на прод / миграция):")
            for t in only_new:
                lines.append(f"  + {t}")
            lines.append("")
        if only_old:
            lines.append("Таблицы есть в OLD, нет в NEW:")
            for t in only_old:
                lines.append(f"  - {t}")
            lines.append("")

        for t in common:
            co_cols = set(column_names(co, t))
            cn_cols = set(column_names(cn, t))
            miss_in_old = sorted(cn_cols - co_cols)
            miss_in_new = sorted(co_cols - cn_cols)
            if miss_in_old or miss_in_new:
                lines.append(f"Таблица «{t}»:")
                if miss_in_old:
                    lines.append(f"  колонки в NEW, которых нет в OLD: {', '.join(miss_in_old)}")
                if miss_in_new:
                    lines.append(f"  колонки в OLD, которых нет в NEW: {', '.join(miss_in_new)}")
                lines.append("")
    finally:
        co.close()
        cn.close()

    if not lines:
        return "Таблицы и наборы колонок совпадают (в рамках общих имён).\n"
    return "\n".join(lines).rstrip() + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description="site.db: inspect / compare / migrate-auth")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_in = sub.add_parser("inspect", help="Вывести все таблицы, колонки и индексы")
    p_in.add_argument("db", type=Path, help="Путь к site.db")

    p_cmp = sub.add_parser("compare", help="Сравнить OLD (прод) и NEW (эталон)")
    p_cmp.add_argument("old_db", type=Path, help="Например oldbd/site.db")
    p_cmp.add_argument("new_db", type=Path, help="Например site.db в проекте")

    p_mig = sub.add_parser("migrate-auth", help="Добавить users / bookmarks / password_resets и email")
    p_mig.add_argument("db", type=Path, help="Путь к site.db для обновления")

    args = ap.parse_args()

    if args.cmd == "inspect":
        path = args.db.resolve()
        if not path.is_file():
            print(f"Файл не найден: {path}", file=sys.stderr)
            return 1
        print(inspect_db(path))
        return 0

    if args.cmd == "compare":
        o, n = args.old_db.resolve(), args.new_db.resolve()
        for p, label in ((o, "OLD"), (n, "NEW")):
            if not p.is_file():
                print(f"{label}: файл не найден: {p}", file=sys.stderr)
                return 1
        print(compare_dbs(o, n))
        return 0

    if args.cmd == "migrate-auth":
        path = args.db.resolve()
        if not path.is_file():
            print(f"Файл не найден: {path}", file=sys.stderr)
            return 1
        import auth as auth_portal

        auth_portal.upgrade_site_db_auth(path)
        print(f"OK: применены миграции auth к {path}")
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
