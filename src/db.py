"""
db.py — strat DB dual: SQLite (local/test) sau Postgres (producție).

Alegerea se face la import prin env:
    NEURALSCAN_DATABASE_URL  setat (postgres://...) -> Postgres (psycopg)
    altfel                   -> SQLite (NEURALSCAN_DB sau audit.db implicit)

Query-urile se scriu cu placeholder `?` (stil sqlite); pentru Postgres se
traduc in `%s` prin q() — doar in valorile parametrizate, niciodata in SQL.
"""
import os
import sqlite3
from pathlib import Path

DATABASE_URL = os.environ.get('NEURALSCAN_DATABASE_URL', '').strip()
USING_PG = DATABASE_URL.startswith('postgresql://') or DATABASE_URL.startswith('postgres://')

# Cale SQLite implicita (aceeasi conventie ca audit.py)
DEFAULT_SQLITE = str(Path(__file__).resolve().parent.parent / 'audit.db')


def connect():
    """Conexiune: psycopg (dict_row) sau sqlite3 (Row + WAL)."""
    if USING_PG:
        import psycopg
        from psycopg.rows import dict_row
        conn = psycopg.connect(DATABASE_URL, connect_timeout=10)
        conn.row_factory = dict_row
        return conn
    path = Path(os.environ.get('NEURALSCAN_DB', DEFAULT_SQLITE))
    conn = sqlite3.connect(str(path), timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA journal_mode=WAL')
    return conn


def q(sql: str) -> str:
    """Traduce placeholder-urile `?` in `%s` pentru Postgres."""
    return sql.replace('?', '%s') if USING_PG else sql


def table_columns(table: str) -> list:
    """Numele coloanelor unui tabel (compatibil SQLite + Postgres)."""
    if USING_PG:
        conn = connect()
        try:
            rows = conn.execute(
                "SELECT column_name FROM information_schema.columns WHERE table_name = %s",
                (table,)).fetchall()
            return [r['column_name'] for r in rows]
        finally:
            conn.close()
    else:
        conn = connect()
        try:
            rows = conn.execute(f'PRAGMA table_info({table})').fetchall()
            return [r['name'] for r in rows]
        finally:
            conn.close()
