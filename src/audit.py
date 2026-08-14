"""
audit.py — Audit log persistent (SQLite) pentru NeuralScan.

Doar METADATE: cine (key_id), cand, marime, rezultate, durata.
NU stocam codul scanat (e al clientului) si NU stocam IP in clar (doar hash).

Schema gandita sa migreze usor pe Postgres (Strat 2 / monetizare):
    scans(id, ts, key_id, ip_hash, size, findings, critical, high, medium, low,
          duration_ms, status)
"""

import hashlib
import json
import os
import sqlite3
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

# BD locala (efemera pe Railway la redeploy — OK pt etapa actuala; migrare Postgres cand avem trafic)
DB_PATH = Path(os.environ.get('NEURALSCAN_DB', str(Path(__file__).resolve().parent.parent / 'audit.db')))

# Sare pt hash IP — previne reverse-engineering pe IPv4 (spatiu mic).
PEPPER = os.environ.get('NEURALSCAN_AUDIT_PEPPER', 'neuralscan-audit-v1')

_lock = threading.Lock()

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          TEXT NOT NULL,
    key_id      TEXT NOT NULL,
    ip_hash     TEXT NOT NULL,
    size        INTEGER NOT NULL,
    findings    INTEGER NOT NULL DEFAULT 0,
    critical    INTEGER NOT NULL DEFAULT 0,
    high        INTEGER NOT NULL DEFAULT 0,
    medium      INTEGER NOT NULL DEFAULT 0,
    low         INTEGER NOT NULL DEFAULT 0,
    duration_ms INTEGER NOT NULL DEFAULT 0,
    status      TEXT NOT NULL DEFAULT 'ok'
);
CREATE INDEX IF NOT EXISTS idx_scans_ts ON scans(ts);
CREATE INDEX IF NOT EXISTS idx_scans_key ON scans(key_id);
"""


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec='seconds').replace('+00:00', 'Z')


def _connect():
    conn = sqlite3.connect(str(DB_PATH), timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA journal_mode=WAL')
    return conn


def init_db():
    """Creeaza schema daca nu exista. Apelat la pornirea app."""
    with _lock:
        conn = _connect()
        try:
            conn.executescript(_SCHEMA)
            conn.commit()
        finally:
            conn.close()


def hash_ip(ip: str) -> str:
    """Hash IP cu pepper — stocam doar hash, nu IP-ul real."""
    return hashlib.sha256(f"{PEPPER}:{ip}".encode('utf-8')).hexdigest()[:16]


def log_scan(key_id: str, ip: str, size: int, summary: dict,
             duration_ms: int, status: str = 'ok'):
    """Inregistreaza un scan. Nu arunca exceptii (audit nu trebuie sa cada pe /scan)."""
    total = int(summary.get('total', 0))
    if total == 0:
        total = sum(int(summary.get(s, 0)) for s in ('critical', 'high', 'medium', 'low'))
    try:
        with _lock:
            conn = _connect()
            try:
                conn.execute(
                    """INSERT INTO scans
                       (ts, key_id, ip_hash, size, findings,
                        critical, high, medium, low, duration_ms, status)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (_now_iso(),
                     key_id, hash_ip(ip), size,
                     total,
                     int(summary.get('critical', 0)),
                     int(summary.get('high', 0)),
                     int(summary.get('medium', 0)),
                     int(summary.get('low', 0)),
                     int(duration_ms), status),
                )
                conn.commit()
            finally:
                conn.close()
    except Exception as exc:
        # Audit nu trebuie sa afecteze scan-ul. Doar log intern.
        import logging
        logging.getLogger('neuralscan.audit').error("audit write failed: %s", exc)


def get_stats(days: int = 14) -> dict:
    """Agregari pt /stats (admin). Doar metadate — fara cod, fara IP real."""
    since = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat(timespec='seconds').replace('+00:00', 'Z')
    try:
        with _lock:
            conn = _connect()
            try:
                total = conn.execute("SELECT COUNT(*) c FROM scans").fetchone()['c']
                since_total = conn.execute(
                    "SELECT COUNT(*) c FROM scans WHERE ts >= ?", (since,)).fetchone()['c']

                # Per zi (ultimele `days` zile)
                daily = conn.execute(
                    """SELECT substr(ts,1,10) d, COUNT(*) c, SUM(findings) f
                       FROM scans WHERE ts >= ? GROUP BY d ORDER BY d DESC LIMIT ?""",
                    (since, days)).fetchall()

                # Per cheie
                by_key = conn.execute(
                    """SELECT key_id, COUNT(*) c, SUM(findings) f
                       FROM scans WHERE ts >= ? GROUP BY key_id ORDER BY c DESC""",
                    (since,)).fetchall()

                # Erori + durata medie
                err = conn.execute(
                    "SELECT COUNT(*) c FROM scans WHERE status != 'ok'").fetchone()['c']
                avg_ms = conn.execute(
                    "SELECT AVG(duration_ms) a FROM scans WHERE status='ok'").fetchone()['a'] or 0

                return {
                    "total_all_time": total,
                    "total_last_days": since_total,
                    "days": days,
                    "daily": [{"date": r['d'], "scans": r['c'], "findings": r['f'] or 0} for r in daily],
                    "by_key": [{"key": r['key_id'], "scans": r['c'], "findings": r['f'] or 0} for r in by_key],
                    "errors": err,
                    "avg_duration_ms": round(avg_ms, 1),
                    "db": str(DB_PATH.name),
                }
            finally:
                conn.close()
    except Exception as exc:
        import logging
        logging.getLogger('neuralscan.audit').error("audit stats failed: %s", exc)
        return {"error": "stats unavailable", "detail": str(exc)}


def export_recent(limit: int = 50) -> list:
    """Ultimele scan-uri (admin/debug). Fara cod, fara IP real."""
    try:
        with _lock:
            conn = _connect()
            try:
                rows = conn.execute(
                    "SELECT ts, key_id, ip_hash, size, findings, duration_ms, status "
                    "FROM scans ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
                return [dict(r) for r in rows]
            finally:
                conn.close()
    except Exception:
        return []
