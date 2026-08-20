"""
keys.py — Strat 2: users + API keys (hash) + revocare + ownership.

DB: SQLite local/test, Postgres in productie (prin db.py).

Reguli:
  - Cheia se stocheaza DOAR ca SHA-256 hash; plaintext-ul se afiseaza o singura data.
  - Revocare = flag revoked=1 → lookup nu mai gaseste cheia (401 imediat, fara redeploy).
  - Rate limit per cheie din DB (free=30/min, pro=300/min).
"""
import hashlib
import os
import secrets
import sqlite3
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path

# asigura ca src/ e in path (keys poate fi importat direct)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import db
from db import USING_PG, q as _q, table_columns as _table_columns

DB_PATH = Path(os.environ.get('NEURALSCAN_DB', str(Path(__file__).resolve().parent.parent / 'audit.db')))

PLAN_RATE_LIMITS = {
    'free': 30,
    'pro': 300,
}

# Anti-abuz: cate scanuri are voie o cheie pe ZI (UTC). Scannerul regex e ~0 cost,
# dar protejeaza CPU-ul si pregateste terenul pt deep-scan (Strix ~$2-4) cand devine expus.
PLAN_DAILY_LIMITS = {
    'free': 50,
    'pro': 500,
}

_lock = threading.Lock()

_SQLITE_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    email       TEXT NOT NULL UNIQUE,
    plan        TEXT NOT NULL DEFAULT 'free',
    created_at  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS api_keys (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL REFERENCES users(id),
    key_hash    TEXT NOT NULL UNIQUE,
    key_prefix  TEXT NOT NULL,
    rate_limit  INTEGER NOT NULL DEFAULT 30,
    revoked     INTEGER NOT NULL DEFAULT 0,
    created_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash);
CREATE INDEX IF NOT EXISTS idx_api_keys_user ON api_keys(user_id);
"""

_PG_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id          BIGSERIAL PRIMARY KEY,
    email       TEXT NOT NULL UNIQUE,
    plan        TEXT NOT NULL DEFAULT 'free',
    created_at  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS api_keys (
    id          BIGSERIAL PRIMARY KEY,
    user_id     INTEGER NOT NULL REFERENCES users(id),
    key_hash    TEXT NOT NULL UNIQUE,
    key_prefix  TEXT NOT NULL,
    rate_limit  INTEGER NOT NULL DEFAULT 30,
    revoked     INTEGER NOT NULL DEFAULT 0,
    created_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash);
CREATE INDEX IF NOT EXISTS idx_api_keys_user ON api_keys(user_id);
"""

_SCHEMA = _PG_SCHEMA if USING_PG else _SQLITE_SCHEMA


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec='seconds').replace('+00:00', 'Z')


def _connect():
    return db.connect()


def init_db():
    """Creeaza tabelele daca nu exista. Apelat la pornire."""
    with _lock:
        conn = _connect()
        try:
            # split pe ';' — psycopg nu suporta executescript
            for stmt in [s.strip() for s in _SCHEMA.split(';') if s.strip()]:
                conn.execute(stmt)
            conn.commit()
        finally:
            conn.close()


def _hash_key(plaintext: str) -> str:
    return hashlib.sha256(plaintext.encode('utf-8')).hexdigest()


# ─── Key lifecycle ─────────────────────────────────────────────────

def _get_or_create_user(email: str, plan: str = 'free'):
    with _lock:
        conn = _connect()
        try:
            conn.execute(_q(
                "INSERT INTO users (email, plan, created_at) VALUES (?, ?, ?) "
                "ON CONFLICT(email) DO NOTHING"),
                (email, plan, _now_iso()))
            conn.commit()
            row = conn.execute(_q("SELECT id FROM users WHERE email = ?"), (email,)).fetchone()
            return row['id']
        finally:
            conn.close()


def create_key(email: str, plan: str = 'free') -> dict:
    """Creeaza o cheie pentru user. Returneaza plaintext-ul O SINGURA DATA (nu se mai poate recupera)."""
    if plan not in PLAN_RATE_LIMITS:
        raise ValueError(f"plan necunoscut: {plan} (alege din {list(PLAN_RATE_LIMITS)})")
    user_id = _get_or_create_user(email, plan)
    plaintext = 'ns_' + secrets.token_urlsafe(18)
    key_hash = _hash_key(plaintext)
    key_prefix = plaintext[:8]
    rate_limit = PLAN_RATE_LIMITS[plan]
    with _lock:
        conn = _connect()
        try:
            conn.execute(_q(
                "INSERT INTO api_keys (user_id, key_hash, key_prefix, rate_limit, created_at) "
                "VALUES (?, ?, ?, ?, ?)"),
                (user_id, key_hash, key_prefix, rate_limit, _now_iso()))
            conn.commit()
        finally:
            conn.close()
    return {
        "key": plaintext,          # singura data cand apare in clar
        "key_prefix": key_prefix,  # pt afisare/revocare
        "email": email,
        "plan": plan,
        "rate_limit": rate_limit,
    }


def lookup_by_key(plaintext: str):
    """Cheie -> (user, key) sau None. Cheile revocate nu se mai gasesc."""
    if not plaintext:
        return None
    key_hash = _hash_key(plaintext)
    with _lock:
        conn = _connect()
        try:
            row = conn.execute(_q(
                "SELECT k.id AS key_id, k.key_prefix, k.rate_limit, k.revoked, "
                "       u.id AS user_id, u.email, u.plan "
                "FROM api_keys k JOIN users u ON u.id = k.user_id "
                "WHERE k.key_hash = ?"), (key_hash,)).fetchone()
            if row is None or row['revoked']:
                return None
            return dict(row)
        finally:
            conn.close()


def daily_scans_used(key_label: str) -> int:
    """Cate scanuri a facut aceasta cheie azi (UTC).

    key_label = stringul din audit (ex: 'user:email key:prefix'), acelasi pe care
    il scrie app.py in scans.key_id. 'anon' / gol -> 0 (anonimii au doar rate limit).
    """
    if not key_label or key_label == 'anon':
        return 0
    start_of_day = datetime.now(timezone.utc).replace(
        hour=0, minute=0, second=0, microsecond=0
    ).isoformat(timespec='seconds').replace('+00:00', 'Z')
    with _lock:
        conn = _connect()
        try:
            row = conn.execute(_q(
                "SELECT COUNT(*) AS n FROM scans WHERE key_id = ? AND ts >= ?"),
                (key_label, start_of_day)).fetchone()
            return int(row['n'])
        finally:
            conn.close()


def daily_limit_for(plan: str) -> int:
    """Limita zilnica pt plan (fallback la free)."""
    return PLAN_DAILY_LIMITS.get(plan, PLAN_DAILY_LIMITS['free'])


def revoke_key(key_prefix: str) -> bool:
    """Revoca o cheie dupa prefix (ns_abc...). Returneaza True daca a gasit ceva de revocat."""
    with _lock:
        conn = _connect()
        try:
            cur = conn.execute(_q(
                "UPDATE api_keys SET revoked = 1 WHERE key_prefix = ? AND revoked = 0"),
                (key_prefix,))
            conn.commit()
            return cur.rowcount > 0
        finally:
            conn.close()


def revoke_key_by_id(key_id: int) -> bool:
    with _lock:
        conn = _connect()
        try:
            cur = conn.execute(_q(
                "UPDATE api_keys SET revoked = 1 WHERE id = ? AND revoked = 0"), (key_id,))
            conn.commit()
            return cur.rowcount > 0
        finally:
            conn.close()


def list_keys() -> list:
    """Toate cheile (fara hash complet — doar prefix + stare)."""
    with _lock:
        conn = _connect()
        try:
            rows = conn.execute(_q(
                "SELECT k.id, k.key_prefix, k.rate_limit, k.revoked, k.created_at, "
                "       u.email, u.plan "
                "FROM api_keys k JOIN users u ON u.id = k.user_id "
                "ORDER BY k.id")).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()


def owner_id_for_key(plaintext: str):
    """owner_id (user_id) pt audit, sau None daca cheia nu e in DB (legacy/anonymous)."""
    row = lookup_by_key(plaintext)
    return row['user_id'] if row else None


def seed_legacy_env_keys(env_keys: str):
    """Cheile vechi din NEURALSCAN_API_KEYS -> user 'legacy' (migrare lina)."""
    keys = {k.strip() for k in (env_keys or '').split(',') if k.strip()}
    if not keys:
        return 0
    user_id = _get_or_create_user('legacy@local', 'free')
    seeded = 0
    with _lock:
        conn = _connect()
        try:
            for k in keys:
                key_hash = _hash_key(k)
                exists = conn.execute(_q(
                    "SELECT 1 FROM api_keys WHERE key_hash = ?"), (key_hash,)).fetchone()
                if not exists:
                    conn.execute(_q(
                        "INSERT INTO api_keys (user_id, key_hash, key_prefix, rate_limit, created_at) "
                        "VALUES (?, ?, ?, ?, ?)"),
                        (user_id, key_hash, k[:8], PLAN_RATE_LIMITS['free'], _now_iso()))
                    seeded += 1
            conn.commit()
        finally:
            conn.close()
    return seeded


if __name__ == '__main__':
    # Utilizare CLI minimala (vezi keymgmt.py pentru comenzi complete)
    init_db()
    print("keys.py OK — DB:", "postgres" if USING_PG else DB_PATH)
