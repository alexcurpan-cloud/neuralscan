"""
keys.py — Strat 2 minimal: users + API keys (hash) + revocare + ownership.

Tabele:
  users(id, email UNIQUE, plan TEXT DEFAULT 'free', created_at)
  api_keys(id, user_id FK, key_hash UNIQUE, key_prefix, rate_limit, revoked, created_at)
  scans.owner_id — coloana se adauga prin migrare in audit.py

Reguli:
  - Cheia se stocheaza DOAR ca SHA-256 hash; plaintext-ul se afiseaza o singura data.
  - Revocare = flag revoked=1 → lookup nu mai gaseste cheia (401 imediat, fara redeploy).
  - Rate limit per cheie din DB (free=30/min, pro=300/min).
"""
import hashlib
import os
import secrets
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path

DB_PATH = Path(os.environ.get('NEURALSCAN_DB', str(Path(__file__).resolve().parent.parent / 'audit.db')))

PLAN_RATE_LIMITS = {
    'free': 30,
    'pro': 300,
}

_lock = threading.Lock()

_SCHEMA = """
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


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec='seconds').replace('+00:00', 'Z')


def _connect():
    conn = sqlite3.connect(str(DB_PATH), timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA journal_mode=WAL')
    return conn


def init_db():
    """Creeaza tabelele daca nu exista. Apelat la pornire."""
    with _lock:
        conn = _connect()
        try:
            conn.executescript(_SCHEMA)
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
            conn.execute(
                "INSERT OR IGNORE INTO users (email, plan, created_at) VALUES (?, ?, ?)",
                (email, plan, _now_iso()))
            conn.commit()
            row = conn.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
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
            conn.execute(
                "INSERT INTO api_keys (user_id, key_hash, key_prefix, rate_limit, created_at) "
                "VALUES (?, ?, ?, ?, ?)",
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
            row = conn.execute(
                "SELECT k.id AS key_id, k.key_prefix, k.rate_limit, k.revoked, "
                "       u.id AS user_id, u.email, u.plan "
                "FROM api_keys k JOIN users u ON u.id = k.user_id "
                "WHERE k.key_hash = ?", (key_hash,)).fetchone()
            if row is None or row['revoked']:
                return None
            return dict(row)
        finally:
            conn.close()


def revoke_key(key_prefix: str) -> bool:
    """Revoca o cheie dupa prefix (ns_abc...). Returneaza True daca a gasit ceva de revocat."""
    with _lock:
        conn = _connect()
        try:
            cur = conn.execute(
                "UPDATE api_keys SET revoked = 1 WHERE key_prefix = ? AND revoked = 0",
                (key_prefix,))
            conn.commit()
            return cur.rowcount > 0
        finally:
            conn.close()


def revoke_key_by_id(key_id: int) -> bool:
    with _lock:
        conn = _connect()
        try:
            cur = conn.execute(
                "UPDATE api_keys SET revoked = 1 WHERE id = ? AND revoked = 0", (key_id,))
            conn.commit()
            return cur.rowcount > 0
        finally:
            conn.close()


def list_keys() -> list:
    """Toate cheile (fara hash complet — doar prefix + stare)."""
    with _lock:
        conn = _connect()
        try:
            rows = conn.execute(
                "SELECT k.id, k.key_prefix, k.rate_limit, k.revoked, k.created_at, "
                "       u.email, u.plan "
                "FROM api_keys k JOIN users u ON u.id = k.user_id "
                "ORDER BY k.id").fetchall()
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
                exists = conn.execute(
                    "SELECT 1 FROM api_keys WHERE key_hash = ?", (key_hash,)).fetchone()
                if not exists:
                    conn.execute(
                        "INSERT INTO api_keys (user_id, key_hash, key_prefix, rate_limit, created_at) "
                        "VALUES (?, ?, ?, ?, ?)",
                        (user_id, key_hash, k[:8], PLAN_RATE_LIMITS['free'], _now_iso()))
                    seeded += 1
            conn.commit()
        finally:
            conn.close()
    return seeded


if __name__ == '__main__':
    # Utilizare CLI minimala (vezi keymgmt.py pentru comenzi complete)
    init_db()
    print("keys.py OK — DB:", DB_PATH)
