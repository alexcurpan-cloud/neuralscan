"""
Strat 2 tests — users + chei hashed + revocare + ownership (18-Aug).
Criterii de acceptare NS-STRAT2-GO: C1 hash-only, C2 revocare 401, C3 owner-scoping,
C4 legacy env merge, C5 rate limit free/pro, C6 52 existente + noi trec.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import keys
from src.app import app

# ─── C1: hash-only storage ──────────────────────────────────────────

def test_create_key_returns_plaintext_once():
    info = keys.create_key('c1-tester@test.com', 'free')
    assert info['key'].startswith('ns_')
    assert len(info['key']) > 20
    assert info['plan'] == 'free'
    assert info['rate_limit'] == 30


def test_db_stores_only_hash():
    info = keys.create_key('c1-hash@test.com', 'free')
    import sqlite3
    conn = sqlite3.connect(str(keys.DB_PATH))
    rows = conn.execute("SELECT key_hash, key_prefix FROM api_keys").fetchall()
    conn.close()
    plaintext = info['key']
    # plaintext-ul NU trebuie sa apara nicaieri (nici ca hash, nici ca prefix integral)
    assert plaintext not in [r[0] for r in rows]
    assert info['key_prefix'] in [r[1] for r in rows]
    # hash-ul stocat e SHA-256 al cheii
    import hashlib
    assert hashlib.sha256(plaintext.encode()).hexdigest() in [r[0] for r in rows]


# ─── C2: revocare ───────────────────────────────────────────────────

def test_revoke_blocks_lookup():
    info = keys.create_key('c2-revoke@test.com', 'free')
    assert keys.lookup_by_key(info['key']) is not None
    ok = keys.revoke_key(info['key_prefix'])
    assert ok is True
    assert keys.lookup_by_key(info['key']) is None  # 401 path


def test_revoke_via_api_401():
    info = keys.create_key('c2-revoke-api@test.com', 'free')
    c = app.test_client()
    r = c.post('/scan', json={'code': 'x = 1'}, headers={'X-API-Key': info['key']})
    assert r.status_code == 200
    keys.revoke_key(info['key_prefix'])
    r2 = c.post('/scan', json={'code': 'x = 1'}, headers={'X-API-Key': info['key']})
    assert r2.status_code == 401


# ─── C3: owner-scoping ──────────────────────────────────────────────

def test_owner_scoping_two_users():
    a = keys.create_key('c3-user-a@test.com', 'free')
    b = keys.create_key('c3-user-b@test.com', 'free')
    c = app.test_client()
    for _ in range(2):
        c.post('/scan', json={'code': 'x = 1'}, headers={'X-API-Key': a['key']})
    c.post('/scan', json={'code': 'y = 2'}, headers={'X-API-Key': b['key']})

    r_a = c.get('/user/scans', headers={'X-API-Key': a['key']})
    r_b = c.get('/user/scans', headers={'X-API-Key': b['key']})
    assert r_a.status_code == 200
    assert r_b.status_code == 200
    scans_a = r_a.get_json()['scans']
    scans_b = r_b.get_json()['scans']
    assert len(scans_a) == 2, f"user A trebuie sa vada DOAR 2 scan-uri, vede {len(scans_a)}"
    assert len(scans_b) == 1, f"user B trebuie sa vada DOAR 1 scan, vede {len(scans_b)}"
    assert r_a.get_json()['user'] == 'c3-user-a@test.com'
    assert r_b.get_json()['user'] == 'c3-user-b@test.com'


def test_user_scans_requires_db_key():
    c = app.test_client()
    r = c.get('/user/scans')  # anonim
    assert r.status_code == 401
    r2 = c.get('/user/scans', headers={'X-API-Key': 'legacy-env-key'})
    assert r2.status_code == 401  # legacy env key nu are owner in DB


# ─── C4: legacy env keys ────────────────────────────────────────────

def test_legacy_env_key_still_works():
    c = app.test_client()
    r = c.post('/scan', json={'code': 'x = 1'},
               headers={'X-API-Key': os.environ.get('NEURALSCAN_API_KEYS', 'test-key-123').split(',')[0]})
    assert r.status_code == 200


def test_seed_legacy_env_keys():
    n = keys.seed_legacy_env_keys('legacy1,legacy2,legacy1')
    # 'legacy1' apare o singura data (hash UNIQUE), 'legacy2' odata -> 2 noi
    assert n >= 0  # idempotent-ish; existenta prealabila in alte teste nu conteaza
    assert keys.lookup_by_key('legacy1') is not None
    assert keys.lookup_by_key('legacy2') is not None


# ─── C5: rate limit per plan ────────────────────────────────────────

def test_rate_limit_per_plan():
    free = keys.create_key('c5-free@test.com', 'free')
    pro = keys.create_key('c5-pro@test.com', 'pro')
    assert free['rate_limit'] == 30
    assert pro['rate_limit'] == 300
    assert keys.lookup_by_key(free['key'])['rate_limit'] == 30
    assert keys.lookup_by_key(pro['key'])['rate_limit'] == 300


# ─── Extra: plan invalid ────────────────────────────────────────────

def test_invalid_plan_rejected():
    import pytest
    with pytest.raises(ValueError):
        keys.create_key('c5-bad@test.com', 'enterprise')
