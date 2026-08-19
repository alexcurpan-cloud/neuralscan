"""
Admin keys API tests — NS-PG fix: creare/revocare/listare chei in productie via HTTP.
De ce exista: `railway run` nu tunelizeaza postgres.railway.internal pe CLI-ul curent,
deci keymgmt-ul local nu poate crea chei in Postgres-ul de productie. Aceste endpoint-uri
ruleaza IN INTERIOR (URL intern OK), protejate cu X-Admin-Key (privilege minim).

Criterii:
- C1: fara X-Admin-Key / cheie gresita -> 401 (nu 500, nu merge anonim)
- C2: POST /admin/keys cu cheie admin -> 201 + plaintext afisat O SINGURA DATA
- C3: cheia creata merge pe /scan (200) si apare in /user/scans
- C4: POST /admin/keys/revoke -> cheia devine 401 imediat pe /scan
- C5: GET /admin/keys -> doar prefix + stare, NICIODATA hash/plaintext complet
- C6: input invalid (email lipsa/prost, plan necunoscut) -> 400
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import keys
from src.app import app

ADMIN = os.environ.get('NEURALSCAN_ADMIN_KEY', 'admin-test-key-456')


def _admin_headers():
    return {'X-Admin-Key': ADMIN}


# ─── C1: auth admin obligatorie ─────────────────────────────────────

def test_admin_keys_requires_admin():
    c = app.test_client()
    r = c.post('/admin/keys', json={'email': 'x@test.com', 'plan': 'free'})
    assert r.status_code == 401
    r2 = c.post('/admin/keys', json={'email': 'x@test.com', 'plan': 'free'},
                headers={'X-Admin-Key': 'wrong-key'})
    assert r2.status_code == 401


def test_admin_list_requires_admin():
    c = app.test_client()
    r = c.get('/admin/keys')
    assert r.status_code == 401


# ─── C2: creare cheie via API ───────────────────────────────────────

def test_admin_create_key_returns_plaintext_once():
    c = app.test_client()
    r = c.post('/admin/keys', json={'email': 'admin-create@test.com', 'plan': 'free'},
               headers=_admin_headers())
    assert r.status_code == 201
    data = r.get_json()
    assert data['key'].startswith('ns_')
    assert len(data['key']) > 20
    assert data['key_prefix'] == data['key'][:8]
    assert data['email'] == 'admin-create@test.com'
    assert data['plan'] == 'free'
    assert data['rate_limit'] == 30
    # plaintext-ul NU e stocat in DB (doar hash)
    import hashlib
    import sqlite3
    conn = sqlite3.connect(str(keys.DB_PATH))
    rows = conn.execute("SELECT key_hash FROM api_keys").fetchall()
    conn.close()
    hashes = [r[0] for r in rows]
    assert data['key'] not in hashes
    assert hashlib.sha256(data['key'].encode()).hexdigest() in hashes


def test_admin_create_pro_plan():
    c = app.test_client()
    r = c.post('/admin/keys', json={'email': 'admin-pro@test.com', 'plan': 'pro'},
               headers=_admin_headers())
    assert r.status_code == 201
    assert r.get_json()['rate_limit'] == 300


# ─── C3: cheia creata e functionala ─────────────────────────────────

def test_admin_created_key_works_on_scan():
    c = app.test_client()
    r = c.post('/admin/keys', json={'email': 'admin-scan@test.com', 'plan': 'free'},
               headers=_admin_headers())
    key = r.get_json()['key']
    r2 = c.post('/scan', json={'code': 'x = 1'}, headers={'X-API-Key': key})
    assert r2.status_code == 200
    r3 = c.get('/user/scans', headers={'X-API-Key': key})
    assert r3.status_code == 200
    assert r3.get_json()['user'] == 'admin-scan@test.com'
    assert len(r3.get_json()['scans']) == 1


# ─── C4: revocare via API ───────────────────────────────────────────

def test_admin_revoke_via_api():
    c = app.test_client()
    r = c.post('/admin/keys', json={'email': 'admin-revoke@test.com', 'plan': 'free'},
               headers=_admin_headers())
    data = r.get_json()
    key, prefix = data['key'], data['key_prefix']
    assert c.post('/scan', json={'code': 'x = 1'}, headers={'X-API-Key': key}).status_code == 200
    rr = c.post('/admin/keys/revoke', json={'key_prefix': prefix}, headers=_admin_headers())
    assert rr.status_code == 200
    assert rr.get_json()['revoked'] is True
    assert c.post('/scan', json={'code': 'x = 1'}, headers={'X-API-Key': key}).status_code == 401


def test_admin_revoke_unknown_prefix_404():
    c = app.test_client()
    r = c.post('/admin/keys/revoke', json={'key_prefix': 'ns_nonexistent'},
               headers=_admin_headers())
    assert r.status_code == 404


# ─── C5: listare fara hash/plaintext ────────────────────────────────

def test_admin_list_keys_no_secrets():
    c = app.test_client()
    r = c.get('/admin/keys', headers=_admin_headers())
    assert r.status_code == 200
    body = r.get_json()
    assert 'keys' in body
    assert isinstance(body['keys'], list)
    for k in body['keys']:
        assert 'key_hash' not in k
        assert 'key' not in k or k['key'] is None  # niciodata plaintext
        assert 'key_prefix' in k
        assert 'email' in k
        assert 'revoked' in k


# ─── C6: input invalid -> 400 ───────────────────────────────────────

def test_admin_create_invalid_input():
    c = app.test_client()
    assert c.post('/admin/keys', json={}, headers=_admin_headers()).status_code == 400
    assert c.post('/admin/keys', json={'email': 'not-an-email', 'plan': 'free'},
                  headers=_admin_headers()).status_code == 400
    assert c.post('/admin/keys', json={'email': 'ok@test.com', 'plan': 'enterprise'},
                  headers=_admin_headers()).status_code == 400
    assert c.post('/admin/keys', json={'email': 'ok@test.com', 'plan': 'free'},
                  headers=_admin_headers()).status_code == 201


def test_admin_revoke_invalid_input():
    c = app.test_client()
    assert c.post('/admin/keys/revoke', json={}, headers=_admin_headers()).status_code == 400
