"""
Strat 2 — Audit log (SQLite) + /stats admin:
- /scan scrie metadate in BD (fara cod, fara IP real)
- /stats returneaza agregate DOAR cu cheie admin
- Fara cheie admin -> 401
- BD nu e accesibila public (fara endpoint care serveste fisierul)
"""

import os
import sys
from pathlib import Path

_TEST_DB = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'test_audit.db')
os.environ.setdefault('NEURALSCAN_API_KEYS', 'test-key-123')
os.environ.setdefault('NEURALSCAN_ADMIN_KEY', 'admin-test-key-456')
os.environ.setdefault('NEURALSCAN_DB', _TEST_DB)

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import src.audit as audit  # noqa: E402
# app.py foloseste `import audit` (top-level) — fortam acelasi modul in memorie,
# altfel avem doua instante cu DB_PATH diferite.
sys.modules['audit'] = audit
# Fortam BD-ul de test INAINTE ca app.py sa importe modulul (fix ordine import).
audit.DB_PATH = Path(_TEST_DB)
audit.init_db()

from src.app import app  # noqa: E402

TEST_KEY = 'test-key-123'
ADMIN_KEY = 'admin-test-key-456'


def _client():
    return app.test_client()


def _scan(code, key=TEST_KEY):
    """POST /scan cu cheie (300/min) — evitam rate limit-ul anonim (30/min) din testele vechi."""
    headers = {'X-API-Key': key} if key else {}
    return _client().post('/scan', json={'code': code}, headers=headers)


def _clean_db():
    import sqlite3
    conn = sqlite3.connect(str(audit.DB_PATH))
    try:
        conn.execute('DELETE FROM scans')
        conn.commit()
    finally:
        conn.close()


def test_scan_writes_audit_row():
    """Un /scan cu cheie valida => exact o inregistrare in BD."""
    _clean_db()
    r = _scan('API_KEY = "sk-abcdefghijklmnopqrstuvwxyz123456"')
    assert r.status_code == 200

    rows = audit.export_recent(limit=10)
    assert len(rows) == 1
    assert rows[0]['key_id'].startswith('key:')
    assert rows[0]['size'] > 0
    assert rows[0]['findings'] >= 1
    assert rows[0]['status'] == 'ok'


def test_audit_never_stores_raw_code():
    """BD nu contine codul scanat — doar metadate."""
    _clean_db()
    secret_marker = 'SUPER_SECRET_MARKER_XYZ'
    _scan(f'X = "{secret_marker}"')
    rows = audit.export_recent(limit=10)
    assert len(rows) == 1
    dumped = str(rows[0])
    assert secret_marker not in dumped
    # coloanele stocate sunt doar metadate
    allowed = {'ts', 'key_id', 'ip_hash', 'size', 'findings', 'duration_ms', 'status'}
    assert set(rows[0].keys()) <= allowed


def test_audit_hashes_ip():
    """IP real nu e stocat — doar hash."""
    _clean_db()
    _scan('x = 1')
    rows = audit.export_recent(limit=10)
    assert len(rows) == 1
    ip_hash = rows[0]['ip_hash']
    assert len(ip_hash) == 16  # sha256[:16]
    assert '127.0.0.1' not in str(rows[0])
    # acelasi IP => acelasi hash (consistent pt agregare)
    assert audit.hash_ip('127.0.0.1') == ip_hash


def test_stats_requires_admin_key():
    """/stats fara cheie admin -> 401; cu cheie gresita -> 401; cu cheie corecta -> 200."""
    _clean_db()
    r_no = _client().get('/stats')
    assert r_no.status_code == 401

    r_bad = _client().get('/stats', headers={'X-Admin-Key': 'wrong-key'})
    assert r_bad.status_code == 401

    r_ok = _client().get('/stats', headers={'X-Admin-Key': ADMIN_KEY})
    assert r_ok.status_code == 200
    data = r_ok.get_json()
    assert 'total_all_time' in data
    assert 'by_key' in data
    assert 'daily' in data


def test_stats_aggregates_scans():
    """Dupa 2 scan-uri, /stats reflecta numarul."""
    _clean_db()
    c = _client()
    _scan('x = 1')
    _scan('y = 2')
    data = c.get('/stats', headers={'X-Admin-Key': ADMIN_KEY}).get_json()
    assert data['total_all_time'] == 2


def test_db_not_served_publicly():
    """Fisierul audit.db NU e accesibil via HTTP."""
    r = _client().get('/audit.db')
    assert r.status_code == 404
