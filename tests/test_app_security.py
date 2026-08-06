"""
Securitate Strat 0 — teste pentru protecțiile noi din app.py:
- Limită dimensiune input (100KB → 413)
- Rate limit pe /scan (30/min per IP → 429)
- Fără scurgeri de traceback la client (500 generic)
- Headere de securitate pe toate răspunsurile
- Validare tip input
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.app import app


def _client():
    return app.test_client()


def test_scan_still_works():
    """Scan normal rămâne funcțional (regresie)."""
    r = _client().post('/scan', json={
        'code': 'API_KEY = "sk-abcdefghijklmnopqrstuvwxyz123456"'
    })
    assert r.status_code == 200
    data = r.get_json()
    assert data['status'] == 'ok'
    assert data['total'] >= 1


def test_oversize_code_rejected():
    """Cod > 100KB → 413 (anti-DoS)."""
    big = 'x = 1\n' * 20000  # ~120KB
    r = _client().post('/scan', json={'code': big})
    assert r.status_code == 413


def test_non_string_code_rejected():
    """code non-string → 400."""
    r = _client().post('/scan', json={'code': 12345})
    assert r.status_code == 400


def test_no_traceback_leak(monkeypatch):
    """Eroare internă → 500 generic, fără traceback/detalii în răspuns."""
    from src import app as app_module

    def boom(code, filename="input.py"):
        raise RuntimeError("secret-internal-path-detail")

    monkeypatch.setattr(app_module, 'scan_code', boom)
    r = app.test_client().post('/scan', json={'code': 'x = 1'})
    assert r.status_code == 500
    body_text = r.get_data(as_text=True)
    assert 'secret-internal-path-detail' not in body_text
    assert 'Traceback' not in body_text
    assert r.get_json()['error']


def test_security_headers():
    """Headere de securitate pe toate răspunsurile."""
    for path in ['/', '/health']:
        r = _client().get(path)
        assert r.status_code == 200
        assert r.headers.get('X-Content-Type-Options') == 'nosniff'
        assert r.headers.get('X-Frame-Options') == 'DENY'
        assert r.headers.get('Referrer-Policy') == 'no-referrer'
        assert 'Content-Security-Policy' in r.headers


def test_rate_limit():
    """>30 request-uri/min la /scan → 429 (anti-abuz)."""
    statuses = []
    for _ in range(35):
        r = _client().post('/scan', json={'code': 'x = 1'})
        statuses.append(r.status_code)
    assert 200 in statuses, "primele request-uri trebuie sa treaca"
    assert 429 in statuses, "dupa limita de 30/min trebuie sa vina 429"
