"""
Daily scan limit tests — cap anti-abuz per cheie (reset la miezul noptii UTC).

De ce exista: rate limit (30/min) protejeaza frecventa, NU volumul zilnic.
Un tester/script poate reveni in fiecare minut si arde resurse toata ziua.
Capul zilnic per cheie limiteaza volumul total (si pregateste terenul pt
deep-scan-ul Strix ~$2-4/run cand devine expus).

Criterii:
- C1: cheie free cu limita mica (monkeypatch) -> 429 la depasire
- C2: raspunsul 429 contine daily_limit + daily_used
- C3: anonimul NU e blocat de capul zilnic (are doar rate limit)
- C4: limitele default sunt sanatoase (free=50, pro=500) si plan necunoscut -> free
"""
import os
import sys
import uuid

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import keys
from src.app import app


def _fresh_key(email=None):
    """Creeaza o cheie fresh (email unic) ca sa nu depindem de scanurile altor teste."""
    email = email or f"limit-{uuid.uuid4().hex[:10]}@test.com"
    created = keys.create_key(email, 'free')
    return created['key']


def test_daily_limit_429_after_cap():
    """C1: cu limita monkeypatch-uita la 2, al 3-lea scan -> 429."""
    original = keys.PLAN_DAILY_LIMITS['free']
    keys.PLAN_DAILY_LIMITS['free'] = 2
    try:
        key = _fresh_key()
        c = app.test_client()
        headers = {'X-API-Key': key}
        payload = {'code': 'print("x")', 'filename': 'a.py'}

        r1 = c.post('/scan', json=payload, headers=headers)
        r2 = c.post('/scan', json=payload, headers=headers)
        r3 = c.post('/scan', json=payload, headers=headers)
        assert r1.status_code == 200, r1.status_code
        assert r2.status_code == 200, r2.status_code
        assert r3.status_code == 429, r3.status_code
    finally:
        keys.PLAN_DAILY_LIMITS['free'] = original


def test_daily_limit_429_body():
    """C2: raspunsul 429 are campurile daily_limit + daily_used."""
    original = keys.PLAN_DAILY_LIMITS['free']
    keys.PLAN_DAILY_LIMITS['free'] = 0  # deja peste limita din start
    try:
        key = _fresh_key()
        c = app.test_client()
        r = c.post('/scan', json={'code': 'x=1'}, headers={'X-API-Key': key})
        assert r.status_code == 429
        body = r.get_json()
        assert 'daily_limit' in body and body['daily_limit'] == 0
        assert 'daily_used' in body and body['daily_used'] >= 0
        assert 'error' in body
    finally:
        keys.PLAN_DAILY_LIMITS['free'] = original


def test_anon_not_blocked_by_daily_cap():
    """C3: anonimul (fara X-API-Key) nu e blocat de capul zilnic.

    Rate limit-ul per IP (30/min) poate da 429 din alte cauze (testele ruleaza
    din aceeasi adresa), deci verificam invers: NICIUN 429 anonim nu poate veni
    de la capul zilnic (niciun raspuns nu are campul daily_limit).
    """
    original = keys.PLAN_DAILY_LIMITS['free']
    keys.PLAN_DAILY_LIMITS['free'] = 1
    try:
        c = app.test_client()
        for _ in range(3):
            r = c.post('/scan', json={'code': 'y=2', 'filename': 'b.py'})
            # daca e 429, nu poate fi din capul zilnic (anonimii nu au cheie)
            if r.status_code == 429:
                body = r.get_json()
                assert 'daily_limit' not in body, body
                assert 'daily_used' not in body, body
            else:
                assert r.status_code == 200, r.status_code
    finally:
        keys.PLAN_DAILY_LIMITS['free'] = original


def test_default_limits_sane():
    """C4: limitele default + fallback pentru plan necunoscut."""
    assert keys.daily_limit_for('free') == 50
    assert keys.daily_limit_for('pro') == 500
    assert keys.daily_limit_for('ceva-nescris') == 50  # fallback la free
