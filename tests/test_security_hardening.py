"""
Security hardening tests (18-Aug-2026):
- ReDoS: input adversarial pe scan_code trebuie sa fie LINIAR (sub prag).
  Inainte de fix: 'os.system(' x 10k = 6.5s. Dupa fix: <0.2s.
- filename non-string / oversized -> 400 (nu 500).
- Pastrarea detectiei pe formele standard dupa optimizarea pattern-urilor.
"""
import sys
import os
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.scanner import scan_code
from src.app import app

# Prag generos (1s): prinde comportament patratic (secunde), fara flaky pe CI.
REDOS_LIMIT_S = 1.0

ADVERSARIAL_CASES = {
    "command_injection_nested": ('os.system(' * 10000),   # 100KB
    "debug_nested":            ('app.run(' * 12000),      # 96KB
    "http_nested":             ('http://' * 14000),       # 98KB
    "sql_format_nested":       ('execute("' * 11000),     # 99KB
    "db_url_nested":           ('postgres://' * 11000),   # 121KB
}


# ─── ReDoS ──────────────────────────────────────────────────────────

def test_redos_adversarial_inputs_linear():
    """Input adversarial ~100KB nu trebuie sa blocheze scanarea (liniaritate)."""
    for name, payload in ADVERSARIAL_CASES.items():
        t0 = time.perf_counter()
        scan_code(payload, 'adv.py')
        dt = time.perf_counter() - t0
        assert dt < REDOS_LIMIT_S, (
            f"{name}: {dt:.2f}s peste pragul {REDOS_LIMIT_S}s — "
            f"posibil backtracking patratic (ReDoS)"
        )


def test_redos_worst_case_bounded():
    """Cazul cel mai rau cunoscut (era 6.5s inainte de fix) sub prag."""
    t0 = time.perf_counter()
    scan_code('os.system(' * 10000, 'adv.py')
    dt = time.perf_counter() - t0
    assert dt < REDOS_LIMIT_S, f"command_injection nested: {dt:.2f}s"


# ─── Pastrarea detectiei (regresie dupa optimizare) ─────────────────

def test_command_injection_concat_still_detected():
    """os.system(\"ping \" + host) — ghilimeaua + e cea de inchidere."""
    res = scan_code('os.system("ping " + host)', 't.py')
    assert any(f["type"] == "command_injection" for f in res)


def test_command_injection_fstring_still_detected():
    res = scan_code('os.system(f"ping {host}")', 't.py')
    assert any(f["type"] == "command_injection" for f in res)


def test_sql_format_percent_placeholder_still_detected():
    res = scan_code('cursor.execute("SELECT * FROM users WHERE name = %s" % name)', 't.py')
    assert any(f["type"] == "sql_injection_format" for f in res)


def test_insecure_http_with_path_still_detected():
    res = scan_code('url = "http://api.example.com/data"', 't.py')
    assert any(f["type"] == "insecure_http" for f in res)


def test_debug_mode_with_host_still_detected():
    res = scan_code('app.run(debug=True, host="0.0.0.0")', 't.py')
    assert any(f["type"] == "hardcoded_debug" for f in res)


# ─── Filename validation (app.py) ───────────────────────────────────

def _client():
    # Cheie valida -> bucket per-key (300/min), imun la test_rate_limit
    # care epuizeaza bucket-ul anonim (30/min/IP) in test_app_security.py.
    return app.test_client(), {'X-API-Key': 'test-key-123'}


def test_filename_non_string_400():
    """filename int/list -> 400, nu crash 500."""
    c, h = _client()
    r = c.post('/scan', json={'code': 'x = 1', 'filename': 123}, headers=h)
    assert r.status_code == 400
    assert 'filename' in r.get_json()['error'].lower()


def test_filename_oversized_400():
    """filename > 255 chars -> 400."""
    c, h = _client()
    r = c.post('/scan', json={'code': 'x = 1', 'filename': 'a' * 500}, headers=h)
    assert r.status_code == 400


def test_filename_valid_still_works():
    """filename string normal -> scan merge (regresie)."""
    c, h = _client()
    r = c.post('/scan', json={'code': 'x = 1', 'filename': 'test.py'}, headers=h)
    assert r.status_code == 200


# ─── Launch hardening (audit extern 18-Aug, punct 1) ────────────────

def test_hsts_header_present():
    """HSTS pe toate raspunsurile (anti-downgrade HTTPS)."""
    for path in ['/', '/app', '/health']:
        r = app.test_client().get(path)
        assert r.headers.get('Strict-Transport-Security', '').startswith('max-age=')


def test_health_does_not_leak_pattern_counts():
    """/health simplificat — fara patterns_secrets/patterns_code (info inutila)."""
    r = app.test_client().get('/health')
    body = r.get_json()
    assert body['status'] == 'ok'
    assert 'patterns_secrets' not in body
    assert 'patterns_code' not in body


def test_findings_capped_at_200():
    """Cod cu sute de probleme -> max 200 findings + flag truncated."""
    code = '\n'.join(f'API_KEY_{i} = "sk-abcdefghijklmnopqrstuvwxyz{i}"' for i in range(260))
    c, h = _client()
    r = c.post('/scan', json={'code': code}, headers=h)
    assert r.status_code == 200
    body = r.get_json()
    assert body['findings_truncated'] is True
    assert len(body['findings']) <= 200
    assert body['total'] <= 200
