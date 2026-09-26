"""
Teste de regresie pentru gaurile reparate 2026-09-26 (inventar scanner).
Fiecare test = un criteriu de acceptare scris INAINTE de fix.

Nota: valorile de test se construiesc prin concatenare, NU ca literali intregi,
ca sa nu fie prinse de filtrele de redactare a secretelor din tooling.
"""
import sys
import os
import io
import zipfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
from scanner import scan_code
import zipscan


def _stripe():
    return "sk" + "_" + "live" + "_" + "a" * 24


def _aws():
    return "AK" + "IA" + "Q" * 16


def _github():
    return "ghp" + "_" + "x" * 36


def _sendgrid():
    return "SG" + "." + "a" * 22 + "." + "b" * 22


def _slack():
    return "xoxb" + "-" + "0" * 12


def _google():
    return "GOCSPX" + "-" + "z" * 24


def _db_url():
    return "postgresql://user:" + "pw123456" + "@localhost:5432/db"


# ── C1: fisierele .env + variante sunt scanate; sabloanele nu ───────

def test_env_variants_are_scannable():
    for name in ['.env', '.env.local', '.env.production', '.env.development',
                 '.env.staging', 'config/.env', 'app/.env.local']:
        assert zipscan._is_scannable(name) is True, f"{name} ar trebui scanat"


def test_env_placeholders_are_not_scannable():
    for name in ['.env.example', '.env.sample', '.env.template']:
        assert zipscan._is_scannable(name) is False, f"{name} nu ar trebui scanat"


def test_env_local_secret_detected_in_zip():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w') as z:
        z.writestr('.env.local', 'STRIPE_KEY=' + _stripe() + '\n')
    r = zipscan.scan_zip(buf.getvalue(), 'proj.zip')
    types = [f['type'] for fb in r['findings_by_file'] for f in fb['findings']]
    assert r['files_scanned'] == 1, r['files_scanned']
    assert 'hardcoded_stripe_key' in types, f"types={types}"


# ── C2: node_modules nu mai blocheaza scanarea ──────────────────────

def test_zip_with_node_modules_still_scans():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w') as z:
        z.writestr('src/app.py', "import os\nos.system('ping ' + host)\n")
        z.writestr('.env', 'DB_PASSWORD="' + "pw123456" + '"\n')
        for i in range(400):
            z.writestr(f'node_modules/pkg{i}/index.js', 'module.exports = 1;\n')
    r = zipscan.scan_zip(buf.getvalue(), 'proiect.zip')  # NU trebuie sa arunce
    assert r['files_scanned'] == 2, r['files_scanned']
    assert r['total'] >= 2, r['total']


def test_zip_excludes_more_noise_dirs():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w') as z:
        z.writestr('main.py', 'x = 1\n')
        for d in ['dist', '.git', 'build', '__pycache__', '.venv', 'vendor']:
            z.writestr(f'{d}/junk.js', 'const a = "' + _stripe() + '";\n')
    r = zipscan.scan_zip(buf.getvalue(), 'p.zip')
    assert r['files_scanned'] == 1, r['files_scanned']
    assert r['total'] == 0, r['total']


def test_zip_still_rejects_many_real_code_files():
    """Exclude-urile nu trebuie sa slabeasca protectia anti-DoS."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w') as z:
        for i in range(301):
            z.writestr(f'src/f{i}.py', 'x = 1\n')
    try:
        zipscan.scan_zip(buf.getvalue(), 'big.zip')
        assert False, "ar trebui ValueError (prea multe fisiere de cod)"
    except ValueError as e:
        assert 'prea multe' in str(e)


def test_zip_slip_still_blocked():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w') as z:
        z.writestr('../evil.py', 'x = 1\n')
    try:
        zipscan.scan_zip(buf.getvalue(), 'evil.zip')
        assert False, "ar trebui ValueError (zip-slip)"
    except ValueError as e:
        assert 'zip-slip' in str(e)


# ── C3: tokenuri specifice etichetate corect ────────────────────────

def _types(code):
    return [f['type'] for f in scan_code(code, 't.py')]


def test_stripe_key_detected_and_labelled():
    assert 'hardcoded_stripe_key' in _types('k = "' + _stripe() + '"')


def test_sendgrid_key_detected():
    assert 'hardcoded_sendgrid_key' in _types('k = "' + _sendgrid() + '"')


def test_slack_token_detected():
    assert 'hardcoded_slack_token' in _types('t = "' + _slack() + '"')


def test_github_token_detected_and_not_mislabelled():
    types = _types('GITHUB_TOKEN = "' + _github() + '"')
    assert 'hardcoded_github_token' in types
    assert 'hardcoded_password' not in types, f"eticheta furata: {types}"


def test_google_oauth_secret_detected():
    assert 'hardcoded_google_secret' in _types('s = "' + _google() + '"')


def test_generic_password_still_detected():
    assert 'hardcoded_password' in _types('DB_PASSWORD = "' + "hunter2secret" + '"')


# ── C4: 2 secrete distincte pe aceeasi linie → 2 findings ───────────

def test_two_secrets_same_line_both_reported():
    code = 'A = "' + _aws() + '"; B = "' + _db_url() + '"'
    types = _types(code)
    assert 'hardcoded_aws_key' in types, types
    assert 'hardcoded_db_url' in types, types


# ── C5: shell=True + paranteze imbricate ────────────────────────────

def test_shell_true_detected():
    assert 'command_injection' in _types('subprocess.run(cmd, shell=True)')


def test_nested_parens_command_detected():
    types = _types('os.system(f"ping {get_host(x)}")')
    assert 'command_injection' in types


def test_safe_list_subprocess_not_flagged():
    types = _types('subprocess.run(["ping", host])')
    assert 'command_injection' not in types


# ── C6: sortare pe rang de severitate ───────────────────────────────

RANK = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}


def test_severity_sorted_by_rank_within_line():
    """critical inaintea lui medium pe aceeasi linie (alfabetic era gresit)."""
    code = 'app.run(debug=True); hashlib.md5(b"a")'
    res = scan_code(code, 't.py')
    sevs = [f['severity'] for f in res if f['line'] == 1]
    assert len(sevs) >= 2, sevs
    assert sevs == sorted(sevs, key=lambda s: RANK[s]), sevs
