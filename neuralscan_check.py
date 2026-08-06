"""
neuralscan_check.py — health check complet intr-o comanda.
Verifica: local :5050, Railway public, auth (401/200), git status.

Folosire:  python neuralscan_check.py
Exit code: 0 = totul OK, 1 = ceva e DOWN/EROARE.
"""
import json
import os
import subprocess
import sys
import urllib.request
import urllib.error

HERE = os.path.dirname(os.path.abspath(__file__))
WS = os.path.normpath(os.path.join(HERE, '..'))
SECRETS = os.path.join(WS, '.secrets.json')

LOCAL = 'http://localhost:5050'
PUBLIC = 'https://neuralscan-production.up.railway.app'

ok = True


def status(label, url, expect=200):
    global ok
    try:
        r = urllib.request.urlopen(url, timeout=10)
        code = r.status
    except urllib.error.HTTPError as e:
        code = e.code
    except Exception as e:
        code = f'ERR:{type(e).__name__}'
    good = (code == expect)
    ok = ok and good
    print(f'  [{"OK " if good else "BAD"}] {label:<28} {url} -> {code}')
    return code


def auth_probe():
    global ok
    key = ''
    try:
        with open(SECRETS, encoding='utf-8') as f:
            key = json.load(f).get('NEURALSCAN_API_KEYS', '')
    except Exception:
        pass

    def post(url, api_key=None):
        data = json.dumps({'code': 'x = 1'}).encode()
        headers = {'Content-Type': 'application/json'}
        if api_key is not None:
            headers['X-API-Key'] = api_key
        req = urllib.request.Request(url, data=data, method='POST', headers=headers)
        try:
            return urllib.request.urlopen(req, timeout=10).status
        except urllib.error.HTTPError as e:
            return e.code
        except Exception:
            return 0

    if key:
        bad = post(PUBLIC + '/scan', api_key='wrong-key')
        good = post(PUBLIC + '/scan', api_key=key)
        good_auth = (bad == 401 and good == 200)
        ok = ok and good_auth
        print(f'  [{"OK " if good_auth else "BAD"}] auth public (cheie gresita->{bad}, valida->{good})')
    else:
        print('  [ -- ] cheie NEURALSCAN_API_KEYS negasita — sar peste probe auth')


def git_state():
    try:
        r = subprocess.run(['git', 'status', '--porcelain'], cwd=HERE,
                           capture_output=True, text=True, timeout=10)
        n = len([l for l in r.stdout.splitlines() if l.strip()])
        print(f'  [INFO] git neuralscan: {n} fisier(e) nemodificat(e)/noi')
    except Exception as e:
        print(f'  [INFO] git: {e}')


print('=== NeuralScan health check ===')
print('[1] Serviciu local')
status('local /health', LOCAL + '/health')
print('[2] Serviciu public (Railway)')
status('public /health', PUBLIC + '/health')
print('[3] Auth public')
auth_probe()
print('[4] Git')
git_state()
print('=' * 40)
print('REZULTAT:', 'TOTUL OK' if ok else 'CEVA E DOWN — interventie necesara')
sys.exit(0 if ok else 1)
