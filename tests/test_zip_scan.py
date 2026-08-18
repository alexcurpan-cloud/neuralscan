"""
NS-FLOW tests — ZIP/repo scan (18-Aug).
Criterii: C1 findings per fisier + agregat, C2 zip-slip 400, C3 non-zip/limite 400,
C4 frontend upload, C5 regresie + deploy live.
"""
import io
import os
import sys
import zipfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.app import app
import src.zipscan as zipscan


def _make_zip(files: dict, names=None) -> bytes:
    """files: {nume: continut}."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zf:
        for name, content in files.items():
            zf.writestr(name, content)
    return buf.getvalue()


def _client():
    return app.test_client(), {'X-API-Key': os.environ.get('NEURALSCAN_API_KEYS', 'test-key-123').split(',')[0]}


# ─── C1: findings per fisier + agregat ──────────────────────────────

def test_zip_with_vulnerable_files():
    zip_data = _make_zip({
        'app.py': 'API_KEY = "sk-proj-1234567890abcdefghij"\n',
        'db.py': 'cursor.execute(f"SELECT * FROM users WHERE name = {name}")\n',
        'utils.py': 'def greet(name):\n    return f"Hello {name}"\n',
    })
    c, h = _client()
    r = c.post('/scan/zip', data={'file': (io.BytesIO(zip_data), 'repo.zip')},
               headers=h, content_type='multipart/form-data')
    assert r.status_code == 200, r.get_json()
    body = r.get_json()
    assert body['files_scanned'] == 3
    assert body['files_with_findings'] == 2
    assert body['total'] >= 2
    by_file = {f['file']: f for f in body['findings_by_file']}
    assert 'app.py' in by_file and by_file['app.py']['count'] >= 1
    assert 'db.py' in by_file and by_file['db.py']['count'] >= 1
    assert 'utils.py' in by_file and by_file['utils.py']['count'] == 0
    assert body['summary']['critical'] >= 1  # API key = critical


def test_zipscan_clean_zip():
    zip_data = _make_zip({'main.py': 'print("hello")\n'})
    res = zipscan.scan_zip(zip_data)
    assert res['total'] == 0
    assert res['files_scanned'] == 1


# ─── C2: zip-slip ───────────────────────────────────────────────────

def test_zip_slip_rejected():
    zip_data = _make_zip({'../evil.py': 'os.system("rm -rf /")\n'})
    c, h = _client()
    r = c.post('/scan/zip', data={'file': (io.BytesIO(zip_data), 'evil.zip')},
               headers=h, content_type='multipart/form-data')
    assert r.status_code == 400
    assert 'zip-slip' in r.get_json()['error'].lower()


def test_zip_absolute_path_rejected():
    zip_data = _make_zip({'/etc/passwd': 'root:x:0:0\n'})
    c, h = _client()
    r = c.post('/scan/zip', data={'file': (io.BytesIO(zip_data), 'abs.zip')},
               headers=h, content_type='multipart/form-data')
    assert r.status_code == 400


# ─── C3: non-zip / limite ───────────────────────────────────────────

def test_non_zip_rejected():
    c, h = _client()
    r = c.post('/scan/zip', data={'file': (io.BytesIO(b'not a zip'), 'x.zip')},
               headers=h, content_type='multipart/form-data')
    assert r.status_code == 400
    assert 'zip' in r.get_json()['error'].lower()


def test_missing_file_field():
    c, h = _client()
    r = c.post('/scan/zip', headers=h)
    assert r.status_code == 400


def test_zip_too_many_files():
    files = {f'f{i}.py': 'x = 1\n' for i in range(400)}
    zip_data = _make_zip(files)
    c, h = _client()
    r = c.post('/scan/zip', data={'file': (io.BytesIO(zip_data), 'big.zip')},
               headers=h, content_type='multipart/form-data')
    assert r.status_code == 400


def test_zip_slip_detected_in_module():
    import pytest
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w') as zf:
        zf.writestr('safe.py', 'x = 1')
        zf.writestr('../../escape.py', 'y = 2')
    with pytest.raises(ValueError):
        zipscan.scan_zip(buf.getvalue())


# ─── Extra: auth pe /scan/zip ───────────────────────────────────────

def test_zip_invalid_key_401():
    zip_data = _make_zip({'a.py': 'x = 1\n'})
    c = app.test_client()
    r = c.post('/scan/zip', data={'file': (io.BytesIO(zip_data), 'a.zip')},
               headers={'X-API-Key': '***'},
               content_type='multipart/form-data')
    assert r.status_code == 401
