"""
security-scanner/app.py
Flask API + Frontend — TASK 1+3+4 integration.

Endpoints:
  POST /scan     — scaneaza cod JSON { code: "..." }
  GET  /         — serveste frontend-ul (textarea + cards)
  GET  /health   — health check
"""

import os
import sys
import json
import time
import traceback
import hmac
import hashlib
from pathlib import Path

from flask import Flask, request, jsonify, render_template_string
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.middleware.proxy_fix import ProxyFix

# Add parent to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from scanner import scan_code
from translator import translate_findings
import audit
import keys
import zipscan

audit.init_db()
keys.init_db()

app = Flask(__name__)

# Railway (si majoritatea PaaS) termina TLS si pune IP-ul real in X-Forwarded-For.
# Fara ProxyFix, request.remote_addr = IP-ul proxy-ului -> TOTI anonimii impart UN bucket
# de rate limit (30/min) si ip_hash din audit e identic pentru toata lumea.
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)

# ─── Securitate: limite de bază (Strat 0) ───────────────────────────
# Anti-DoS: request max 6MB (ZIP upload pana la 5MB); /scan JSON pastreaza capul
# de 100KB la nivel de cod (len(code) > 100_000 -> 413).
app.config['MAX_CONTENT_LENGTH'] = 6 * 1024 * 1024

# ─── Auth: API keys (Strat 1 + Strat 2) ───────────────────────────
# Strat 2: chei in DB (hash, revocabile, per-user) — lookup inainte de legacy env.
# Legacy: chei din env NEURALSCAN_API_KEYS (comma-separated) — merg in continuare (seed).
API_KEYS = {k.strip() for k in os.environ.get('NEURALSCAN_API_KEYS', '').split(',') if k.strip()}

# Limite de raspuns (anti-abuz): findings max per scan / per fisier ZIP
MAX_FINDINGS_PER_SCAN = 200
MAX_FINDINGS_PER_FILE = 100
MAX_FINDINGS_TOTAL_ZIP = 500

# Cheie admin pt /stats + /admin/* (separata de cheile de tester — privilege minim).
ADMIN_KEY = os.environ.get('NEURALSCAN_ADMIN_KEY', '').strip()


def _is_admin() -> bool:
    """Verifica X-Admin-Key cu comparatie constant-time (hmac.compare_digest)."""
    if not ADMIN_KEY:
        return False
    sent = (request.headers.get('X-Admin-Key', '') or '').encode('utf-8')
    return hmac.compare_digest(sent, ADMIN_KEY.encode('utf-8'))


def _request_key() -> str:
    """Cheia trimisă de client (header X-API-Key), sau ''."""
    return (request.headers.get('X-API-Key') or '').strip()


def _db_key_info():
    """Info DB (hash lookup, nerevocata) pt cheia curenta, sau None."""
    k = _request_key()
    if not k:
        return None
    return keys.lookup_by_key(k)


def _has_valid_key() -> bool:
    """Cheie valida = in DB (nerevocata) SAU legacy env."""
    return _db_key_info() is not None or _request_key() in API_KEYS


def _current_key_id() -> str:
    """ID scurt pt audit/log: user:<email> key:<prefix> / key:<prefix> / anon."""
    info = _db_key_info()
    if info:
        return f"user:{info['email']} key:{info['key_prefix']}"
    key = _request_key()
    return f'key:{key[:8]}' if key in API_KEYS else 'anon'


def _auth_bucket():
    """Bucket de rate limit: cheie DB -> per key_id; orice alta cheie prezentata (legacy/invalida)
    -> bucket propriu (ca revocata/gresita sa primeasca 401, nu 429 pe bucket IP); altfel -> per IP."""
    info = _db_key_info()
    if info:
        return f'key:{info["key_id"]}'
    key = _request_key()
    if key:
        return f'key:{hashlib.sha256(key.encode()).hexdigest()[:16]}'
    return f'ip:{get_remote_address()}'


def _rate_limit_str() -> str:
    """Limita per cheie din DB (free/pro), legacy env 300, anon 30."""
    info = _db_key_info()
    if info:
        return f"{info['rate_limit']} per minute"
    if _request_key() in API_KEYS:
        return "300 per minute"
    return "30 per minute"


# Anti-abuz: /scan → 300 req/min per key (auth), 30 req/min per IP (anon)
limiter = Limiter(
    get_remote_address,
    app=app,
    storage_uri="memory://",
)


@app.errorhandler(413)
def too_large(e):
    return jsonify({"error": "Request too large — maximum 6MB (sau 100KB pt /scan JSON)."}), 413


@app.errorhandler(429)
def rate_limited(e):
    return jsonify({"error": "Rate limit exceeded — please slow down and try again in a minute."}), 429


@app.errorhandler(401)
def unauthorized(e):
    return jsonify({"error": "Invalid API key. Pass X-API-Key header."}), 401


@app.after_request
def security_headers(resp):
    """Headere de securitate pe toate răspunsurile."""
    resp.headers.setdefault('X-Content-Type-Options', 'nosniff')
    resp.headers.setdefault('X-Frame-Options', 'DENY')
    resp.headers.setdefault('Referrer-Policy', 'no-referrer')
    resp.headers.setdefault('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')
    resp.headers.setdefault('Content-Security-Policy',
        "default-src 'self'; style-src 'self' 'unsafe-inline'; "
        "script-src 'self' 'unsafe-inline'; img-src 'self' data:")
    return resp

# ─── API: POST /scan ────────────────────────────────────────────────

@app.route('/scan', methods=['POST'])
@limiter.limit(lambda: _rate_limit_str(), key_func=_auth_bucket)
def scan():
    """
    Primeste cod, il scrie in fisier temp, ruleaza scanare, returneaza JSON.
    Body: { "code": "...", "filename": "optional.py" }
    Auth: X-API-Key optional — cu cheie valida → rate limit generos; fara → per IP.
    """
    data = request.get_json(silent=True)
    if not data or 'code' not in data:
        return jsonify({
            "error": "Trimite JSON cu campul 'code'.",
            "exemplu": '{ "code": "print(1)", "filename": "test.py" }'
        }), 400

    # Auth: header prezent dar cheie invalida → 401 (fara header = anon, merge)
    if _request_key() and not _has_valid_key():
        return jsonify({"error": "Invalid API key. Pass X-API-Key header."}), 401

    # Anti-abuz: cap zilnic per cheie (reset la miezul noptii UTC). Anonimii raman
    # limitati doar de rate limit per IP (30/min) — nu au cheie de abuzat.
    key_label = _current_key_id()
    if key_label != 'anon':
        _kinfo = _db_key_info()
        _plan = _kinfo['plan'] if _kinfo else 'free'
        _limit = keys.daily_limit_for(_plan)
        _used = keys.daily_scans_used(key_label)
        if _used >= _limit:
            return jsonify({
                "error": f"Daily scan limit reached ({_used}/{_limit} today). "
                          "Resets at midnight UTC.",
                "daily_limit": _limit,
                "daily_used": _used,
            }), 429

    code = data['code']
    filename = data.get('filename', 'input.py')

    if not isinstance(code, str):
        return jsonify({"error": "Campul 'code' trebuie sa fie string."}), 400

    # FIX securitate: filename non-string / urias -> 400 (nu crash -> 500).
    # (scanner.py il foloseste in _is_batch_eval_context: filename.lower())
    if not isinstance(filename, str) or len(filename) > 255:
        return jsonify({"error": "Campul 'filename' trebuie sa fie string (max 255 chars)."}), 400

    if len(code) > 100_000:
        return jsonify({"error": "Code too large — maximum 100KB."}), 413

    if not code.strip():
        return jsonify({"findings": [], "total": 0, "summary": {}}), 200

    # Audit minimal: cine scanează (key_id scurt / anon) + dimensiune
    app.logger.info("scan: %s size=%d", _current_key_id(), len(code))

    start_ms = time.time()

    try:
        # Ruleaza scannerul IN MEMORIE — fara fisier temp (codul nu se scrie pe disk)
        findings = scan_code(code, filename)

        # Anti-abuz: limiteaza findings in raspuns (fara pagini de 100KB+)
        truncated = len(findings) > MAX_FINDINGS_PER_SCAN
        if truncated:
            findings = findings[:MAX_FINDINGS_PER_SCAN]

        # Tradu in raport non-dev
        reports = translate_findings(findings, code)

        result = {
            "status": "ok",
            "file": filename,
            "total": len(findings),
            "findings_truncated": truncated,
            "summary": {
                "critical": sum(1 for f in findings if f["severity"] == "critical"),
                "high": sum(1 for f in findings if f["severity"] == "high"),
                "medium": sum(1 for f in findings if f["severity"] == "medium"),
                "low": sum(1 for f in findings if f["severity"] == "low"),
            },
            "findings": findings,        # raw
            "report": reports,           # tradus
        }
        audit.log_scan(_current_key_id(), request.remote_addr, len(code),
                       result["summary"], int((time.time() - start_ms) * 1000), 'ok',
                       owner_id=keys.owner_id_for_key(_request_key()))
        return jsonify(result)

    except Exception as e:
        # Log intern complet, fara sa scurgem detalii catre client
        app.logger.error("Scan failed: %s\n%s", e, traceback.format_exc())
        audit.log_scan(_current_key_id(), request.remote_addr, len(code),
                       {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0},
                       int((time.time() - start_ms) * 1000), 'error',
                       owner_id=keys.owner_id_for_key(_request_key()))
        return jsonify({
            "status": "error",
            "error": "Internal scan error. Please try again with a smaller code sample."
        }), 500


# ─── Scan ZIP / repo (NS-FLOW) ──────────────────────────────────────

@app.route('/scan/zip', methods=['POST'])
@limiter.limit(lambda: _rate_limit_str(), key_func=_auth_bucket)
def scan_zip_route():
    """Primeste ZIP (multipart, campul 'file') si scaneaza recursiv fisierele de cod.
    Zip-slip protection + limite de dimensiune in zipscan.py."""
    if _request_key() and not _has_valid_key():
        return jsonify({"error": "Invalid API key. Pass X-API-Key header."}), 401
    if 'file' not in request.files:
        return jsonify({"error": "Trimite fisierul ZIP in campul 'file'."}), 400
    f = request.files['file']
    data = f.read()
    if not data:
        return jsonify({"error": "Fisier gol."}), 400

    start_ms = time.time()
    try:
        result = zipscan.scan_zip(data, f.filename or 'repo.zip')
        audit.log_scan(_current_key_id(), request.remote_addr, len(data),
                       result["summary"], int((time.time() - start_ms) * 1000), 'ok',
                       owner_id=keys.owner_id_for_key(_request_key()))
        return jsonify(result)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        app.logger.error("zip scan failed: %s", e)
        audit.log_scan(_current_key_id(), request.remote_addr, len(data),
                       {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0},
                       int((time.time() - start_ms) * 1000), 'error',
                       owner_id=keys.owner_id_for_key(_request_key()))
        return jsonify({"error": "Internal scan error."}), 500


# ─── Stats (admin only) ──────────────────────────────────────────────

@app.route('/stats', methods=['GET'])
@limiter.limit("10 per minute")
def stats():
    """Statistici agregate de folosire. Doar cu cheie admin (X-Admin-Key).
    Returneaza metadate (numar scan-uri, pe zi, pe cheie) — NICIODATA cod scanat,
    nici IP real (doar hash)."""
    if not _is_admin():
        return jsonify({"error": "Invalid admin key. Pass X-Admin-Key header."}), 401
    days = request.args.get('days', 14, type=int)
    days = max(1, min(days, 90))
    return jsonify(audit.get_stats(days=days))


# ─── Scans per user (owner-scoping, Strat 2) ────────────────────────

@app.route('/user/scans', methods=['GET'])
@limiter.limit("60 per minute")
def user_scans():
    """Scan-urile DOAR ale userului curent (identificat prin X-API-Key din DB).
    Fara cheie DB valida -> 401. Fara cod, fara IP real."""
    info = _db_key_info()
    if not info:
        return jsonify({"error": "Valid X-API-Key (DB) required for this endpoint."}), 401
    limit = request.args.get('limit', 20, type=int)
    limit = max(1, min(limit, 100))
    return jsonify({
        "user": info["email"],
        "plan": info["plan"],
        "scans": audit.get_user_scans(info["user_id"], limit),
    })


# ─── Admin: key management (NS-PG fix — creare chei in prod via HTTP) ──
# De ce: `railway run` nu tunelizeaza postgres.railway.internal pe CLI-ul curent,
# deci keymgmt-ul local nu poate crea chei in Postgres-ul de productie.
# Aceste endpoint-uri ruleaza IN INTERIOR (URL intern OK) si folosesc X-Admin-Key
# (aceeasi cheie ca /stats — privilege minim, separata de cheile de tester).

@app.route('/admin/keys', methods=['POST'])
@limiter.limit("10 per minute")
def admin_create_key():
    """Creeaza o cheie API pt un user. Body: { "email": "...", "plan": "free|pro" }.
    Returneaza plaintext-ul O SINGURA DATA — nu se mai poate recupera."""
    if not _is_admin():
        return jsonify({"error": "Invalid admin key. Pass X-Admin-Key header."}), 401
    data = request.get_json(silent=True) or {}
    email = (data.get('email') or '').strip()
    plan = (data.get('plan') or 'free').strip()
    if not email or '@' not in email or len(email) > 254:
        return jsonify({"error": "Campul 'email' trebuie sa fie o adresa valida."}), 400
    if plan not in keys.PLAN_RATE_LIMITS:
        return jsonify({"error": f"Plan necunoscut: {plan} (alege din {list(keys.PLAN_RATE_LIMITS)})."}), 400
    try:
        info = keys.create_key(email, plan)
    except Exception as e:
        app.logger.error("admin create key failed: %s", e)
        return jsonify({"error": "Internal error creating key."}), 500
    app.logger.info("admin: key created for %s (plan=%s, prefix=%s)", email, plan, info['key_prefix'])
    return jsonify({
        "key": info['key'],
        "key_prefix": info['key_prefix'],
        "email": info['email'],
        "plan": info['plan'],
        "rate_limit": info['rate_limit'],
        "warning": "Aceasta este singura data cand cheia apare in clar.",
    }), 201


@app.route('/admin/keys/revoke', methods=['POST'])
@limiter.limit("10 per minute")
def admin_revoke_key():
    """Revoca o cheie dupa key_prefix. Body: { "key_prefix": "ns_abc..." }.
    Revocata = 401 imediat, fara redeploy."""
    if not _is_admin():
        return jsonify({"error": "Invalid admin key. Pass X-Admin-Key header."}), 401
    data = request.get_json(silent=True) or {}
    prefix = (data.get('key_prefix') or '').strip()
    if not prefix:
        return jsonify({"error": "Campul 'key_prefix' este obligatoriu."}), 400
    ok = keys.revoke_key(prefix)
    if not ok:
        return jsonify({"error": f"Nicio cheie activa cu prefixul '{prefix}'."}), 404
    app.logger.info("admin: key revoked prefix=%s", prefix)
    return jsonify({"ok": True, "key_prefix": prefix, "revoked": True}), 200


@app.route('/admin/keys', methods=['GET'])
@limiter.limit("10 per minute")
def admin_list_keys():
    """Listeaza cheile (doar prefix + stare + owner — NICIODATA hash/plaintext)."""
    if not _is_admin():
        return jsonify({"error": "Invalid admin key. Pass X-Admin-Key header."}), 401
    return jsonify({"keys": keys.list_keys()}), 200


# ─── Health ─────────────────────────────────────────────────────────

@app.route('/health', methods=['GET'])
def health():
    return jsonify({
        "status": "ok",
        "service": "security-scanner",
        "version": "1.0.0",
    })


# ─── Frontend (TASK 3) ─────────────────────────────────────────────

INDEX_HTML = r"""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>🔍 NeuralScan — Security Scanner</title>
<style>
  :root {
    --bg: #0d1117;
    --card: #161b22;
    --border: #30363d;
    --text: #e6edf3;
    --muted: #8b949e;
    --critical: #f85149;
    --high: #d29922;
    --medium: #58a6ff;
    --low: #3fb950;
    --accent: #2f81f7;
    --radius: 8px;
  }
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    background: var(--bg);
    color: var(--text);
    min-height: 100vh;
    padding: 24px;
  }
  .container { max-width: 900px; margin: 0 auto; }
  h1 {
    font-size: 1.8rem;
    margin-bottom: 4px;
    display: flex;
    align-items: center;
    gap: 10px;
  }
  .subtitle {
    color: var(--muted);
    font-size: 0.9rem;
    margin-bottom: 24px;
  }
  textarea {
    width: 100%;
    min-height: 260px;
    background: #010409;
    color: var(--text);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 14px;
    font-family: 'Cascadia Code', 'Fira Code', 'JetBrains Mono', monospace;
    font-size: 13px;
    line-height: 1.6;
    resize: vertical;
    outline: none;
    transition: border-color 0.2s;
  }
  textarea:focus { border-color: var(--accent); }
  .toolbar {
    display: flex;
    gap: 10px;
    margin: 12px 0 20px;
    align-items: center;
  }
  .btn {
    padding: 10px 24px;
    border: none;
    border-radius: var(--radius);
    font-size: 0.95rem;
    font-weight: 600;
    cursor: pointer;
    transition: opacity 0.2s, transform 0.1s;
    display: inline-flex;
    align-items: center;
    gap: 6px;
  }
  .btn:active { transform: scale(0.97); }
  .btn-primary { background: var(--accent); color: #fff; }
  .btn-primary:hover { opacity: 0.9; }
  .btn-primary:disabled { opacity: 0.4; cursor: not-allowed; }
  .btn-outline {
    background: transparent;
    color: var(--muted);
    border: 1px solid var(--border);
  }
  .btn-outline:hover { border-color: var(--text); color: var(--text); }

  /* Stats bar */
  .stats {
    display: flex;
    gap: 12px;
    margin-bottom: 20px;
    flex-wrap: wrap;
  }
  .stat {
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 10px 18px;
    font-size: 0.85rem;
    display: flex;
    align-items: center;
    gap: 6px;
  }
  .stat .num { font-weight: 700; font-size: 1.1rem; }

  /* Card */
  .card {
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 18px 20px;
    margin-bottom: 14px;
    border-left: 4px solid var(--muted);
  }
  .card.critical { border-left-color: var(--critical); }
  .card.high { border-left-color: var(--high); }
  .card.medium { border-left-color: var(--medium); }
  .card.low { border-left-color: var(--low); }

  .card-header {
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    gap: 10px;
    margin-bottom: 8px;
  }
  .card-title {
    font-size: 1rem;
    font-weight: 600;
    line-height: 1.3;
  }
  .badge {
    display: inline-block;
    padding: 2px 10px;
    border-radius: 20px;
    font-size: 0.72rem;
    font-weight: 700;
    text-transform: uppercase;
    white-space: nowrap;
  }
  .badge.critical { background: rgba(248,81,73,0.15); color: var(--critical); }
  .badge.high { background: rgba(210,153,34,0.15); color: var(--high); }
  .badge.medium { background: rgba(88,166,255,0.15); color: var(--medium); }
  .badge.low { background: rgba(63,185,80,0.15); color: var(--low); }

  .card-body { font-size: 0.9rem; line-height: 1.6; }
  .card-body p { margin-bottom: 8px; }
  .card-meta { color: var(--muted); font-size: 0.8rem; margin-bottom: 8px; }

  .snippet {
    background: #010409;
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 10px 12px;
    margin: 8px 0 12px;
    font-family: monospace;
    font-size: 0.8rem;
    line-height: 1.5;
    overflow-x: auto;
    white-space: pre;
  }
  .snippet .hl { background: rgba(248,81,73,0.2); }

  .btn-fix {
    background: var(--accent);
    color: #fff;
    border: none;
    border-radius: 4px;
    padding: 6px 14px;
    font-size: 0.8rem;
    font-weight: 600;
    cursor: pointer;
    transition: opacity 0.2s;
  }
  .btn-fix:hover { opacity: 0.85; }

  /* Toast */
  .toast {
    position: fixed;
    bottom: 24px;
    right: 24px;
    background: #238636;
    color: #fff;
    padding: 12px 20px;
    border-radius: var(--radius);
    font-size: 0.85rem;
    opacity: 0;
    transform: translateY(10px);
    transition: opacity 0.3s, transform 0.3s;
    pointer-events: none;
  }
  .toast.show { opacity: 1; transform: translateY(0); }

  .loading {
    text-align: center;
    padding: 40px;
    color: var(--muted);
  }
  .spinner {
    display: inline-block;
    width: 24px;
    height: 24px;
    border: 3px solid var(--border);
    border-top-color: var(--accent);
    border-radius: 50%;
    animation: spin 0.8s linear infinite;
    margin-right: 8px;
    vertical-align: middle;
  }
  @keyframes spin { to { transform: rotate(360deg); } }

  .empty {
    text-align: center;
    padding: 40px 20px;
    color: var(--muted);
    border: 2px dashed var(--border);
    border-radius: var(--radius);
  }
  .empty svg { width: 48px; height: 48px; margin-bottom: 12px; opacity: 0.4; }

  @media (max-width: 600px) {
    body { padding: 12px; }
    .card-header { flex-direction: column; }
    .toolbar { flex-wrap: wrap; }
  }
</style>
</head>
<body>
<div class="container">
  <h1>🔍 NeuralScan</h1>
  <div class="subtitle">Security scanner with plain-language reports</div>

  <textarea id="codeInput" placeholder="Paste your code here to scan...&#10;&#10;Exemplu:&#10;API_KEY = 'sk-proj-1234567890abcdef1234567890abcdef'&#10;&#10;def get_user(name):&#10;    cursor.execute(f'SELECT * FROM users WHERE name = {name}')" spellcheck="false"></textarea>

  <div class="toolbar">
    <button class="btn btn-primary" id="scanBtn" onclick="scan()">Check</button>
    <button class="btn btn-outline" onclick="document.getElementById('zipInput').click()">📦 Scan ZIP</button>
    <input type="file" id="zipInput" accept=".zip" style="display:none" onchange="scanZip(event)">
    <button class="btn btn-outline" onclick="clearAll()">✕ Clear</button>
    <button class="btn btn-outline" onclick="loadExample()">Example</button>
    <span id="statusText" style="color:var(--muted);font-size:0.85rem;margin-left:auto;"></span>
  </div>

  <div id="stats"></div>
  <div id="results"></div>
</div>

<div class="toast" id="toast"></div>

<script>
const scanBtn = document.getElementById('scanBtn');
const codeInput = document.getElementById('codeInput');
const resultsDiv = document.getElementById('results');
const statsDiv = document.getElementById('stats');
const statusText = document.getElementById('statusText');
const toast = document.getElementById('toast');

function showToast(msg) {
  toast.textContent = msg;
  toast.classList.add('show');
  setTimeout(() => toast.classList.remove('show'), 2500);
}

function escapeHtml(s) {
  return String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}

function clearAll() {
  codeInput.value = '';
  resultsDiv.innerHTML = '';
  statsDiv.innerHTML = '';
  statusText.textContent = '';
}

function loadExample() {
  codeInput.value = `import os
import sqlite3

# Hardcoded API key
OPENAI_API_KEY = "sk-proj-1234567890abcdef1234567890abcdef"

# Debug left on
app.run(debug=True, host="0.0.0.0")

# SQL injection
def get_user(name):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE name = '{name}'")
    return cursor.fetchall()

# Command injection
def ping(host):
    os.system("ping " + host)

# Weak crypto
import hashlib
h = hashlib.md5(b"test")

# HTTP instead of HTTPS
url = "http://api.example.com/data"`;
  codeInput.dispatchEvent(new Event('input'));
}

const severityColors = {
  critical: { bg: 'rgba(248,81,73,0.12)', text: '#f85149', border: '#f85149' },
  high: { bg: 'rgba(210,153,34,0.12)', text: '#d29922', border: '#d29922' },
  medium: { bg: 'rgba(88,166,255,0.12)', text: '#58a6ff', border: '#58a6ff' },
  low: { bg: 'rgba(63,185,80,0.12)', text: '#3fb950', border: '#3fb950' },
};

async function scan() {
  const code = codeInput.value.trim();
  if (!code) {
    showToast('Paste some code first');
    return;
  }

  scanBtn.disabled = true;
  scanBtn.textContent = '⏳ Scanning...';
  statusText.textContent = 'Scanning...';

  try {
    const res = await fetch('/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ code, filename: 'input.py' }),
    });
    const data = await res.json();

    if (!res.ok) {
      resultsDiv.innerHTML = `<div class="empty">❌ Error: ${escapeHtml(data.error) || 'unknown'}</div>`;
      statusText.textContent = 'Error';
      return;
    }

    renderResults(data);
  } catch (err) {
    resultsDiv.innerHTML = `<div class="empty">❌ Network error: ${err.message}</div>`;
    statusText.textContent = 'Error';
  } finally {
    scanBtn.disabled = false;
    scanBtn.textContent = 'Check';
  }
}

function renderResults(data) {
  const { total, summary = {}, report = [], findings = [] } = data;

  // Stats
  let statsHtml = '';
  if (total > 0) {
    const cats = [
      { key: 'critical', label: 'Critical', color: '#f85149' },
      { key: 'high', label: 'High', color: '#d29922' },
      { key: 'medium', label: 'Medium', color: '#58a6ff' },
      { key: 'low', label: 'Low', color: '#3fb950' },
    ];
    statsHtml = '<div class="stats">';
    cats.forEach(c => {
      if (summary[c.key] > 0) {
        statsHtml += `<div class="stat"><span class="num" style="color:${c.color}">${summary[c.key]}</span> ${c.label}</div>`;
      }
    });
    statsHtml += `<div class="stat" style="color:var(--muted)">Total: <strong>${total}</strong></div>`;
    statsHtml += '</div>';
  }
  statsDiv.innerHTML = statsHtml;

  // Results
  let html = '';
  if (total === 0) {
    html = `<div class="empty">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>
      <div>No issues detected. Looks clean! 🎉</div>
    </div>`;
    resultsDiv.innerHTML = html;
    statusText.textContent = '✅ Nothing found';
    return;
  }

  report.forEach((r, idx) => {
    const sev = r.severity_raw || 'medium';
    const cls = sev;
    const colors = severityColors[sev] || severityColors.medium;

    let snippetHtml = '';
    if (r.snippet) {
      snippetHtml = `<div class="snippet">${escapeHtml(r.snippet)}</div>`;
    }

    html += `<div class="card ${cls}">
      <div class="card-header">
        <div class="card-title">${escapeHtml(r.titlu)}</div>
        <span class="badge ${cls}">${escapeHtml(r.severity)}</span>
      </div>
      <div class="card-body">
        <div class="card-meta">Line ${r.line}${r.match_redactat ? ' · Match: ' + escapeHtml(r.match_redactat) : ''}</div>
        <p>${escapeHtml(r.explicatie)}</p>
        ${snippetHtml}
        <button class="btn-fix" onclick="copyFix(${idx})">📋 Copy fix prompt</button>
        <span id="copied_${idx}" style="color:var(--low);font-size:0.8rem;margin-left:8px;display:none;">Copied! ✓</span>
      </div>
    </div>`;
  });

  resultsDiv.innerHTML = html;
  statusText.textContent = `✅ ${total} issue(s) found in ${(performance.now() * 0.001).toFixed(1)}s`;
}

function copyFix(idx) {
  // Get the fix prompt text from the reports array in the DOM
  const cards = document.querySelectorAll('.card');
  if (idx >= cards.length) return;
  const card = cards[idx];
  const fixBtn = card.querySelector('.btn-fix');
  const copiedSpan = card.querySelector('[id^="copied_"]');

  // Find the explanation paragraph and build the fix text
  const paragraphs = card.querySelectorAll('.card-body p');
  const explanation = paragraphs.length > 0 ? paragraphs[0].textContent : '';
  const title = card.querySelector('.card-title').textContent;

  const fixText = `**Problem:** ${title}\n\n${explanation}\n\n**Fix request:**\n`;

  navigator.clipboard.writeText(fixText).then(() => {
    if (copiedSpan) copiedSpan.style.display = 'inline';
    setTimeout(() => { if (copiedSpan) copiedSpan.style.display = 'none'; }, 2000);
    showToast('📋 Prompt copied!');
  }).catch(() => {
    // Fallback: try selecting from hidden textarea
    const ta = document.createElement('textarea');
    ta.value = fixText;
    document.body.appendChild(ta);
    ta.select();
    document.execCommand('copy');
    document.body.removeChild(ta);
    if (copiedSpan) copiedSpan.style.display = 'inline';
    setTimeout(() => { if (copiedSpan) copiedSpan.style.display = 'none'; }, 2000);
    showToast('📋 Prompt copied!');
  });
}

// ─── ZIP upload scan (NS-FLOW) ─────────────────────────────────────
async function scanZip(event) {
  const file = event.target.files[0];
  if (!file) return;
  const scanBtn = document.getElementById('scanBtn');
  scanBtn.disabled = true;
  statusText.textContent = 'Scanning ZIP: ' + file.name + '...';
  try {
    const fd = new FormData();
    fd.append('file', file);
    const res = await fetch('/scan/zip', { method: 'POST', body: fd });
    const data = await res.json();
    if (!res.ok) {
      resultsDiv.innerHTML = `<div class="empty">❌ Error: ${escapeHtml(data.error) || 'unknown'}</div>`;
      statusText.textContent = 'Error';
      return;
    }
    renderZipResults(data);
  } catch (err) {
    resultsDiv.innerHTML = `<div class="empty">❌ Network error: ${err.message}</div>`;
    statusText.textContent = 'Error';
  } finally {
    scanBtn.disabled = false;
    event.target.value = '';
  }
}

function renderZipResults(data) {
  const { files_scanned, files_with_findings, total, summary = {}, findings_by_file = [] } = data;

  let statsHtml = '<div class="stats">';
  statsHtml += `<div class="stat">Files: <strong>${files_scanned}</strong></div>`;
  statsHtml += `<div class="stat">With issues: <strong>${files_with_findings}</strong></div>`;
  statsHtml += `<div class="stat">Total issues: <strong>${total}</strong></div>`;
  if (summary.critical) statsHtml += `<div class="stat">🔴 Critical: <strong>${summary.critical}</strong></div>`;
  if (summary.high) statsHtml += `<div class="stat">🟠 High: <strong>${summary.high}</strong></div>`;
  statsHtml += '</div>';
  statsDiv.innerHTML = statsHtml;

  let html = '';
  if (total === 0) {
    html = `<div class="empty">✅ No issues detected across ${files_scanned} file(s). Looks clean!</div>`;
  } else {
    findings_by_file.forEach((fb, fi) => {
      if (fb.count === 0) return;
      const sev = fb.findings[0]?.severity || 'medium';
      const sevLabel = fb.findings[0]?.severity || '';
      html += `<div class="card ${sev}">
        <div class="card-header">
          <div class="card-title">📄 ${escapeHtml(fb.file)}</div>
          <span class="badge ${sev}">${fb.count} issue(s)</span>
        </div>
        <div class="card-body">`;
      fb.report.forEach((r, ri) => {
        html += `<p style="margin-bottom:4px;"><span class="badge ${r.severity_raw}">${escapeHtml(r.severity)}</span> ${escapeHtml(r.titlu)} <span class="card-meta">line ${r.line}</span></p>`;
      });
      html += `</div></div>`;
    });
  }
  resultsDiv.innerHTML = html;
  statusText.textContent = `✅ ${files_with_findings}/${files_scanned} file(s) with issues — ${total} total`;
}

// Auto-height textarea
codeInput.addEventListener('input', function() {
  this.style.height = 'auto';
  this.style.height = Math.min(this.scrollHeight, 500) + 'px';
});
</script>
</body>
</html>
"""


@app.route('/', methods=['GET'])
def index():
    """Landing page EN (marketing) — /app ramane scanner-ul."""
    landing = Path(__file__).with_name('landing.html')
    if landing.exists():
        return landing.read_text(encoding='utf-8')
    return render_template_string(INDEX_HTML)


@app.route('/app', methods=['GET'])
def scanner_ui():
    return render_template_string(INDEX_HTML)


# ─── Run ────────────────────────────────────────────────────────────

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5050))
    print(f"[OK] NeuralScan pornit pe http://localhost:{port}")
    print(f"   POST /scan   — scaneaza cod")
    print(f"   GET  /health — check stare")
    print(f"   POST /admin/keys — creare cheie tester (X-Admin-Key)")
    print(f"   GET  /       — frontend")
    app.run(host='0.0.0.0', port=port, debug=False)
