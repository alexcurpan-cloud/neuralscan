"""
security-scanner/scanner.py
Pattern-based security scanner (gitleaks + semgrep emulation).
Detects:
  - Hardcoded secrets / API keys
  - SQL injection patterns
  - Code injection (eval, exec, os.system)
  - Insecure crypto
  - Path traversal
"""

import re
import os
import base64
import tempfile
import json
from dataclasses import dataclass, field, asdict
from typing import List, Optional


@dataclass
class Finding:
    type: str          # e.g. "hardcoded_api_key", "sql_injection", "code_injection"
    severity: str      # "critical" | "high" | "medium" | "low"
    line: int
    column: int
    match: str         # the matched text (redacted for secrets)
    description: str   # human-readable
    confidence: str    # "high" | "medium" | "low"


# Rang real de severitate (sortare 2026-09-26: înainte se sorta alfabetic →
# 'low' apărea înaintea lui 'medium').
SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}


# Fix 2026-10-09: fisierele LOCK contin hash-uri de integritate (nu secrete) si
# produc fals-pozitive (ex. 'hardcoded_jwt' in package-lock.json). Sunt sarite la
# colectarea fisierelor (CLI + ZIP), NU la scanarea unui sir de cod dat direct.
LOCKFILE_NAMES = {
    "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml",
    "bun.lockb", "composer.lock", "gemfile.lock", "poetry.lock", "cargo.lock",
    "pipfile.lock", "packages.lock.json", "mix.lock", "pubspec.lock",
}


def is_lockfile(name: str) -> bool:
    """True pentru fisiere lock (zgomot in scanare) — verificat pe basename."""
    base = os.path.basename((name or "").replace("\\", "/")).lower()
    return base in LOCKFILE_NAMES


# Fix 2026-10-11 (precizie outreach): 3 clase de fals-pozitive care umflau rapoartele
# pe apps reale (Lovable/Supabase), confirmate pe 5 repo-uri publice:
#   1. chei Supabase anon/publishable (PUBLICE prin design) raportate ca "JWT critic"
#   2. data: URI base64 (imagini inline) cu substring ce arata ca JWT/secret
#   3. model.eval() / regex.exec() in fisiere minificate -> "executie de cod"
ANON_ROLES = {"anon", "publishable"}


def _mask_data_uris(code: str) -> str:
    """Mascheaza data: URI base64 (imagini/fonturi inline) — zgomot, nu secrete."""
    return re.sub(
        r'data:[a-zA-Z0-9.+-]+/[a-zA-Z0-9.+-]+(?:;base64)?,[A-Za-z0-9+/=%\s]{16,}',
        lambda m: " " * len(m.group()), code,
    )


def _jwt_is_public(text: str) -> bool:
    """True pentru JWT-uri PUBLICE (Supabase anon/publishable) — nu sunt secrete.

    Supabase anon key = JWT cu payload {iss: supabase, role: anon}. E menit public
    (protejat de RLS). Orice app Lovable il are in client.ts -> era raportat 'critic'.
    """
    parts = text.split(".")
    if len(parts) < 2:
        return False
    payload = parts[1] + "=" * (-len(parts[1]) % 4)
    try:
        data = json.loads(base64.urlsafe_b64decode(payload))
    except Exception:
        return False
    role = str(data.get("role", "")).lower()
    if role in ANON_ROLES:
        return True
    # Fix 2026-10-13: JWT de tip Supabase storage SIGNED URL (payload are "scope":
    # "download"/"upload") = link semnat catre UN obiect, nu credential de acces.
    # Raportarea lui ca "JWT critic" a fost FP dovedit (MODOBOOK logo).
    if str(data.get("scope", "")).lower() in ("download", "upload"):
        return True
    return False


def _is_safe_subprocess_list_call(line_text: str, matched: str) -> bool:
    """True daca e subprocess.*([...]) in forma de LISTA, fara shell=True.

    Forma de lista trece argumentele direct (fara shell) -> NU e injectie shell.
    FP dovedit 2026-10-13 (afterthought/crew: subprocess.run(["wt", "-C", f"..."])
    raportat ca 'command_injection critical').
    os.system/os.popen/exec sunt mereu shell/exec -> NU sunt sigure.
    """
    if re.search(r"shell\s*=\s*True", line_text):
        return False  # shell=True explicit -> risc real
    if re.match(r"\s*os\.(?:system|popen)\b", matched) or re.match(r"\s*exec\b", matched):
        return False
    return bool(re.match(r"\s*subprocess\.\w+\s*\(\s*\[", matched))


# ── Fix 2026-10-18 (lot r6): identificatori nu sunt secrete ──────────────
# Dovedit pe lotul r6: `SERVICE_TOKEN_SECRET = 'clike.serviceToken'` (nume de cheie
# in SecretStorage) si `{ token: "tag.html", foreground: "FF9F0A" }` (regula de
# syntax highlighting) au fost raportate ca "parola hardcodata". 18 din 32 findings.
_KEY_NAME_RE = re.compile(r"^[a-z][a-zA-Z0-9_]*(?:\.[a-zA-Z0-9_]+)+$")


def _looks_like_identifier(value: str) -> bool:
    """True daca valoarea e un NUME de cheie/identificator, nu un secret.

    Secretele reale nu arata ca niste nume punctate cu litere mici
    ('clike.serviceToken', 'tag.html')."""
    v = (value or "").strip()
    if not v or len(v) > 60:
        return False
    return bool(_KEY_NAME_RE.match(v))


# ── Fix 2026-10-18 (lot r6): proza/documentatie nu e vulnerabilitate ─────
# Dovedit pe lotul r6: `subprocess.run(shell=True)` mentionat intr-un DOCSTRING si
# `eval(` dintr-un text de ajutor CLI (`help="... eval (roadmap §3)"`) au fost
# raportate ca 'command_injection critical' / 'eval_usage high'.
_PROSE_CODE_HINTS = re.compile(
    r"\b(?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE|DROP|CREATE|ALTER)\b"
    r"|curl|wget|\brm\b|\bsudo\b", re.IGNORECASE)


def _is_eval_definition(line_text: str) -> bool:
    """True pentru `def eval(...)` / `async def eval(...)` — numele functiei, nu eval().

    FP dovedit r6: `orchestrator/services/local_agent/eval.py:1` raportat ca eval_usage."""
    return bool(re.search(r"\b(?:async\s+)?def\s+eval\s*\(", line_text))


def _is_ui_theme_rule(line_text: str) -> bool:
    """True pentru reguli de tema / syntax highlighting (`{ token: "x", foreground: "FFF" }`).

    FP dovedit r6: 6 findings 'parola hardcodata' in EmailTemplatesEditor.tsx —
    erau culori si nume de tokeni de highlight, nu secrete."""
    return bool(re.search(r"\b(?:foreground|background|fontStyle|colors?)\s*:", line_text)
                and re.search(r"\btoken\s*:", line_text))


def _in_prose_string(line_text: str, match_text: str) -> bool:
    """True daca match-ul sta intr-un string care e proza, nu cod.

    Determina string-ul prin PARITATEA ghilimelelor de dinaintea match-ului
    (regex-ul naiv se încurcă la linii cu mai multe string-uri: `ap.add_argument(
    "--auto-eval", help="KIT ... eval (roadmap)")`).
    Proza = >= 6 spatii in string si niciun cuvant de cod (SQL/shell).
    """
    idx = line_text.find(match_text)
    if idx < 0:
        return False
    for q in ('"', "'"):
        if line_text.count(q, 0, idx) % 2 == 1:
            start = line_text.rfind(q, 0, idx)
            end = line_text.find(q, idx)
            if end == -1:
                end = len(line_text)
            seg = line_text[start + 1:end]
            if _PROSE_CODE_HINTS.search(seg):
                return False
            if seg.count(" ") >= 6:
                return True
    return False


# ── Fix 2026-10-18 (r6): docstring-urile nu sunt cod ─────────────────────
_TRIPLE_QUOTED_RE = re.compile(r'("""|\'\'\')(?:.*?)\1', re.DOTALL)


def _mask_docstrings(code: str) -> str:
    """Inlocuieste blocurile triple-quoted cu spatii (aceeasi lungime, aceleasi linii).

    Dovedit r6: `subprocess.run(shell=True)` si `eval (` din docstring-uri si din
    texte de ajutor au fost raportate ca vulnerabilitati critice (clike: 4/11).
    """
    def _blank(m):
        seg = m.group(0)
        return "".join("\n" if ch == "\n" else " " for ch in seg)
    return _TRIPLE_QUOTED_RE.sub(_blank, code)


def _is_self_pip_install(line_text: str) -> bool:
    """True pentru `os.system(f"{sys.executable} -m pip install ...")` — auto-install
    de dependente, fara input extern (FP dovedit r6: smart-hebrew-transcriber)."""
    low = line_text.lower()
    if "pip install" not in low:
        return False
    return ("sys.executable" in line_text) or ("-m pip" in low)


def _is_method_eval_context(line_before: str) -> bool:
    """True daca 'eval(' e de fapt un apel de METODA (obj.eval()) — nu eval() global.

    Ex: PyTorch model.eval(), re.Pattern.exec -> zgomot, nu executie de cod."""
    return line_before.rstrip().endswith(".")


def _is_minified(code: str) -> bool:
    """Heuristica: fisiere minificate/bundled (linii f. lungi, putine) = zgomot."""
    lens = [len(l) for l in code.split("\n") if l.strip()]
    if not lens:
        return False
    very_long = sum(1 for L in lens if L > 1000)
    if very_long >= 3 or (max(lens) > 2000 and len(lens) < 40):
        return True
    # JS obfuscat (mult _0x...) = cod de bundle/vendor, nu codul autorului.
    return code.count("_0x") > 10


# Valori-cunoscute care NU sunt secrete (constante de protocol/placeholder).
NOT_SECRET_VALUES = {"x-oauth-basic", "x-access-token", "oauth2", "basic"}


def _password_match_is_noise(match_text: str) -> bool:
    """True daca un match 'password/token = "..."' e de fapt zgomot.

    - valoarea contine spatii -> e o propozitie (log/mesaj), nu o parola
    - valoarea e o constanta de protocol (x-oauth-basic)
    """
    quoted = re.findall(r"[\"']([^\"']{1,})[\"']", match_text)
    if not quoted:
        return False
    value = quoted[-1]
    if value.strip().lower() in NOT_SECRET_VALUES:
        return True
    # Fix 2026-10-13: valoare pur numerica si scurta (ex. token de preview '123456')
    # = placeholder de template SAMPLE, nu secret. (Parolele reale nu-s 6 cifre.)
    if value.strip().isdigit() and len(value.strip()) <= 8:
        return True
    # Fix 2026-10-16 (Poarta 0): placeholder/expresie/junk in valoare, nu secret.
    #   ex: token='{hash}', password="%s", TOKEN='):env[' (artefact peste ghilimele)
    if re.search(r"[{}%()\[\]<>;]", value):
        return True
    # Fix 2026-10-16 (Poarta 0): masca de UI (********, ••••••••) nu e o parola.
    if len(value.strip()) >= 4 and len(set(value.strip())) == 1:
        return True
    # psql variable substitution lipita de ghilimeaua de deschidere:
    #   ALTER USER x WITH PASSWORD :'pgpass';   (NU prinde JS 'password: "x"')
    if re.search(r":[\"']", match_text):
        return True
    return bool(re.search(r"\s", value))


# Fix 2026-10-16 (Poarta 0, precizie outreach): fisierele de TEST contin
# credentiale dummy PRIN DESIGN (ex. `password: 'WrongPass123'` intr-un
# cypress/*.cy.js, `const FAKE_TOKEN = 'abc'` intr-un __tests__/). Raportarea
# lor ca "parola hardcodata" e fals-pozitiv garantat — confirmat pe 2/2 findings
# din runda r3 (1 real, 1 FP de test). Se aplica DOAR la tipul generic
# `hardcoded_password`; cheile reale (API keys/JWT/PAT) raman raportate si in
# teste, pentru ca alea pot fi scurse real acolo.
_TEST_DIRS = {
    "__tests__", "__mocks__", "test", "tests", "spec", "specs",
    "cypress", "e2e", "fixtures", "fixture", "testdata",
}
_TEST_FILE_RE = re.compile(r"(?:[._-](?:test|spec|cy|e2e))\.[^.]+$", re.IGNORECASE)


def _is_test_file(filename: str) -> bool:
    """True daca fisierul e un test/spec/fixture (parolele dummy = zgomot)."""
    if not filename:
        return False
    parts = filename.replace("\\", "/").strip("/").split("/")
    if any(p.lower() in _TEST_DIRS for p in parts[:-1]):
        return True
    base = parts[-1] if parts else ""
    return bool(_TEST_FILE_RE.search(base))


# Fix 2026-10-16 (Poarta 0): fisierele de traduceri au chei ca `password: "Пароль"`
# (cuvantul tradus) — raportate gresit ca "parola hardcodata".
_I18N_DIRS = {"i18n", "intl", "locale", "locales", "lang", "langs", "translations", "translation"}
_I18N_FILE_RE = re.compile(
    r"(?:^|/)(?:i18n|locale|locales|lang|translations?|messages?|strings?)\.[^/]+$", re.IGNORECASE)


def _is_i18n_file(filename: str) -> bool:
    """True daca fisierul e un catalog de traduceri (parolele = cuvinte traduse)."""
    if not filename:
        return False
    parts = filename.replace("\\", "/").strip("/").split("/")
    if any(p.lower() in _I18N_DIRS for p in parts[:-1]):
        return True
    return bool(_I18N_FILE_RE.search(parts[-1] if parts else ""))


# Tipuri de findings care sunt zgomot in fisiere de test (credentiale dummy,
# harness-uri care scriu config etc.). Cheile reale de provider NU sunt aici —
# alea pot fi scurse si intr-un test, deci raman raportate.
TEST_NOISE_TYPES = {
    "hardcoded_password", "hardcoded_api_key", "path_traversal",
    "command_injection", "sql_injection_concat", "sql_injection_format",
    "eval_usage", "insecure_http", "hardcoded_debug",
}


def _mask_comment_lines(code: str, filename: str = "") -> str:
    """Inlocuieste liniile care sunt DOAR comentariu cu spatii (aceeasi lungime).

    Astfel un URL/secret mentionat intr-un comentariu nu mai produce findings,
    fara sa atinga liniile de cod si fara sa deplaseze numerele de linie.
    """
    ext = os.path.splitext(filename or "")[1].lower()
    dash_ok = ext in (".sql", ".sh", ".bash", ".zsh", ".yml", ".yaml")
    out = []
    for line in code.split("\n"):
        s = line.lstrip()
        is_c = s.startswith(("//", "/*", "*/", "#"))
        if not is_c and s.startswith("*") and (len(s) == 1 or s[1] in " \t"):
            is_c = True  # continuare de block-comment (linia incepe cu '*')
        if not is_c and dash_ok and s.startswith("--") and (len(s) == 2 or s[2] in " \t"):
            is_c = True  # comentariu SQL/shell
        out.append(" " * len(line) if is_c else line)
    return "\n".join(out)


# Fix 2026-10-09: valori care NU sunt secrete reale — placeholdere de template si
# chei de TEST (zero bani). Raportarea lor = fals-pozitive care ne face de râs
# (ex: "your-password-here" sau sk_test_... raportate ca secret CRITIC).
_EXACT_PLACEHOLDERS = {
    "password", "passwd", "pwd", "secret", "token", "apikey", "api_key",
    "changeme", "change-me", "change_me", "admin", "root", "example", "sample",
    "dummy", "todo", "fixme", "placeholder", "none", "null", "undefined",
    "yourpassword", "your_password", "your-password", "test", "12345678",
    "password123", "123456", "qwerty",
}
# Markerii trebuie sa fie NON-ambigui: NU include 'aaaa'/'xxxx'/'test' (apar in
# chei de test legitime: ghp_+xxx, SG.aaaa..., etc.).
_PLACEHOLDER_MARKERS = (
    "your-", "your_", "yourpassword", "changeme", "change-me", "change_me",
    "placeholder", "example", "dummy", "sample", "redacted", "replace-me",
    "replace_me", "insert your", "<", ">", "{{", "${", "***", "your password",
)
_TEST_TOKEN_PREFIXES = ("tok_", "tok-")

# Prefixe de PROVIDER real: daca valoarea incepe asa, NU e placeholder chiar daca
# are caractere repetate (ghp_xxxx, SG.aaaa, AKIAxxxx...).
_PROVIDER_PREFIXES = (
    "ghp_", "gho_", "ghs_", "ghr_", "github_pat_",
    "sk_live_", "rk_live_", "sk-", "sk_",
    "SG.", "xoxb-", "xoxp-", "xoxa-", "xoxr-",
    "GOCSPX-", "AKIA", "ASIA", "AIza",
)


def _is_placeholder_value(value: str) -> bool:
    """True daca valoarea e un placeholder/valoare de test, nu un secret real."""
    s = (value or "").strip().strip("'\"").lower()
    if not s:
        return True
    if s in _EXACT_PLACEHOLDERS:
        return True
    if s.startswith(_TEST_TOKEN_PREFIXES):
        return True
    # Fix 2026-10-16 (Poarta 0): placeholder evidente care scapau.
    #   - run de 6+ caractere identice: 're_xxxxxxxxxxxx', 'lov_xxxxx'
    #     DAR NU daca valoarea incepe cu un prefix real de provider (ghp_, SG.,
    #     AKIA, xoxb-, GOCSPX-...) — alea folosesc des caractere repetate si
    #     trebuie raportate.
    #   - nume de variabila de mediu (SCREAMING_SNAKE, fara minuscule): 'AI_GEMINI_API_KEY'
    #   - exemplu trunchiat in documentatie: 'eyJ...'
    raw = value.strip()
    if re.search(r"(.)\1{5,}", s) and not raw.startswith(_PROVIDER_PREFIXES):
        return True
    if len(raw) >= 6 and "_" in raw and re.fullmatch(r"[A-Z0-9_]+", raw):
        return True
    if "..." in s:
        return True
    return any(m in s for m in _PLACEHOLDER_MARKERS)


def _secret_is_placeholder(match_text: str, ptype: str) -> bool:
    """Decide daca un match de SECRET e de fapt placeholder/test (se poate sări)."""
    t = match_text or ""
    low = t.lower()
    if ptype == "hardcoded_stripe_key":
        # sk_test_/rk_test_ = mod de TEST (fara acces la bani) -> nu e "critic".
        return "_test_" in low or "_live_" not in low
    if ptype == "hardcoded_db_url":
        m = re.search(r"://([^:\s/]+):([^@\s]+)@", t)
        if m:
            return _is_placeholder_value(m.group(2)) or _is_placeholder_value(m.group(1))
        return False
    # generic (parole, api keys): extrage ultimul sir intre ghilimele
    quoted = re.findall(r"[\"']([^\"']{3,})[\"']", t)
    if quoted:
        return _is_placeholder_value(quoted[-1])
    return _is_placeholder_value(t)


# ─── Secret patterns ────────────────────────────────────────────────

# ORDINEA CONTEAZA (fix 2026-09-26): pattern-urile SPECIFICE (prefix de provider)
# vin INAINTE de cele generice. Un match acoperit de un pattern mai specific nu mai
# e raportat de generic (ex: GitHub PAT nu mai apare ca "hardcoded_password").
SECRET_PATTERNS = [
    # AWS Access Key
    {
        "type": "hardcoded_aws_key",
        "severity": "critical",
        "confidence": "high",
        "description": "Cheie AWS hardcodata — poate duce la preluarea contului. Roteste imediat.",
        "pattern": re.compile(r'(?:AKIA[0-9A-Z]{16}|aws_access_key_id[\s\'\"=:]+[\'\"][A-Z0-9]{16,}[\'\"])'),
    },
    # Stripe secret/restricted key (rare in AI-gen code, dar echivaleaza cu acces la bani)
    {
        "type": "hardcoded_stripe_key",
        "severity": "critical",
        "confidence": "high",
        "description": "Cheie Stripe hardcodata — oricine o vede poate initia plati/rambursari pe contul tau.",
        "pattern": re.compile(r'\b(?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{16,}'),
    },
    # SendGrid / Mailgun API key
    {
        "type": "hardcoded_sendgrid_key",
        "severity": "critical",
        "confidence": "high",
        "description": "Cheie SendGrid hardcodata — poate fi folosita pentru spam de pe domeniul tau.",
        "pattern": re.compile(r'\bSG\.[a-zA-Z0-9_\-]{16,}\.[a-zA-Z0-9_\-]{16,}'),
    },
    # Slack token (bot/user/app/webhook)
    {
        "type": "hardcoded_slack_token",
        "severity": "critical",
        "confidence": "high",
        "description": "Token Slack hardcodat — da acces la workspace-ul tau.",
        "pattern": re.compile(r'\bxox[baprse]-[0-9a-zA-Z\-]{10,}'),
    },
    # GitHub token (PAT / app / refresh)
    {
        "type": "hardcoded_github_token",
        "severity": "critical",
        "confidence": "high",
        "description": "Token GitHub hardcodat — poate da acces la toate repo-urile tale.",
        "pattern": re.compile(r'(?:\b(?:ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36,}|\bgithub_pat_[a-zA-Z0-9_]{22,})'),
    },
    # Google OAuth client secret
    {
        "type": "hardcoded_google_secret",
        "severity": "critical",
        "confidence": "high",
        "description": "Client secret Google hardcodat — permite impersonarea aplicatiei tale.",
        "pattern": re.compile(r'\bGOCSPX-[a-zA-Z0-9_\-]{20,}'),
    },
    # OpenAI / Anthropic / generic API keys
    {
        "type": "hardcoded_api_key",
        "severity": "critical",
        "confidence": "high",
        "description": "Hardcodat API key — orice commit o expune. GitHub scaneaza automat si trimite alerta.",
        "pattern": re.compile(r'(?:(?:sk-|pk-)[a-zA-Z0-9]{20,}|AIza[0-9A-Za-z\-_]{35}|api[_-]?key[\s\'\"=:]+[\'\"][a-zA-Z0-9_\-]{16,}[\'\"])', re.IGNORECASE),
    },
    # JWT / Bearer tokens
    {
        "type": "hardcoded_jwt",
        "severity": "critical",
        "confidence": "high",
        "description": "JWT token hardcodat — oricine vede codul il poate folosi.",
        "pattern": re.compile(r'(?:bearer\s+[a-zA-Z0-9\-_\.]{20,}|eyJ[a-zA-Z0-9\-_\.]{20,})', re.IGNORECASE),
    },
    # Password / secret assignments — GENERIC, ultimul (nu mai fura eticheta
    # pattern-urilor specifice de mai sus).
    {
        "type": "hardcoded_password",
        "severity": "high",
        "confidence": "high",
        "description": "Parola hardcodata in cod — nu se pune in git niciodata.",
        "pattern": re.compile(r'(?:password|passwd|pwd|secret|token)\s*[=:]\s*[\'\"][^\'\"$\n]{6,}[\'\"]', re.IGNORECASE),
    },
    # Database connection strings
    {
        "type": "hardcoded_db_url",
        "severity": "critical",
        "confidence": "high",
        "description": "URL de baza de date cu credentiale — expune toate datele.",
        "pattern": re.compile(r'(?:postgresql?|mysql|mongodb|redis)://[^\s\'\"@]+:[^\s\'\"@]+@', re.IGNORECASE),
    },
    # Private keys
    {
        "type": "hardcoded_private_key",
        "severity": "critical",
        "confidence": "high",
        "description": "Cheie privata (RSA/EC) in cod — compromite orice sistem care o foloseste.",
        "pattern": re.compile(r'-----BEGIN\s+(?:RSA|EC|DSA|OPENSSH)\s+PRIVATE\s+KEY-----'),
    },
]


# ─── Namespace host whitelist (plasă SECUNDARĂ, după context) ──────
NAMESPACE_HOSTS = {
    "w3.org",
    "xmlsoap.org",
    "schemas.xmlsoap.org",
    "purl.org",
    "openxmlformats.org",
    "tempuri.org",
    "www.w3.org",
}


def _extract_line(code: str, pos: int) -> str:
    """Extrage textul liniei care conține poziția pos."""
    line_start = code.rfind('\n', 0, pos) + 1
    if line_start == -1 or line_start == 0:
        line_start = 0
    line_end = code.find('\n', pos)
    if line_end == -1:
        line_end = len(code)
    return code[line_start:line_end]


def _text_before(code: str, pos: int) -> str:
    """Extrage textul de la începutul liniei până la poziția pos."""
    line_start = code.rfind('\n', 0, pos) + 1
    if line_start == -1 or line_start == 0:
        line_start = 0
    return code[line_start:pos]


def _host_from_url(url: str) -> str:
    """Extrage hostname-ul dintr-un URL http://."""
    # http://some.host.com/path → some.host.com
    rest = url[len("http://"):]
    # Stop at first /, ?, #, or :
    for sep in ('/', '?', '#', ':'):
        idx = rest.find(sep)
        if idx >= 0:
            rest = rest[:idx]
    return rest.lower()


def _is_namespace_url(url: str) -> bool:
    """Check if an http:// URL host is in the namespace whitelist (plasă SECUNDARĂ)."""
    host = _host_from_url(url)
    for ns_host in NAMESPACE_HOSTS:
        if host == ns_host or host.endswith('.' + ns_host):
            return True
    return False


# ─── Gap 1: Context-aware namespace detection for insecure_http ────
# Patterns that identify the text BEFORE an http:// match as a namespace
# declaration (NOT a real network target).
NAMESPACE_CONTEXT_PATTERNS = [
    # 1a. Variable/const name ENDS with Ns / Namespace / Schema / Xmlns
    #     e.g. SoapSchemaNs = "http://...",  CustomNs = "http://..."
    #     NU substring: "insecureUrl" conține "ns" dar nu e namespace.
    #     Cheia: \w+ (unul+) + fără \w* după sufix → sufixul e la sfârșitul
    #     identificatorului, imediat înainte de \s*[=:]
    re.compile(r'\b\w+(?:Ns|Namespace|Schema|Xmlns)\s*[=:]\s*[\'\"#]?$', re.IGNORECASE),
    # 1b. Type declaration XNamespace or XmlSerializerNamespaces
    #     e.g. XNamespace x = "http://..."
    re.compile(r'\bXNamespace\b|\bXmlSerializerNamespaces\b'),
    # 2. XML attribute: xmlns=, xmlns:prefix=, targetNamespace=
    #     e.g. xmlns:xsi="http://..."
    re.compile(r'\bxmlns[\:\w]*\s*=\s*[\'\"#]?$', re.IGNORECASE),
    re.compile(r'\btargetNamespace\s*=\s*[\'\"#]?$', re.IGNORECASE),
    # 3. SOAP Action constant
    #     e.g. private const string Action = "http://..."
    re.compile(r'\bAction\s*=\s*[\'\"#]?$', re.IGNORECASE),
    # 4. SOAPAction header
    re.compile(r'SOAPAction[\'\"\s]*[:=]\s*[\'\"#]?$', re.IGNORECASE),
    # 5. Namespace API method calls (AddNamespace, AppendNamespace, etc.)
    re.compile(r'(?:AddNamespace|AppendNamespace|NamespaceManager|DefineNamespace|RegisterNamespace)', re.IGNORECASE),
]


def _is_namespace_context(line_before: str, match_url: str) -> bool:
    """
    Verifică dacă un URL http:// (matchuit de regex) e un identificator
    de namespace în contextul liniei, NU o țintă reală de rețea.

    line_before = textul de la începutul liniei până la URL (exclusiv)
    match_url   = URL-ul matchuit (pentru fallback host-whitelist)
    """
    # Check 1: Context patterns — nume variabilă, tip, xmlns, SOAP Action
    for pat in NAMESPACE_CONTEXT_PATTERNS:
        if pat.search(line_before):
            return True

    # Check 2: Fallback — host whitelist (plasă secundară)
    if _is_namespace_url(match_url):
        return True

    return False


# ─── Gap 2: Token-level eval detection ─────────────────────────────
# Check if THIS SPECIFIC eval match is a batch variable, not a function call.
# Scanned on text BEFORE the match position (not the whole line).


def _is_batch_eval_context(line_before: str, filename: str) -> bool:
    """
    Verifică dacă ocurența CURRENȚĂ de 'eval' e nume de variabilă batch,
    NU apel de funcție. Verifică doar textul DINANTEA match-ului.

    line_before = textul de la începutul liniei până la 'eval'
    """
    # Skip entirely for .bat/.cmd files — eval() is not a thing in batch
    if filename.lower().endswith(('.bat', '.cmd')):
        return True

    # Check text just before 'eval' for batch variable patterns
    stripped = line_before.rstrip()
    # if defined eval → text_before ends with "if defined"
    if re.search(r'if\s+defined\s*$', stripped, re.IGNORECASE):
        return True
    # set eval → text_before ends with "set"
    if re.search(r'\bset\s*$', stripped, re.IGNORECASE):
        return True

    return False


# ─── Code injection patterns ────────────────────────────────────────

CODE_PATTERNS = [
    {
        "type": "sql_injection_concat",
        "severity": "critical",
        "confidence": "high",
        "description": "SQL injection prin concatenare de stringuri — atacatorul poate citi/stergere toate datele.",
        "pattern": re.compile(r'(?:execute|cursor\.execute|query|raw_query)\s*\(\s*(?:f[\'\"]|[\'\"]\s*\+)', re.IGNORECASE),
    },
    {
        "type": "sql_injection_format",
        "severity": "critical",
        "confidence": "high",
        "description": "SQL query construit cu format() — la fel de periculos ca concatenarea.",
        "pattern": re.compile(r'(?:execute|cursor\.execute|query|raw_query)\s*\(\s*[\'\"][^\'\"]*%[sd][^\'\"]*[\'\"]\s*%(?!\s*[\'\"])', re.IGNORECASE),
    },
    {
        "type": "command_injection",
        "severity": "critical",
        "confidence": "high",
        "description": "Comanda shell construita dinamic — injectie shell posibila. Atacatorul poate rula comenzi pe server.",
        # [^\n;] in loc de [^)]: prinde si argumente cu paranteze imbricate
        # (ex: os.system(f"ping {get_host(x)}")) fara sa treaca peste linii/comenzi.
        "pattern": re.compile(r'(?:os\.system|subprocess\.(?:call|Popen|run|check_output|check_call)|os\.popen|exec)\s*\([^\n;]{0,200}?(?:f[\'\"]|[\'\"]\s*\+)', re.IGNORECASE),
    },
    # shell=True transforma orice argument string in comanda shell (injectie),
    # chiar si fara concatenare vizibila (fix 2026-09-26).
    {
        "type": "command_injection",
        "severity": "critical",
        "confidence": "high",
        "description": "subprocess cu shell=True — inputul devine comanda shell. Atacatorul poate rula comenzi pe server.",
        "pattern": re.compile(r'\bsubprocess\.(?:run|call|Popen|check_output|check_call)\s*\([^\n]{0,200}?shell\s*=\s*True', re.IGNORECASE),
    },
    {
        "type": "eval_usage",
        "severity": "high",
        "confidence": "high",
        "description": "eval() cu input dinamic — executie de cod arbitrar.",
        "pattern": re.compile(r'\beval\s*\(', re.IGNORECASE),
    },
    {
        "type": "path_traversal",
        "severity": "high",
        "confidence": "medium",
        # Fix 2026-10-16 (Poarta 0): scos read_text/write_text (in pathlib primul
        # argument e CONTINUTUL, nu calea -> FP) + lookbehind anti-'urlopen('.
        "description": "Cale de fisier construita prin concatenare fara sanitizare — path traversal posibil.",
        "pattern": re.compile(r'(?<![A-Za-z0-9_])open\s*\(\s*(?:f[\'\"]|[\'\"]\s*\+)', re.IGNORECASE),
    },
    {
        "type": "weak_crypto",
        "severity": "medium",
        "confidence": "high",
        "description": "Algoritm criptografic slab (MD5/SHA1) — nu mai e sigur pentru securitate.",
        "pattern": re.compile(r'(?:hashlib\.md5|hashlib\.sha1|Crypt::MD5|MessageDigest\.getInstance\s*\(\s*[\'\"]MD5)', re.IGNORECASE),
    },
    {
        "type": "weak_encryption",
        "severity": "medium",
        "confidence": "high",
        "description": "Algoritm de criptare slab (DES/RC4) — foloseste AES in loc.",
        "pattern": re.compile(r'(?:\.getInstance\s*\(\s*[\'\"]DES|\.getInstance\s*\(\s*[\'\"]RC4|Fernet\s*\(|AES\.new)', re.IGNORECASE),
    },
    {
        "type": "insecure_http",
        "severity": "low",
        "confidence": "medium",
        "description": "Conexiune HTTP in loc de HTTPS — trafic necriptat, usor de interceptat.",
        "pattern": re.compile(r'http://[^\s\'\"{}/:?#]+\.(?:com|ro|org|net|io)', re.IGNORECASE),
    },
    {
        "type": "hardcoded_debug",
        "severity": "high",
        "confidence": "high",
        "description": "Debug mode + host 0.0.0.0 activ in productie — Werkzeug debugger permite RCE (Remote Code Execution). Atacatorul poate obtine shell pe server.",
        "pattern": re.compile(r'(?:debug\s*=\s*True|DEBUG\s*=\s*True|app\.run\([^()]*debug\s*=\s*True)', re.IGNORECASE),
    },
]


def redact_match(match_text: str, pattern_type: str) -> str:
    """Redacteaza textul match-uit, pastrand primii si ultimii 4 char."""
    t = match_text.strip()
    if len(t) <= 12:
        return t[:2] + "***" + t[-2:] if len(t) > 4 else "***"
    return t[:4] + "..." + t[-4:]


def scan_code(code: str, filename: str = "input") -> List[dict]:
    """
    Scaneaza codul pentru pattern-uri de securitate.
    Returneaza lista de findings.
    """
    findings = []
    # Fix 2026-10-09: liniile care sunt DOAR comentariu nu mai produc findings
    # (ex: un URL 'http://...' într-un comentariu → fals-pozitiv). Înlocuim
    # comentariile cu spații — aceeași lungime, deci liniile/coloanele rămân corecte.
    code = _mask_comment_lines(code, filename)
    code = _mask_docstrings(code)
    code = _mask_data_uris(code)
    lines = code.split('\n')
    minified = _is_minified(code)
    is_test = _is_test_file(filename)
    is_i18n = _is_i18n_file(filename)

    # Track matched (type, line) to avoid duplicates of the SAME type on a line,
    # dar lasa tipuri diferite pe aceeasi linie sa se raporteze separat (fix 2026-09-26).
    matched_lines_secrets = set()
    matched_lines_code = set()

    # Scan for secrets
    secret_spans = []  # (start, end) raportate deja de un pattern mai specific
    for pattern_def in SECRET_PATTERNS:
        for match in pattern_def["pattern"].finditer(code):
            # Nu raporta generic peste ceva deja prins de un pattern specific:
            # ex. cheia Stripe/GitHub nu mai apare si ca "hardcoded_password".
            if any(not (match.end() <= s or match.start() >= e)
                   for s, e in secret_spans):
                continue

            # Fix 2026-10-18: calculat INAINTE de filtre (unele se uita la linie).
            line_no = code[:match.start()].count('\n') + 1

            # Fix 2026-10-09: placeholdere de template + chei de TEST nu sunt
            # secrete reale -> nu le raportam (fals-pozitive care ne-ar face de râs).
            if _secret_is_placeholder(match.group(), pattern_def["type"]):
                continue

            # Fix 2026-10-11: cheile PUBLICE (Supabase anon/publishable) nu sunt secrete.
            if pattern_def["type"] == "hardcoded_jwt" and _jwt_is_public(match.group()):
                continue
            # Fix 2026-10-11: 'password/token = "..."' cu propozitie/constantă = zgomot.
            if pattern_def["type"] == "hardcoded_password" and _password_match_is_noise(match.group()):
                continue
            # Fix 2026-10-16 (Poarta 0): atribute HTML `data-token=...` (widget-uri
            # Trustpilot etc.) nu-s secrete.
            if pattern_def["type"] == "hardcoded_password" and re.search(r"data-\s*$", _text_before(code, match.start())):
                continue
            # Fix 2026-10-18 (lot r6): valoarea e un NUME de cheie, nu un secret
            #   ('clike.serviceToken', 'tag.html') -> 18/32 findings din r6.
            if pattern_def["type"] == "hardcoded_password":
                quoted_vals = re.findall(r"[\"']([^\"']{1,})[\"']", match.group())
                if quoted_vals and _looks_like_identifier(quoted_vals[-1]):
                    continue
                # Fix 2026-10-18 (r6): regula de tema/highlight (token + foreground) = UI, nu secret.
                line_txt_ui = lines[line_no - 1] if line_no - 1 < len(lines) else ""
                if _is_ui_theme_rule(line_txt_ui):
                    continue
            # Fix 2026-10-16: credentiale dummy din teste + cuvinte traduse din i18n.
            if is_test and pattern_def["type"] in TEST_NOISE_TYPES:
                continue
            if is_i18n and pattern_def["type"] == "hardcoded_password":
                continue

            # Calculate line number
            line_no = code[:match.start()].count('\n') + 1
            dedup_key = (pattern_def["type"], line_no)
            if dedup_key in matched_lines_secrets:
                continue
            matched_lines_secrets.add(dedup_key)

            col = match.start() - code[:match.start()].rfind('\n') - 1
            if col < 0:
                col = 0

            secret_spans.append((match.start(), match.end()))
            findings.append(Finding(
                type=pattern_def["type"],
                severity=pattern_def["severity"],
                line=line_no,
                column=max(col, 0),
                match=redact_match(match.group(), pattern_def["type"]),
                description=pattern_def["description"],
                confidence=pattern_def["confidence"],
            ))

    # Scan for code issues (SQL injection, etc.)
    # Fix 2026-10-11: in fisiere minificate (bundle/vendor) pattern-urile de cod sunt zgomot.
    for pattern_def in ([] if minified else CODE_PATTERNS):
        for match in pattern_def["pattern"].finditer(code):
            line_no = code[:match.start()].count('\n') + 1

            # Fix 2026-10-16 (Poarta 0): zgomot de test (harness scrie config etc.).
            if is_test and pattern_def["type"] in TEST_NOISE_TYPES:
                continue

            # ── Gap 1: insecure_http — context-based namespace detection ──
            if pattern_def["type"] == "insecure_http":
                before = _text_before(code, match.start())
                if _is_namespace_context(before, match.group()):
                    continue  # FP — namespace identifier, not network target

            # ── Gap 2: eval_usage — token-level batch check ──
            if pattern_def["type"] == "eval_usage":
                before = _text_before(code, match.start())
                if _is_batch_eval_context(before, filename):
                    continue  # FP — eval is a variable name in batch context
                # Fix 2026-10-11: model.eval() / obj.eval() = apel de metoda, nu eval() global.
                if _is_method_eval_context(before):
                    continue
                # Fix 2026-10-18 (r6): `def eval(` = numele functiei, nu eval() global.
                line_txt_eval = lines[line_no - 1] if line_no - 1 < len(lines) else ""
                if _is_eval_definition(line_txt_eval):
                    continue

            # Fix 2026-10-13: subprocess.run([...]) in forma de LISTA (fara shell=True)
            # nu e injectie shell — FP dovedit (afterthought/crew).
            if pattern_def["type"] == "command_injection":
                line_txt_ci = lines[line_no - 1] if line_no - 1 < len(lines) else ""
                if _is_safe_subprocess_list_call(line_txt_ci, match.group()):
                    continue
                # Fix 2026-10-18 (r6): auto-install de dependente (sys.executable -m pip).
                if _is_self_pip_install(line_txt_ci):
                    continue

            # Fix 2026-10-18 (lot r6): match intr-un string de PROZA (docstring, text
            # de ajutor CLI) nu e vulnerabilitate — dovedit pe clike (4 din 11).
            if pattern_def["type"] in ("command_injection", "eval_usage", "path_traversal"):
                line_txt_prose = lines[line_no - 1] if line_no - 1 < len(lines) else ""
                if _in_prose_string(line_txt_prose, match.group()):
                    continue

            # Fix 2026-10-11: PRAGMA/DDL nu se parametrizeaza (nu e injectabil prin concat).
            # Fix 2026-10-13: DDL scris pe 2 linii ("ALTER TABLE " +
            #   "users ADD COLUMN ...") — verificam fereastra linia curenta + cea precedenta,
            #   altfel concatenarea pe continuare scapa filtrul si iese FP.
            if pattern_def["type"].startswith("sql_injection"):
                lo = max(0, line_no - 2)
                hi = min(len(lines), line_no + 1)
                # Fix 2026-10-16: inclus si linia URMATOARE — DDL-ul (ALTER TABLE)
                # poate fi pe linia urmatoare fata de `conn.execute(` (FP dovedit).
                line_txt = " ".join(lines[lo:hi])
                if re.search(r'\b(PRAGMA|ALTER\s+TABLE|CREATE\s+TABLE|DROP\s+TABLE)\b', line_txt, re.IGNORECASE):
                    continue

            code_key = (pattern_def["type"], line_no)
            if pattern_def["type"] in ("sql_injection_concat", "sql_injection_format") and code_key in matched_lines_code:
                continue
            matched_lines_code.add(code_key)

            col = match.start() - code[:match.start()].rfind('\n') - 1
            if col < 0:
                col = 0

            findings.append(Finding(
                type=pattern_def["type"],
                severity=pattern_def["severity"],
                line=line_no,
                column=max(col, 0),
                match=redact_match(match.group(), pattern_def["type"]),
                description=pattern_def["description"],
                confidence=pattern_def["confidence"],
            ))

    # Deduplicate by (type, line, column) — 2 secrete DISTINCTE pe aceeasi linie
    # trebuie raportate amandoua (fix 2026-09-26; inainte cheia era (type, line)).
    seen = set()
    unique = []
    for f in findings:
        key = (f.type, f.line, f.column)
        if key not in seen:
            seen.add(key)
            unique.append(f)

    # Sortare pe RANG de severitate (nu alfabetic: 'low' < 'medium' era gresit).
    unique.sort(key=lambda f: (f.line, SEVERITY_RANK.get(f.severity, 9)))
    return [asdict(f) for f in unique]


def scan_file(filepath: str) -> dict:
    """Scaneaza un fisier si returneaza rezultatul."""
    with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
        code = f.read()
    findings = scan_code(code, os.path.basename(filepath))
    return {
        "file": os.path.basename(filepath),
        "findings": findings,
        "total": len(findings),
        "summary": {
            "critical": sum(1 for f in findings if f["severity"] == "critical"),
            "high": sum(1 for f in findings if f["severity"] == "high"),
            "medium": sum(1 for f in findings if f["severity"] == "medium"),
            "low": sum(1 for f in findings if f["severity"] == "low"),
        }
    }


# ─── CLI ────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        result = scan_file(sys.argv[1])
        print(json.dumps(result, indent=2))
    else:
        # Default test
        print("Scanning...")
        print(json.dumps(scan_file(__file__), indent=2))
