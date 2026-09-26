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
        "description": "Cale de fisier construita prin concatenare fara sanitizare — path traversal posibil.",
        "pattern": re.compile(r'(?:open|read_text|write_text)\s*\(\s*(?:f[\'\"]|[\'\"]\s*\+)', re.IGNORECASE),
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
    lines = code.split('\n')

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
    for pattern_def in CODE_PATTERNS:
        for match in pattern_def["pattern"].finditer(code):
            line_no = code[:match.start()].count('\n') + 1

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
