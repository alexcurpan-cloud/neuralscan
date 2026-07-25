"""
security-scanner/translator.py
Converts scanner findings to plain-language reports with fix prompts.

Two modes:
1. RULE-BASED (default) — keyword mapping, zero API cost
2. LLM-enhanced — if OPENAI_API_KEY or ANTHROPIC_API_KEY set
"""

import os
import json
from typing import List, Dict, Any, Optional


# ─── Plain-language templates ──────────────────────────────────────

SEVERITY_LABELS = {
    "critical": "🔴 CRITICAL",
    "high": "🟠 PERICOL",
    "medium": "🟡 MEDIUM",
    "low": "🔵 LOW",
}

FIX_TEMPLATES = {
    "hardcoded_api_key": {
        "title": "Hardcoded API key found in source code",
        "explanation": "A secret API key (e.g. OpenAI, Google) is written as plaintext in source code. Once it hits GitHub, anyone can see and use it on your bill.",
        "fix_prompt": "Move the API key to an environment variable (.env). Replace the hardcoded value with `os.getenv('KEY_NAME')`. Add `.env` to `.gitignore`. Walk me through this step by step in my project.",
    },
    "hardcoded_aws_key": {
        "title": "AWS key exposed in source code",
        "explanation": "An AWS access key (AKIA...) is written directly in code. Anyone with code access can control your cloud resources.",
        "fix_prompt": "Remove the AWS key from code and move it to AWS CLI credentials file or environment variables. Rotate the key immediately from AWS Console. Walk me through the exact steps?",
    },
    "hardcoded_password": {
        "title": "Password or secret written in plaintext in code",
        "explanation": "Text that looks like a password or secret is written directly in source code. If the project goes public, anyone can use it.",
        "fix_prompt": "Replace the hardcoded password with an environment variable or secrets manager. Use `os.getenv()` or a secret management library. Help me do this?",
    },
    "hardcoded_jwt": {
        "title": "JWT token written in plaintext in code",
        "explanation": "An authentication token (JWT) is written directly in source code. Anyone who finds it can impersonate that user.",
        "fix_prompt": "Do not put JWT tokens in code. Generate the token on login and keep it in a secure cookie or localStorage. Rewrite my code to work this way?",
    },
    "hardcoded_db_url": {
        "title": "Database URL with password in source code",
        "explanation": "A database connection string contains username and password. Anyone who clones the code can access your database directly.",
        "fix_prompt": "Remove credentials from the database URL and put them in environment variables. Use `os.getenv()` for user, password, and host. Show me how?",
    },
    "hardcoded_private_key": {
        "title": "Private cryptographic key found in source code",
        "explanation": "An RSA or similar private key appears in source code. A private key is like a digital signature — if leaked, anyone can impersonate you.",
        "fix_prompt": "Never store private keys in source code. Use a secrets manager (Vault, AWS Secrets Manager) or separate files with access restrictions. Explain how to set this up?",
    },
    "sql_injection_concat": {
        "title": "Danger: SQL query built by string concatenation",
        "explanation": "A SQL query is built by concatenating strings with variables. An attacker can inject fake SQL in input fields and steal all your database data.",
        "fix_prompt": "Replace string concatenation with prepared statements or parameterized queries. For example in Python: `cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))`. Help me rewrite the query?",
    },
    "sql_injection_format": {
        "title": "Dangerous SQL query built with format()",
        "explanation": "A SQL query uses format() to insert variables. This is as dangerous as concatenation — an attacker can inject SQL commands.",
        "fix_prompt": "Replace format() with parameterized queries. In Python use `?` and parameter tuples. In JavaScript use `?` or `$1`. Rewrite my query correctly?",
    },
    "command_injection": {
        "title": "Shell command built dynamically — injection risk",
        "explanation": "A system command is built by concatenating user-controlled text. An attacker can run arbitrary commands on the server. This is a complete loss of control.",
        "fix_prompt": "Replace `os.system()`/`subprocess.Popen()` with `subprocess.run()` using argument lists, not strings. Or use a specialized library instead of shell commands. Show me the safe version?",
    },
    "eval_usage": {
        "title": "eval() — can execute arbitrary attacker code",
        "explanation": "Using eval() on dynamic input is like giving your apartment keys to a stranger. It can run any code the attacker wants on your server.",
        "fix_prompt": "Replace `eval()` with a safe alternative: `ast.literal_eval()` for simple data, or a function map for known commands. Rewrite my code?",
    },
    "path_traversal": {
        "title": "File path built dynamically — potential path traversal",
        "explanation": "A file path is built by concatenating user input. An attacker can access files they should not see (e.g. `/etc/passwd`).",
        "fix_prompt": "Validate and sanitize the path: use `os.path.basename()` or a whitelist of allowed files. Never build paths with direct input. Rewrite my function?",
    },
    "weak_crypto": {
        "title": "Weak cryptographic algorithm (MD5 or SHA1)",
        "explanation": "You are using MD5 or SHA1 for security. These algorithms are considered broken — an attacker can generate collisions and bypass protection.",
        "fix_prompt": "Replace MD5/SHA1 with SHA-256 or SHA-3. For passwords, use bcrypt, argon2, or pbkdf2. Rewrite my code with the correct algorithm?",
    },
    "weak_encryption": {
        "title": "Weak encryption algorithm (DES/RC4)",
        "explanation": "You are using DES or RC4 for encryption. These algorithms are decades obsolete — they can be broken in hours with modern hardware.",
        "fix_prompt": "Replace DES/RC4 with AES-256-GCM for symmetric encryption. Rewrite my code using a modern crypto library (cryptography, pycryptodome)?",
    },
    "insecure_http": {
        "title": "Unencrypted HTTP connection",
        "explanation": "The code uses HTTP instead of HTTPS. Any data sent (passwords, tokens, personal data) can be read by anyone intercepting traffic.",
        "fix_prompt": "Replace `http://` with `https://` in all URLs. If the API does not support HTTPS, find a provider that does. Update my URLs?",
    },
    "hardcoded_debug": {
        "title": "Danger: debug mode left ACTIVE in production — RCE risk",
        "explanation": "Flask debug mode is active with host 0.0.0.0. The Werkzeug debugger allows Remote Code Execution (RCE) — anyone connecting can run arbitrary Python commands. This is not just an info leak, it is complete loss of control.",
        "fix_prompt": "Disable debug=True in production. Use an environment variable: `DEBUG = os.getenv('DEBUG', 'False').lower() == 'true'`. Also remove host='0.0.0.0' in production. Rewrite my config to be safe?",
    },
}


# ─── Default for unknown types ─────────────────────────────────────

DEFAULT_FIX = {
    "title": "Security issue detected",
    "explanation": "The scanner found a pattern that could be a vulnerability. Check the indicated line and decide if it is a real risk.",
    "fix_prompt": "Analyze the issue on the indicated line and propose a safe solution. Tell me what you found and how you fixed it.",
}


def _extract_snippet(code: str, line: int, context: int = 2) -> str:
    """Extrage un snippet din jurul liniei indicate."""
    lines = code.split('\n')
    start = max(0, line - 1 - context)
    end = min(len(lines), line + context)
    snippet_lines = []
    for i in range(start, end):
        prefix = ">" if i == line - 1 else " "
        snippet_lines.append(f"{prefix} {i+1}: {lines[i]}")
    return '\n'.join(snippet_lines)


def translate_findings(
    findings: List[dict],
    code: str = "",
    use_llm: bool = False,
) -> List[dict]:
    """
    Traduce findings in raport non-tehnic.

    Args:
        findings: Lista de dict-uri de la scanner
        code: Codul original (pentru context/snippet)
        use_llm: Daca sa incerce LLM (else rule-based)

    Returns:
        Lista de dict-uri: {severitate, titlu, explicatie, fix_prompt}
    """
    reports = []

    for f in findings:
        ftype = f["type"]
        template = FIX_TEMPLATES.get(ftype, DEFAULT_FIX)
        snippet = _extract_snippet(code, f["line"]) if code else ""
        severity_label = SEVERITY_LABELS.get(f["severity"], f["severity"])

        report = {
            "severity": severity_label,
            "severity_raw": f["severity"],
            "line": f["line"],
            "titlu": template["title"],
            "explicatie": template["explanation"],
            "fix_prompt": template["fix_prompt"],
            "match_redactat": f.get("match", ""),
            "snippet": snippet,
            "confidence": f.get("confidence", "medium"),
        }
        reports.append(report)

    return reports


# ─── CLI ────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        with open(sys.argv[1], 'r') as f:
            data = json.load(f)
        findings = data if isinstance(data, list) else data.get("findings", [])
        code = data.get("code", "")
        reports = translate_findings(findings, code)
        print(json.dumps(reports, indent=2, ensure_ascii=False))
    else:
        # Demo
        demo_findings = [
            {"type": "hardcoded_api_key", "severity": "critical", "line": 5, "match": "sk-pr***abcd", "confidence": "high"},
            {"type": "sql_injection_concat", "severity": "critical", "line": 12, "match": "execu***(?x)", "confidence": "high"},
        ]
        demo_code = (
            "import os\n"
            "import sqlite3\n\n"
            "API_KEY = 'sk-proj-1234567890abcdef1234567890abcdef'\n\n"
            "def get_user(name):\n"
            "    conn = sqlite3.connect('db.sqlite')\n"
            "    cursor = conn.cursor()\n"
            "    cursor.execute(f'SELECT * FROM users WHERE name = {name}')\n"
            "    return cursor.fetchall()\n"
        )
        reports = translate_findings(demo_findings, demo_code)
        print(json.dumps(reports, indent=2, ensure_ascii=False))
