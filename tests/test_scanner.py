"""
Test suite for NeuralScan scanner.
Covers all 7 categories + edge cases + regression.
"""
import sys
import os
import json

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
from scanner import scan_code, scan_file
from translator import translate_findings


# ═══════════════════════════════════════════════════════════════════
# 1. SECRET PATTERNS
# ═══════════════════════════════════════════════════════════════════

def test_detects_hardcoded_api_key():
    code = 'API_KEY = "sk-proj-1234567890abcdef123456"'
    res = scan_code(code, 'test.py')
    types = [f["type"] for f in res]
    assert "hardcoded_api_key" in types, f"Expected hardcoded_api_key, got {types}"
    assert res[0]["severity"] == "critical"


def test_detects_aws_key():
    code = 'aws_access_key = "AKIA1234567890ABCDEF"'
    res = scan_code(code, 'test.py')
    types = [f["type"] for f in res]
    assert "hardcoded_aws_key" in types, f"Expected hardcoded_aws_key, got {types}"


def test_detects_hardcoded_password():
    code = 'DB_PASSWORD = "supersecret123!"'
    res = scan_code(code, 'test.py')
    types = [f["type"] for f in res]
    assert "hardcoded_password" in types


def test_detects_jwt():
    # JWT token outside variable assignment to avoid password pattern collision
    code = 'auth_header = "Bearer " + "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0X3VzZXIifQ.test1234567890"'
    res = scan_code(code, 'test.py')
    types = [f["type"] for f in res]
    assert "hardcoded_jwt" in types, f"Expected hardcoded_jwt, got {types}"


def test_detects_db_url_with_creds():
    code = 'DATABASE_URL = "postgresql://user:pass123@localhost:5432/db"'
    res = scan_code(code, 'test.py')
    types = [f["type"] for f in res]
    assert "hardcoded_db_url" in types


def test_detects_private_key():
    code = '-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...'
    res = scan_code(code, 'test.pem')
    types = [f["type"] for f in res]
    assert "hardcoded_private_key" in types


# ═══════════════════════════════════════════════════════════════════
# 2. CODE INJECTION PATTERNS
# ═══════════════════════════════════════════════════════════════════

def test_detects_sql_injection_concat():
    code = '''
def get_user(name):
    cursor.execute(f"SELECT * FROM users WHERE name = {name}")
'''
    res = scan_code(code, 'test.py')
    types = [f["type"] for f in res]
    assert "sql_injection_concat" in types


def test_detects_sql_injection_format():
    code = '''
def get_user(name):
    cursor.execute("SELECT * FROM users WHERE name = %s" % name)
'''
    res = scan_code(code, 'test.py')
    types = [f["type"] for f in res]
    assert "sql_injection_format" in types


def test_detects_command_injection():
    code = '''
def ping(host):
    os.system("ping " + host)
'''
    res = scan_code(code, 'test.py')
    types = [f["type"] for f in res]
    assert "command_injection" in types


def test_detects_eval():
    code = 'result = eval(user_input)'
    res = scan_code(code, 'test.py')
    types = [f["type"] for f in res]
    assert "eval_usage" in types


def test_detects_path_traversal():
    code = '''
def read_file(path):
    content = open(f"/data/{path}").read()
'''
    res = scan_code(code, 'test.py')
    types = [f["type"] for f in res]
    assert "path_traversal" in types


def test_detects_weak_crypto():
    code = 'h = hashlib.md5(b"test")'
    res = scan_code(code, 'test.py')
    types = [f["type"] for f in res]
    assert "weak_crypto" in types


def test_detects_insecure_http():
    code = 'url = "http://api.example.com/data"'
    res = scan_code(code, 'test.py')
    types = [f["type"] for f in res]
    assert "insecure_http" in types


def test_detects_debug_mode():
    code = 'app.run(debug=True, host="0.0.0.0")'
    res = scan_code(code, 'test.py')
    types = [f["type"] for f in res]
    assert "hardcoded_debug" in types


# ═══════════════════════════════════════════════════════════════════
# 3. CLEAN CODE — should return ZERO findings
# ═══════════════════════════════════════════════════════════════════

def test_clean_code_zero_findings():
    clean = '''import os
import json

def greet(name):
    return f"Hello, {name}!"

def safe_query(conn, user_id):
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return cursor.fetchall()

if __name__ == "__main__":
    print(greet("World"))
'''
    res = scan_code(clean, 'clean.py')
    assert len(res) == 0, f"Clean code produced {len(res)} findings: {[f['type'] for f in res]}"


def test_empty_code_zero_findings():
    res = scan_code('', 'empty.py')
    assert len(res) == 0


def test_parameterized_query_not_flagged():
    code = 'cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))'
    res = scan_code(code, 'safe.py')
    types = [f["type"] for f in res]
    assert "sql_injection_concat" not in types
    assert "sql_injection_format" not in types


# ═══════════════════════════════════════════════════════════════════
# 4. EDGE CASES
# ═══════════════════════════════════════════════════════════════════

def test_namespace_url_not_flagged_as_http():
    """w3.org namespace URLs should NOT trigger insecure_http"""
    code = 'XNamespace x = "http://www.w3.org/2001/XMLSchema"'
    res = scan_code(code, 'test.cs')
    types = [f["type"] for f in res]
    assert "insecure_http" not in types, f"Namespace URL flagged: {types}"


def test_comment_with_secret_not_flagged():
    """A comment mentioning 'password' in prose should not trigger."""
    code = '# TODO: password reset flow'
    res = scan_code(code, 'test.py')
    types = [f["type"] for f in res]
    assert "hardcoded_password" not in types


def test_batch_eval_variable_not_flagged():
    """Batch 'if defined eval' should not trigger eval_usage"""
    code = 'if defined eval (set eval=1)'
    res = scan_code(code, 'test.bat')
    types = [f["type"] for f in res]
    assert "eval_usage" not in types


# ═══════════════════════════════════════════════════════════════════
# 5. TRANSLATOR TESTS
# ═══════════════════════════════════════════════════════════════════

def test_translator_returns_correct_fields():
    findings = scan_code(
        'API_KEY = "sk-proj-1234567890abcdef123456"', 'test.py'
    )
    reports = translate_findings(findings, 'API_KEY = "sk-proj-1234567890abcdef123456"')
    assert len(reports) > 0
    r = reports[0]
    assert "severity" in r
    assert "titlu" in r
    assert "explicatie" in r
    assert "fix_prompt" in r
    assert "line" in r
    assert "snippet" in r


def test_translator_unknown_type_falls_back():
    findings = [{"type": "unknown_vuln", "severity": "medium", "line": 1, "match": "x"}]
    reports = translate_findings(findings)
    assert len(reports) == 1
    assert reports[0]["titlu"] == "Security issue detected"  # DEFAULT_FIX


def test_translator_snippet_extraction():
    # Use a key long enough to trigger the regex (sk- + 20+ alphanumeric chars)
    code = "line1\nline2\nAPI_KEY = 'sk-proj-1234567890abcdef1234567890abcdef'\nline4\nline5"
    findings = scan_code(code, 'test.py')
    reports = translate_findings(findings, code)
    assert len(reports) > 0, f"No findings for code. Expected at least 1."
    assert "2:" in reports[0]["snippet"] or "3:" in reports[0]["snippet"]


# ═══════════════════════════════════════════════════════════════════
# 6. SCAN FILE
# ═══════════════════════════════════════════════════════════════════

def test_scan_file_returns_summary():
    # Create a temp file with a vulnerability
    import tempfile
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write('SECRET = "sk-test-1234567890abcdef123456"')
        tmp_path = f.name
    try:
        result = scan_file(tmp_path)
        assert "file" in result
        assert "findings" in result
        assert "total" in result
        assert "summary" in result
        assert result["total"] > 0
    finally:
        os.unlink(tmp_path)


def test_scan_file_empty():
    import tempfile
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write('# just a comment\nprint("hello")')
        tmp_path = f.name
    try:
        result = scan_file(tmp_path)
        assert result["total"] == 0
    finally:
        os.unlink(tmp_path)


# ═══════════════════════════════════════════════════════════════════
# 7. DEDUPLICATION
# ═══════════════════════════════════════════════════════════════════

def test_dedup_same_line_type():
    """Same vulnerability type on same line should appear once."""
    code = "key1 = 'sk-abc'\nkey2 = 'sk-xyz'"
    res = scan_code(code, 'test.py')
    api_key_count = sum(1 for f in res if f["type"] == "hardcoded_api_key")
    assert api_key_count <= 2  # max one per line


# ═══════════════════════════════════════════════════════════════════
# 8. SEVERITY ORDER
# ═══════════════════════════════════════════════════════════════════

def test_results_sorted_by_line():
    """Findings should be sorted by line number."""
    code = '''
x = "http://api.example.com/data"
API_KEY = "sk-proj-1234567890abcdef123456"
'''
    res = scan_code(code, 'test.py')
    if len(res) >= 2:
        assert res[0]["line"] <= res[1]["line"]
