"""Regresii din lotul r6 (2026-10-18): fals-pozitive prinse pe repo-uri reale.

Toate cazurile de mai jos au fost findings 'critical/high' raportate pe repo-uri
publice si verificate manual ca FALSE-POZITIVE.
"""
from src.scanner import scan_code


def _types(code, filename="f.py"):
    return {f["type"] for f in scan_code(code, filename)}


def test_identifier_is_not_secret():
    # clike: SERVICE_TOKEN_SECRET = 'clike.serviceToken' = nume de cheie in SecretStorage
    assert "hardcoded_password" not in _types(
        "const SERVICE_TOKEN_SECRET = 'clike.serviceToken';\n", "service-auth.js")


def test_ui_theme_rule_is_not_secret():
    # Autopilot: reguli de syntax highlighting, nu parole
    assert "hardcoded_password" not in _types(
        '{ token: "metatag", foreground: "FF9F0A" },\n')


def test_docstring_is_not_vulnerability():
    # clike: subprocess.run(shell=True) mentionat intr-un docstring
    code = 'def f():\n    """subprocess.run(shell=True) that stops the process group on timeout."""\n    return 1\n'
    assert "command_injection" not in _types(code)


def test_prose_help_string_is_not_eval():
    # clike: eval (roadmap §3) intr-un text de ajutor CLI
    code = 'ap.add_argument("--auto-eval", type=int, default=0, help="KIT repair cycles after a failed eval (roadmap 3)")\n'
    assert "eval_usage" not in _types(code)


def test_self_pip_install_is_not_command_injection():
    # smart-hebrew-transcriber: auto-install de dependente
    code = 'os.system(f"{sys.executable} -m pip install sounddevice numpy -q")\n'
    assert "command_injection" not in _types(code)


def test_real_secret_still_reported():
    # control: fix-urile nu reduc recall-ul pe secrete reale
    assert "hardcoded_api_key" in _types('OPENAI_API_KEY = "sk-aBcD1234eFgH5678iJkL9012mNoP3456"\n')


def test_real_command_injection_still_reported():
    # control: os.system cu interpolare reala ramane raportat
    assert "command_injection" in _types('os.system(f"ping -c 4 {host}")\n')
