#!/usr/bin/env python3
"""
find_targets_secrets.py — gaseste REPO-URI PUBLICE cu SECRETE REALE hardcodate
(clasa dovedita ca singura care produce findings reale: r5 + 9-Oct + r6).

De ce exista: runda r6 (18-Oct) a dovedit ca pattern-urile de cod (SQLi/cmd/path)
sunt zgomot pe repo-uri AI-built, iar secretele hardcodate sunt semnalul real.
Cauta prin GitHub CODE SEARCH (cere token), nu prin lista ghicta manual.

Folosire:
  export GITHUB_TOKEN=ghp_...           # sau pune "github_token" in .secrets.json
  python3 find_targets_secrets.py --dry-run          # arata interogarile, nu cheama API
  python3 find_targets_secrets.py --max 8 --out targets_secrets.json

Cost: zero LLM. Doar GitHub API + scanner local.
"""
import argparse
import base64
import json
import os
import re
import sys
import tempfile
import time
import urllib.parse
import urllib.request
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))
from find_targets import CLONE_RE, GH, scan_repo  # noqa: E402

SECRETS_FILES = [
    ".secrets.json",
    "memory/shared-knowledge/.secrets.json",
    "neuralscan/.secrets.json",
]

# Interogari tintite pe SECRETE (nu pe pattern-uri de cod).
# Toate cer un singur tipar per cautare — code search nu accepta OR in interiorul unui termen.
QUERIES = [
    # Chei Stripe live — tipar specific (sk_live_51...), putine rezultate, semnal mare
    '"sk_live_51" in:file',
    # Chei OpenAI de proiect (sk-proj-...) in cod de aplicatie
    '"sk-proj-" in:file language:python',
    '"sk-proj-" in:file language:typescript',
    # Token-uri bot Slack
    '"xoxb-" in:file language:python',
    # Supabase service_role in fisiere de config reale (nu .env.example)
    '"service_role" in:file language:javascript',
    # Google API keys in cod TS/JS
    '"AIzaSy" in:file language:typescript',
]

# Semnale ca repo-ul e construit cu AI (pozitionarea produsului).
AI_RE = re.compile(r"(lovable|bolt\.new|cursor|vibe[- ]?cod|replit|base44|same\.dev|"
                   r"claude code|generated with ai|built with ai)", re.I)

SKIP_FILE_RE = re.compile(r"(test|spec|example|sample|mock|fixture|\.md$)", re.I)
SKIP_PATH_RE = re.compile(r"(seed_|_seed|migrat|demo_data|fixtures?/)", re.I)

# --- Filtru de VALOARE (runda 2, 19-Oct): scannerul confunda numele variabilei cu valoarea.
# Toate cele 5 findings verificate manual au fost FP: env var names, chei Firebase publice,
# constante i18n. Un finding trece mai departe doar daca LINIA contine un secret real.
PROVIDER_PATTERNS = [
    ("stripe_live", re.compile(r"sk_live_[0-9A-Za-z]{16,}")),
    ("stripe_test", re.compile(r"sk_test_[0-9A-Za-z]{16,}")),
    ("openai", re.compile(r"sk-(proj-)?[A-Za-z0-9_-]{32,}")),
    ("anthropic", re.compile(r"sk-ant-[A-Za-z0-9_-]{20,}")),
    ("slack_bot", re.compile(r"xoxb-\d{8,}-[0-9A-Za-z-]{10,}")),
    ("github_pat", re.compile(r"gh[pous]_[A-Za-z0-9]{30,}")),
    ("telegram_bot", re.compile(r"\d{8,10}:[A-Za-z0-9_-]{35}")),
    ("aws_key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("private_key_block", re.compile(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----")),
]
# Ce NU e secret, oricat de mult seamana:
NOT_SECRET_RES = [
    re.compile(r"\bAIza[0-9A-Za-z_-]{30,}"),                  # cheie Firebase/Google = publica prin design
    re.compile(r"['\"][A-Z][A-Z0-9_]{3,}['\"]"),            # 'OPENAI_API_KEY' = nume, nu valoare
    re.compile(r"process\.env|os\.environ|os\.getenv|getenv\("),  # citire din env, nu secret hardcodat
    re.compile(r"auth/[a-z-]+"),                              # coduri de eroare Firebase
    re.compile(r"\b[A-Z][A-Z0-9_]{2,}\b\s*[:=]\s*['\"][a-z0-9_.\-]{1,20}['\"]"),  # CONSTANTA: 'valoare-mica'
]


def is_real_secret(line, path, ftype):
    """True doar daca linia contine o valoare de tip secret real, nu un nume/constant."""
    low = path.lower()
    if "google-services.json" in low or "firebase" in low or low.endswith(".env.example"):
        return False
    for pat in NOT_SECRET_RES:
        if pat.search(line):
            return False
    for _, pat in PROVIDER_PATTERNS:
        if pat.search(line):
            return True
    # parole hardcodate: acceptam doar valoare lunga, fara spatii, care nu arata ca identificator
    if ftype in ("hardcoded_password", "hardcoded_jwt", "hardcoded_db_url"):
        m = re.search(r"['\"]([^'\"\s]{10,})['\"]", line)
        if m:
            val = m.group(1)
            if val.upper() == val and "_" in val:   # ARATA_ASA = nume de constanta
                return False
            if re.search(r"(pass|parol|secret|admin|root|token|changeme|placeholder)", val, re.I):
                return True
    return False

# Runda 1 (19-Oct): cele 230 de "findings" de pe un repo erau din examples/ si seed_demo_data.py.
# Scannerul filtra doar NUMELE fisierului, nu folderul — de aici zgomotul.
SKIP_DIRS = {".git", "node_modules", "dist", "build", ".next", "vendor", "__pycache__",
             "coverage", "examples", "example", "docs", "doc", "demo", "demos",
             "samples", "sample", "fixtures", "test", "tests", "e2e", "benchmarks"}

def token():
    t = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if t:
        return t.strip()
    for rel in SECRETS_FILES:
        p = ROOT.parent / rel
        if not p.exists():
            continue
        try:
            d = json.loads(p.read_text())
        except Exception:
            continue
        for k in ("github_token", "github_pat", "GITHUB_TOKEN"):
            if d.get(k):
                return str(d[k]).strip()
    return None


def headers(tok=None):
    h = {"User-Agent": "neuralscan-outreach", "Accept": "application/vnd.github+json"}
    if tok:
        h["Authorization"] = "Bearer " + tok
    return h


def api(url, tok=None):
    req = urllib.request.Request(url, headers=headers(tok))
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read().decode())


def code_search(q, tok, per_page=20):
    """Cauta in cod; intoarce repo-urile unice (full_name, stars, size, fork)."""
    url = f"{GH}/search/code?q={urllib.parse.quote(q)}&per_page={per_page}"
    try:
        d = api(url, tok)
    except Exception as e:
        print(f"  [code search err] {q}: {e}")
        return []
    repos, seen = [], set()
    for it in d.get("items", []):
        r = it.get("repository") or {}
        fn = r.get("full_name")
        if not fn or fn in seen:
            continue
        seen.add(fn)
        repos.append({
            "full_name": fn,
            "stargazers_count": r.get("stargazers_count", 0),
            "size": r.get("size", 0),
            "fork": r.get("fork", False),
            "hit_path": it.get("path"),
            "query": q,
        })
    return repos


def readme(repo, tok):
    try:
        d = api(f"{GH}/repos/{repo}/readme", tok)
        return base64.b64decode(d.get("content", "")).decode("utf-8", "ignore")[:20000]
    except Exception:
        return ""


def owner_email(repo, tok):
    try:
        commits = api(f"{GH}/repos/{repo}/commits?per_page=3", tok)
    except Exception:
        return None
    for c in commits:
        email = (c.get("commit", {}).get("author", {}) or {}).get("email") or ""
        # .local / .invalid / noreply = adrese care nu exista in realitate
        if email and "noreply" not in email and "github" not in email.lower() \
                and not re.search(r"\.(local|invalid|example|test)$", email, re.I):
            return email
    return None


def scan_repo_clean(repo, tmp, tok=None):
    """Clone + scan, cu skip pe foldere de exemple/docs (runda 1 a aratat ca acolo e zgomotul)."""
    import shutil
    import subprocess
    from find_targets import SCAN_EXT, SERIOUS
    from scanner import is_lockfile, scan_code  # noqa: F401

    dst = Path(tmp) / repo.replace("/", "__")
    try:
        subprocess.run(["git", "clone", "--depth", "1", "-q",
                        f"https://github.com/{repo}.git", str(dst)],
                       check=True, timeout=120, capture_output=True)
    except Exception as e:
        return None, f"clone: {e}"

    findings = []
    for dirpath, dirnames, files in os.walk(dst):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for f in files:
            p = Path(dirpath) / f
            if p.suffix.lower() not in SCAN_EXT or is_lockfile(f) or SKIP_FILE_RE.search(f):
                continue
            try:
                code = p.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue
            if not code.strip():
                continue
            rel = str(p.relative_to(dst))
            if SKIP_PATH_RE.search(rel):
                continue
            lines = code.splitlines()
            for fd in scan_code(code, rel):
                if fd.get("severity") not in SERIOUS:
                    continue
                ftype = fd.get("type") or fd.get("rule") or ""
                ln = fd.get("line")
                raw = lines[ln - 1] if isinstance(ln, int) and 0 < ln <= len(lines) else ""
                if not is_real_secret(raw, rel, ftype):
                    continue
                findings.append({
                    "file": rel, "line": ln,
                    "severity": fd.get("severity"),
                    "type": ftype,
                    "match": (fd.get("match") or "")[:60],
                    "raw": raw.strip()[:120],
                })
    shutil.rmtree(dst, ignore_errors=True)
    return findings, None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--max", type=int, default=8, help="max repo-uri scanate")
    ap.add_argument("--out", default=str(HERE / "targets_secrets.json"))
    ap.add_argument("--dry-run", action="store_true", help="afiseaza interogarile, fara API")
    ap.add_argument("--no-ai-filter", action="store_true", help="nu cere semnal AI in README")
    args = ap.parse_args()

    if args.dry_run:
        print(f"{len(QUERIES)} interogari code search pregatite:")
        for q in QUERIES:
            print("  •", q)
        print("\nToken gasit:", "DA" if token() else "NU (pune github_token in .secrets.json)")
        return

    tok = token()
    if not tok:
        print("LIPSA TOKEN. Pune `github_token` in .secrets.json sau export GITHUB_TOKEN=...")
        print("Fara token, GitHub code search nu raspunde (401).")
        sys.exit(2)

    cands, seen = [], set()
    for q in QUERIES:
        print(f"[caut] {q}")
        for r in code_search(q, tok):
            fn = r["full_name"]
            if fn in seen or r["fork"] or r["size"] > 25000 or CLONE_RE.search(fn):
                continue
            if r["stargazers_count"] > 800:
                continue
            seen.add(fn)
            cands.append(r)
        time.sleep(2)  # rate limit prietenos (30/min autentificat)

    print(f"\nCandidati unici: {len(cands)}")
    results, scanned = [], 0
    with tempfile.TemporaryDirectory() as tmp:
        for r in cands:
            if scanned >= args.max:
                break
            repo = r["full_name"]
            if not args.no_ai_filter:
                rm = readme(repo, tok)
                if not AI_RE.search(rm):
                    continue
            scanned += 1
            findings, err = scan_repo_clean(repo, tmp, tok)
            if err:
                print(f"  [{scanned}] {repo}: {err}")
                continue
            if not findings:
                print(f"  [{scanned}] {repo}: 0 findings serioase")
                continue
            email = owner_email(repo, tok)
            results.append({
                "repo": repo,
                "url": f"https://github.com/{repo}",
                "stars": r["stargazers_count"],
                "hit_path": r["hit_path"],
                "query": r["query"],
                "findings": findings,
                "email": email,
            })
            print(f"  [{scanned}] {repo}: {len(findings)} findings | contact: {email or '—'}")
            time.sleep(1)

    Path(args.out).write_text(json.dumps(results, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\nSalvat: {args.out} — {len(results)} repo-uri cu findings serioase")
    print("ATENTIE: fiecare finding se verifica MANUAL inainte de orice mesaj (Poarta 0).")


if __name__ == "__main__":
    main()
