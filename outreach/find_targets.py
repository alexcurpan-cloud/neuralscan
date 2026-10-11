#!/usr/bin/env python3
"""
find_targets.py — gaseste repo-uri publice construite cu AI (Lovable/Bolt/Cursor),
le scaneaza local (zero cost, cod public) si scoate finding-uri REALE + contactul owner-ului.

Scop: outreach personalizat cu DOVADA (nu spam generic). Consuma: GitHub API public + scanner local.

Folosire:
  python3 find_targets.py --max 12 --out targets.json
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request
import urllib.parse
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent                     # neuralscan/
sys.path.insert(0, str(ROOT / "src"))
from scanner import scan_code, is_lockfile  # noqa: E402

GH = "https://api.github.com"
UA = {"User-Agent": "neuralscan-outreach", "Accept": "application/vnd.github+json"}

QUERIES = [
    "lovable.dev in:readme",
    "\"built with lovable\" in:readme",
    "\"bolt.new\" in:readme",
    "\"generated with cursor\" in:readme",
    "lovable clone in:name",
]

SCAN_EXT = {".py", ".js", ".ts", ".tsx", ".jsx", ".html", ".json", ".sql", ".sh", ".env"}
SKIP_DIRS = {".git", "node_modules", "dist", "build", ".next", "vendor", "__pycache__", "coverage"}
SKIP_FILE_RE = re.compile(r"(test|spec|example|sample|mock|fixture)", re.I)
SERIOUS = {"critical", "high"}


def api(url):
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read().decode())


def search(queries, per_query=8):
    seen, out = set(), []
    for q in queries:
        try:
            d = api(f"{GH}/search/repositories?q={urllib.parse.quote(q)}&sort=updated&per_page={per_query}")
        except Exception as e:
            print(f"  [search err] {q}: {e}")
            continue
        for r in d.get("items", []):
            fn = r["full_name"]
            if fn in seen or r.get("fork"):
                continue
            if r.get("size", 0) > 25000:      # >25MB = prea mare pt scan rapid
                continue
            seen.add(fn)
            out.append(r)
    return out


def owner_email(repo):
    try:
        commits = api(f"{GH}/repos/{repo}/commits?per_page=3")
    except Exception:
        return None
    for c in commits:
        email = (c.get("commit", {}).get("author", {}) or {}).get("email") or ""
        if email and "noreply" not in email and "github" not in email.lower():
            return email
    return None


def scan_repo(repo, tmp):
    url = f"https://github.com/{repo}.git"
    dst = Path(tmp) / repo.replace("/", "__")
    try:
        subprocess.run(["git", "clone", "--depth", "1", "-q", url, str(dst)],
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
            for fd in scan_code(code, rel):
                if fd.get("severity") in SERIOUS:
                    findings.append({
                        "file": rel, "line": fd.get("line"),
                        "severity": fd.get("severity"),
                        "type": fd.get("type") or fd.get("rule") or fd.get("pattern_type"),
                        "match": (fd.get("match") or fd.get("matched") or "")[:60],
                    })
    shutil.rmtree(dst, ignore_errors=True)
    return findings, None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--max", type=int, default=12, help="max repo-uri scanate")
    ap.add_argument("--out", default=str(HERE / "targets.json"))
    args = ap.parse_args()

    cands = search(QUERIES)
    print(f"Candidati gasiti: {len(cands)} (scanez max {args.max})")
    results, scanned = [], 0
    with tempfile.TemporaryDirectory() as tmp:
        for r in cands:
            if scanned >= args.max:
                break
            repo = r["full_name"]
            if (r.get("stargazers_count") or 0) > 800:
                continue
            scanned += 1
            findings, err = scan_repo(repo, tmp)
            if err:
                print(f"  [{scanned}] {repo}: {err}")
                continue
            if not findings:
                print(f"  [{scanned}] {repo}: 0 findings serioase")
                continue
            email = owner_email(repo)
            print(f"  [{scanned}] {repo}: {len(findings)} findings | contact: {email or '—'}")
            results.append({
                "repo": repo, "url": f"https://github.com/{repo}",
                "stars": r.get("stargazers_count"), "language": r.get("language"),
                "findings": findings, "email": email,
            })
            time.sleep(1)

    Path(args.out).write_text(json.dumps(results, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\nSalvat: {args.out} — {len(results)} repo-uri cu findings serioase")
    for r in results:
        t = ", ".join(sorted({f["type"] for f in r["findings"] if f["type"]}))
        print(f"  • {r['repo']} — {len(r['findings'])} findings [{t}] — {r['email'] or 'fara email'}")


if __name__ == "__main__":
    main()
