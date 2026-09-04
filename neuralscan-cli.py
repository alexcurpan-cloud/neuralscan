#!/usr/bin/env python3
"""
neuralscan-cli.py — NeuralScan scanner local, 100% standalone.
Zero dependinte externe (doar Python 3.8+). Fara server, fara deploy, fara API calls.

Folosire:
    python3 neuralscan-cli.py fisier.py            # scaneaza 1 fisier
    python3 neuralscan-cli.py director/            # scaneaza un folder (py/js/ts/html/json/sql/sh...)
    python3 neuralscan-cli.py fisier.py --json     # output brut JSON (pt pipe in alte unelte)
    python3 neuralscan-cli.py fisier.py -v         # verbose: arata si codul liniei suspecte

Exit code: 0 = niciun finding | 1 = findings gasite | 2 = eroare
"""
import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "src"))

from scanner import scan_code  # noqa: E402
from translator import translate_findings  # noqa: E402

EXTENSIONS = {".py", ".js", ".ts", ".jsx", ".tsx", ".html", ".htm", ".json", ".sql", ".sh", ".rb", ".php"}
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build", ".pytest_cache"}
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
SEV_ICON = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵"}


def _read(p):
    with open(p, encoding="utf-8", errors="replace") as f:
        return f.read()


def collect(path):
    """Returneaza [(path, code)] — un fisier sau toate fisierele dintr-un folder."""
    if os.path.isfile(path):
        return [(path, _read(path))]
    if os.path.isdir(path):
        out = []
        for root, dirs, names in os.walk(path):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            for n in sorted(names):
                if os.path.splitext(n)[1].lower() in EXTENSIONS:
                    p = os.path.join(root, n)
                    try:
                        out.append((p, _read(p)))
                    except Exception as e:
                        print(f"  [!] nu pot citi {p}: {e}", file=sys.stderr)
        return out
    raise FileNotFoundError(f"Nu exista: {path}")


def main():
    ap = argparse.ArgumentParser(description="NeuralScan CLI — scaneaza cod pentru vulnerabilitati. Local, gratis.")
    ap.add_argument("target", help="fisier sau director de scanat")
    ap.add_argument("--json", action="store_true", help="output brut JSON")
    ap.add_argument("-v", "--verbose", action="store_true", help="afiseaza si linia de cod suspecta")
    args = ap.parse_args()

    try:
        files = collect(args.target)
    except FileNotFoundError as e:
        print(f"EROARE: {e}", file=sys.stderr)
        return 2

    if not files:
        print(f"EROARE: niciun fisier scanabil gasit in: {args.target}", file=sys.stderr)
        return 2

    results = []  # (path, code, findings)
    for path, code in files:
        try:
            findings = scan_code(code, filename=os.path.basename(path))
        except Exception as e:
            print(f"  [!] esec scanare {path}: {e}", file=sys.stderr)
            continue
        for f in findings:
            f["file"] = path
        results.append((path, code, findings))

    all_findings = [f for _, _, fs in results for f in fs]

    if args.json:
        print(json.dumps(all_findings, indent=1, ensure_ascii=False))
        return 1 if all_findings else 0

    print(f"NeuralScan — {len(results)} fisier(e), {len(all_findings)} finding(s)\n")

    for path, code, finds in sorted(results, key=lambda r: r[0]):
        if not finds:
            continue
        ordered = sorted(finds, key=lambda x: SEV_ORDER.get(x.get("severity", "low"), 9))
        print(f"📄 {path}")
        for f in ordered:
            icon = SEV_ICON.get(f.get("severity", "?"), "⚪")
            line = f.get("line", "?")
            print(f"  {icon} [{str(f.get('severity','?')).upper()}] {f.get('type','?')} — linia {line}")
            if args.verbose:
                src_lines = code.splitlines()
                if isinstance(line, int) and 0 < line <= len(src_lines):
                    print(f"      > {src_lines[line - 1].strip()[:120]}")
        reports = translate_findings(ordered, code=code, use_llm=False)
        for r in reports:
            print(f"     💡 {r.get('titlu','')}")
            expl = (r.get("explicatie") or "").strip()
            if expl:
                print(f"        {expl[:200]}")
            fix = (r.get("fix_prompt") or "").strip()
            if fix:
                print(f"        🔧 {fix[:200]}")
        print()

    if not all_findings:
        print("✅ Curat — niciun pattern suspect gasit.")
    else:
        sev_counts = {}
        for f in all_findings:
            sev_counts[f.get("severity", "?")] = sev_counts.get(f.get("severity", "?"), 0) + 1
        summary = ", ".join(f"{SEV_ICON.get(s, '')} {s}: {c}" for s, c in sorted(sev_counts.items()))
        print(f"⚠️  {len(all_findings)} finding(s): {summary}")

    return 1 if all_findings else 0


if __name__ == "__main__":
    sys.exit(main())
