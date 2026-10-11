#!/usr/bin/env python3
"""
find_contacts.py — CONTACT ÎNTÂI: pentru fiecare țintă, găsește canale reale de contact
și verifică dacă sunt REACHABLE (fără să trimită nimic).

Surse (toate publice / gratuite):
  - git commits (author email) — din clone
  - GitHub /users/<owner> (nume, blog/site, twitter, email public)
  - MX lookup pe domeniul emailului (Cloudflare DoH — zero dependențe): domeniul poate primi mail?
  - verificare site (HTTP HEAD pe blogul din profil)

Output: contacts.json — fiecare țintă cu canale + verdict reachable.

Folosire:
  python3 find_contacts.py --targets targets.json --out contacts.json
  python3 find_contacts.py --emails a@x.com,b@y.com          # doar verificare MX
"""
import argparse
import json
import re
import subprocess
import sys
import urllib.request
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")
HERE = Path(__file__).resolve().parent
DOH = "https://cloudflare-dns.com/dns-query"


def mx_ok(domain):
    """Domeniul are înregistrare MX (poate primi email)? Fără să trimitem nimic."""
    try:
        req = urllib.request.Request(f"{DOH}?name={domain}&type=MX",
                                     headers={"Accept": "application/dns-json"})
        with urllib.request.urlopen(req, timeout=15) as r:
            d = json.loads(r.read().decode())
        return d.get("Status") == 0 and any(a.get("type") == 15 for a in d.get("Answer", []))
    except Exception:
        return None


def gh_user(owner):
    try:
        req = urllib.request.Request(f"https://api.github.com/users/{owner}",
                                     headers={"User-Agent": "neuralscan-outreach"})
        with urllib.request.urlopen(req, timeout=20) as r:
            return json.loads(r.read().decode())
    except Exception:
        return {}


def commit_emails(repo_dir, limit=5):
    try:
        out = subprocess.run(["git", "-C", str(repo_dir), "log", f"-{limit}", "--format=%ae|%an"],
                             capture_output=True, text=True, timeout=30).stdout
    except Exception:
        return []
    seen = []
    for line in out.strip().split("\n"):
        if "|" not in line:
            continue
        email, name = line.split("|", 1)
        if "noreply" in email or "github" in email.lower():
            continue
        if (email, name) not in seen:
            seen.append((email, name))
    return seen


def site_alive(url):
    if not url:
        return None
    if not url.startswith("http"):
        url = "http://" + url
    try:
        req = urllib.request.Request(url, method="HEAD",
                                     headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status < 500
    except Exception:
        return False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--targets", help="targets.json din find_targets")
    ap.add_argument("--clones", default="/home/alexmarian112/openclaw-workspace/.openclaw/tmp/outreach_check")
    ap.add_argument("--emails", help="lista de emailuri (verificare MX)")
    ap.add_argument("--out", default=str(HERE / "contacts.json"))
    args = ap.parse_args()

    if args.emails:
        for e in [x.strip() for x in args.emails.split(",") if x.strip()]:
            dom = e.split("@")[-1]
            print(f"{e:40s} MX={mx_ok(dom)}")
        return

    targets = json.load(open(args.targets, encoding="utf-8"))
    clones = Path(args.clones)
    out = []
    for t in targets:
        repo = t["repo"]
        owner = repo.split("/")[0]
        d = clones / repo.replace("/", "_")
        emails = commit_emails(d) if d.exists() else ([(t["email"], "")] if t.get("email") else [])
        gh = gh_user(owner)
        blog = gh.get("blog") or ""
        mails = []
        for email, name in emails:
            dom = email.split("@")[-1]
            mails.append({"email": email, "name": name, "mx": mx_ok(dom)})
        rec = {
            "repo": repo, "owner": owner,
            "owner_name": gh.get("name"), "owner_bio": (gh.get("bio") or "")[:120],
            "blog": blog, "twitter": gh.get("twitter_username"),
            "gh_email": gh.get("email"),
            "emails": mails, "site_alive": site_alive(blog),
        }
        rec["reachable"] = bool([m for m in mails if m["mx"]]) or bool(blog)
        out.append(rec)
        status = "REACHABLE" if rec["reachable"] else "NU"
        ch = ", ".join(m["email"] for m in mails) or (blog or "—")
        print(f"[{status}] {repo:44s} {ch}")

    Path(args.out).write_text(json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8")
    n = sum(1 for r in out if r["reachable"])
    print(f"\n{n}/{len(out)} cu canal de contact verificat -> {args.out}")


if __name__ == "__main__":
    main()
