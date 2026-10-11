#!/usr/bin/env python3
"""
NeuralScan Inbox Agent v0 — triage + raspuns automat pentru email-uri de client.

SCOP (de ce exista): blochează pe ADOPȚIE, nu pe cod. Fiecare email de la un
potențial client trebuie să primească răspuns în ore, nu în zile. Argus rezolvă
cazurile standard; Alex vorbește DOAR cu cele dificile/comerciale.

CONSUMĂ (nu construiește): AgentMail API (inbox existent) + DeepSeek (clasificare).
Zero dependențe noi (urllib + json).

Moduri:
  --fixtures FILE   offline, deterministic: clasifică un fișier de mesaje de test
  --live            fetch mesaje reale din AgentMail (received, neprocesate)
  --send            trimite răspunsurile marcate auto_send (implicit: doar draft)
  --limit N         max mesaje (default 20)
  --json            output JSON complet

Politica de rutare (impusă ÎN COD, nu doar de LLM):
  free_check / pricing / support  -> auto-draft; auto_send dacă nu există cuvinte de risc
  partnership / job / media       -> ESCALATE (Alex)
  difficult (legal/refund/amenințări/limbaj dur) -> ESCALATE (Alex)
  spam                            -> IGNORE
"""

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")

ROOT = Path(__file__).resolve().parent.parent.parent
CONFIG = ROOT / "skills" / "agent-inbox" / "inbox_config.json"
SECRETS = ROOT / ".secrets.json"
STATE = Path(__file__).resolve().parent / "state.json"

AGENTMAIL = "https://api.agentmail.to/v0"
DEEPSEEK = "https://api.deepseek.com/chat/completions"

# Cuvinte care NU se auto-trimit niciodată (risc comercial/legal) -> escaladare
RISK_WORDS = [
    "refund", "ramburs", "bani înapoi", "banii inapoi", "legal", "avocat", "lawyer",
    "gdpr", "leak", "scurgere", "breach", "hack", "compromis", "sue", "dat în judecată",
    "reclam", "ancpc", "protecția consumatorului", "m-ați", "v-am", "escrocherie", "fraud",
]

# Răspunsuri FIXE (deterministe) pentru cazurile standard. LLM-ul NU are voie să inventeze
# fluxuri de produs pentru emailuri trimise automat — doar clasifică și rezumă.
SITE = "https://neuralscan-production.up.railway.app"
TEMPLATES = {
    "free_check": (
        "Hi,\n\nThanks for reaching out. You can run a free scan right now at " + SITE + "/app "
        "— upload your project (zip) or paste the code you want checked. You get one static scan "
        "plus a plain-language summary report, free of charge.\n\n"
        "If you want deeper coverage afterwards, we offer unlimited static scans on Pro ($19/month) "
        "and manual deep scans for larger projects.\n\n"
        "Let me know if you hit any snags getting started.\n\n— NeuralScan"
    ),
    "pricing": (
        "Hi,\n\nThanks for reaching out. Pricing is simple:\n\n"
        "- Free: 1 static scan + summary report (run it at " + SITE + "/app)\n"
        "- Pro: $19/month — unlimited static scans\n"
        "- Deep scan: $49-99 — manual review by a human, for larger or more complex apps\n\n"
        "If you tell me a bit about your stack and what you want checked, I'll point you to the right option.\n\n— NeuralScan"
    ),
}

SYSTEM_PROMPT = """Ești asistentul de inbox al NeuralScan, un scanner de securitate pentru aplicații construite cu AI (Lovable/Bolt/Cursor).
Primești un email de la un potențial client. Îl clasifici și, pentru cazurile standard, scrii un răspuns scurt.

Categorii:
- free_check: vrea o scanare gratuită / întreabă cum funcționează
- pricing: întreabă preț / planuri
- support: problemă tehnică cu tool-ul / nu-i merge ceva
- partnership: colaborare, afiliere, integrare, investitor, media/presă
- difficult: nemulțumit, cere bani înapoi, amenință legal, limbaj dur, caz neclar/complex
- spam: reclame, phishing, irelevant

Context de produs (folosește-l în răspuns când e cazul, NU inventa altceva):
- Free: 1 scanare statică + raport sumar, în UI la /app
- Pro: $19/lună — scanări statice nelimitate
- Deep scan (manual, cu Strix): $49-99, credit separat, oferit de om
- Site: https://neuralscan-production.up.railway.app
- Răspunsurile se scriu în engleză (clienții sunt internaționali), 2-5 propoziții, ton profesionist și direct.

Întoarce STRICT JSON:
{
  "category": "free_check|pricing|support|partnership|difficult|spam",
  "urgency": "low|med|high",
  "language": "en|ro|other",
  "summary": "o propoziție în română despre ce vrea omul",
  "reply_subject": "Re: <subiect>",
  "reply": "textul răspunsului (engleză) sau '' dacă nu e cazul",
  "escalate": true|false,
  "reason": "de ce escaladezi (română), '' dacă nu"
}"""


def _key(path, *names):
    with open(path, encoding="utf-8") as f:
        d = json.load(f)
    for n in names:
        if d.get(n):
            return d[n]
    raise RuntimeError(f"Cheie lipsă în {path}: {names}")


def agentmail_creds(inbox_override=None):
    cfg = json.load(open(CONFIG, encoding="utf-8"))
    key = cfg["api_key"]
    inbox = inbox_override or cfg["inboxes"]["default"]["id"]
    return key, inbox


def _http(url, key, method="GET", payload=None, timeout=30):
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Authorization", f"Bearer {key}")
    req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        body = r.read().decode()
    return json.loads(body) if body.strip() else {}


def fetch_live(key, inbox, limit):
    d = _http(f"{AGENTMAIL}/inboxes/{inbox}/messages?limit={limit}", key)
    msgs = d.get("messages", d if isinstance(d, list) else [])
    out = []
    for m in msgs:
        if "received" not in (m.get("labels") or []):
            continue
        text = m.get("text") or m.get("extracted_text") or ""
        if not text:
            try:
                full = _http(f"{AGENTMAIL}/inboxes/{inbox}/messages/{m['message_id']}", key)
                text = full.get("text") or full.get("extracted_text") or ""
            except Exception:
                text = ""
        out.append({
            "id": m.get("message_id"),
            "from": m.get("from"),
            "subject": m.get("subject") or "",
            "text": text,
            "labels": m.get("labels") or [],
        })
    return out


def classify(msg):
    key = _key(SECRETS, "DEEPSEEK_API_KEY", "deepseek_api_key")
    payload = {
        "model": "deepseek-chat",
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": (
                f"From: {msg.get('from')}\nSubject: {msg.get('subject')}\n\n{msg.get('text','')[:4000]}"
            )},
        ],
        "temperature": 0,
        "response_format": {"type": "json_object"},
    }
    req = urllib.request.Request(DEEPSEEK, data=json.dumps(payload).encode(), method="POST")
    req.add_header("Authorization", f"Bearer {key}")
    req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=90) as r:
        resp = json.loads(r.read().decode())
    raw = resp["choices"][0]["message"]["content"]
    return json.loads(raw)


def apply_policy(msg, cls):
    """Politica de rutare trăiește în COD. LLM-ul propune, codul decide.

    action:
      auto_send -> raspuns FIX (template), trimis automat
      draft     -> schita LLM pentru aprobare (support tehnic)
      escalate  -> Alex decide (comercial/legal/complex)
      ignore    -> spam
    """
    blob = (msg.get("subject", "") + " " + msg.get("text", "")).lower()
    risk = [w for w in RISK_WORDS if w in blob]
    cat = cls.get("category", "difficult")

    if cat in ("free_check", "pricing") and not risk:
        action = "auto_send"
        cls["reply"] = TEMPLATES[cat]          # template fix, nu text LLM
    elif cat == "support" and not risk:
        action = "draft"                       # tehnic: poate fi greșit -> omul aprobă
    elif cat == "spam":
        action = "ignore"
        cls["reply"] = ""
    else:
        action = "escalate"                    # partnership / difficult / orice cu risc

    cls["action"] = action
    cls["auto_send"] = action == "auto_send"
    cls["escalate"] = action == "escalate"
    if risk:
        cls["reason"] = (cls.get("reason", "") + f" [risc: {', '.join(risk)}]").strip()
    return cls


def send_reply(key, inbox, to, subject, text):
    payload = {"to": to, "subject": subject, "text": text}
    return _http(f"{AGENTMAIL}/inboxes/{inbox}/messages/send", key, method="POST", payload=payload)


def load_state():
    if STATE.exists():
        return json.load(open(STATE, encoding="utf-8"))
    return {"processed": {}}


def save_state(st):
    STATE.write_text(json.dumps(st, indent=2, ensure_ascii=False), encoding="utf-8")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--fixtures")
    ap.add_argument("--live", action="store_true")
    ap.add_argument("--send", action="store_true")
    ap.add_argument("--limit", type=int, default=20)
    ap.add_argument("--inbox")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--ignore-state", action="store_true")
    args = ap.parse_args()

    key, inbox = agentmail_creds(args.inbox)

    if args.fixtures:
        msgs = json.load(open(args.fixtures, encoding="utf-8"))
        if isinstance(msgs, dict):
            msgs = msgs.get("messages", [])
    elif args.live:
        msgs = fetch_live(key, inbox, args.limit)
    else:
        print("Alege --fixtures FILE sau --live"); sys.exit(2)

    st = load_state()
    results = []
    for m in msgs:
        mid = m.get("id") or m.get("message_id") or m.get("subject")
        if not args.ignore_state and mid in st["processed"]:
            continue
        try:
            cls = apply_policy(m, classify(m))
        except Exception as e:
            results.append({"id": mid, "error": f"{type(e).__name__}: {e}"})
            continue

        sent = None
        if args.send and cls.get("auto_send") and cls.get("reply"):
            try:
                sent = send_reply(key, inbox, m.get("from"), cls.get("reply_subject") or f"Re: {m.get('subject')}", cls["reply"])
            except Exception as e:
                sent = {"error": f"{type(e).__name__}: {e}"}

        rec = {
            "id": mid, "from": m.get("from"), "subject": m.get("subject"),
            "category": cls.get("category"), "urgency": cls.get("urgency"),
            "action": cls.get("action"), "summary": cls.get("summary"),
            "escalate": cls.get("escalate"), "auto_send": cls.get("auto_send"),
            "reason": cls.get("reason"), "reply": cls.get("reply"), "sent": sent,
        }
        results.append(rec)
        st["processed"][mid] = {
            "at": datetime.now(timezone.utc).isoformat(),
            "category": cls.get("category"), "action": cls.get("action"),
            "sent": bool(sent),
        }

    if not args.json:
        for r in results:
            if "error" in r:
                print(f"[ERR] {r['id']}: {r['error']}"); continue
            tag = {"auto_send": "AUTO", "draft": "DRAFT", "escalate": "ESCALATE", "ignore": "IGNORE"}.get(r["action"], "?")
            print(f"\n[{tag}] {r['category']}/{r['urgency']} · {r['from']}")
            print(f"  subiect: {r['subject']}")
            print(f"  sumar:   {r['summary']}")
            if r["reason"]:
                print(f"  motiv:   {r['reason']}")
            if r["reply"]:
                print(f"  raspuns:\n    " + r["reply"].replace("\n", "\n    "))
    else:
        print(json.dumps(results, indent=2, ensure_ascii=False))

    save_state(st)


if __name__ == "__main__":
    main()
