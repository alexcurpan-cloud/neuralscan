# CODEX HANDOFF — NeuralScan (18-Aug-2026)

> Document de predare pentru Codex (agent de cod). Citește înainte de orice task.

## Cine e cine

| Rol | Cine | Ce face |
|---|---|---|
| **Admin / Owner** | **Alex Curpan** („Admin") | Decizii finale, buget, outreach, aprobă direcția. Singurul care dă OK pe monetizare/prețuri. |
| **Argus** | Agent executor (OpenClaw, pe acest workspace) | Scrie cod, teste, deploy, monitorizare. Execută DOAR task-uri din PLAN.md cu criterii scrise înainte. |
| **Codex (tu)** | Agent de cod (OpenAI) | Audit + task-uri din PLAN.md. Lucrezi cu aceleași reguli ca Argus: criteriu înainte, dovadă la final. |

## Reguli de operare (non-negociabile)

1. **PLAN.md = sursa de adevăr** (`C:\Users\Alexandru\.openclaw\workspace\plan.md` — secțiunea NS-LAUNCH-RISKS). Nu construi ce nu e acolo; propune ce lipsește.
2. **Criterii de acceptare scrise ÎNAINTE de cod** (în PLAN.md), dovadă la final (teste + output real lipit).
3. **DONE se dovedește** — nu spune „merge", arată testul rulat.
4. **Gard roșu/verde:** nu construi ce există deja ca serviciu/SDK (ex. Stripe pentru plăți, Redis ca serviciu). Glue vertical OK.
5. **Secrete:** niciodată în log/transcript/commit. Cheile stau în `.secrets.json` (gitignored). Nu printa valori.
6. **Testele:** `python -m pytest neuralscan/tests -q` — azi **74/74 trec** (baseline).
7. **Deploy:** `railway up --detach` din `neuralscan/` (auto-deploy GitHub NU pornește singur — deploy manual, mereu).
8. **DB dual:** `src/db.py` — SQLite local/test, Postgres producție (`NEURALSCAN_DATABASE_URL` sau `DATABASE_URL`). Placeholder-urile `?` se traduc automat în `%s`.
9. **Nu rupe:** cheile prod (Strat 2), Postgres live, landing la `/`, scanner la `/app`, ZIP upload.

## Starea produsului (18-Aug, toate dovedite)

- Scanner static 16 pattern-uri + rapoarte non-dev (EN) — `src/scanner.py`, `src/translator.py`
- API: `/scan` (paste, max 100KB, cap 200 findings), `/scan/zip` (multipart, zip-slip safe, cap 500), `/stats` (admin), `/user/scans` (owner-scoping)
- Strat 2: chei hashed + revocare + ownership — `src/keys.py`, `src/keymgmt.py`
- Postgres live (durabil), landing EN la `/`, scanner la `/app`, Deep Scan = BETA (runner Strix local, NU în producție)
- Mapper Strix: `scripts/strix_to_neuralscan.py` — verdict 🟡 „Scan INCOMPLET" la run-uri nefinalizate (NU zice „curat" mincinos)

## Task-uri rămase (din auditul extern, PLAN.md NS-LAUNCH-RISKS)

### P6a — CI GitHub (mic, prioritar)
- Workflow GitHub Actions: `pytest neuralscan/tests` pe push/PR.
- Criteriu: push pe branch → testele rulează → verde; workflow-ul e vizibil în Actions.

### P6b — README corectat (mic, prioritar)
- README-ul zice că scanarea e locală — GREȘIT pentru aplicația live: codul e trimis la Railway, NU e stocat. Documentează arhitectura reală (endpoint-uri, auth, DB dual, deploy).
- Criteriu: README reflectă realitatea (scan remote, never stored), fără pretenții false.

### P6c — Lockfile dependințe (mic)
- `requirements.txt` → versiuni pin-uite sau lockfile (pip-tools / pip freeze).
- Criteriu: instalare reproductibilă (același set de versiuni).

### P3c — Redis rate limiting (mediu, doar când avem multi-workers)
- `flask-limiter` storage din `memory://` → Redis (variabile `REDIS_URL`/`UPSTASH_REDIS_REST_URL`), cu fallback memory dacă nu există.
- Criteriu: rate limit partajat între workers; fără Redis setat → comportament actual (memory).

### P4 — Monetizare static scan (mare, necesită OK Admin înainte)
- Signup UI simplu + chei revocabile din UI (backend Strat 2 există), scan history în UI, Stripe Free/Pro $19, limite clare (Free=1 scan).
- ⚠️ NU începe fără acordul Admin — implică plăți și decizii de produs.

### P5 — Deep Scan corect (mare, necesită OK Admin înainte)
- Job queue separată (nu în request web), status completed/failed/incomplete, sandbox izolat fără secrete/host access, credite separate.
- ⚠️ NU începe fără acordul Admin — implică infra și costuri.

## Căi utile

- Cod: `neuralscan/src/` (app.py, scanner.py, translator.py, audit.py, keys.py, keymgmt.py, zipscan.py, db.py, landing.html, static/)
- Teste: `neuralscan/tests/` (74: test_app_security, test_audit_log, test_keys, test_scanner, test_security_hardening, test_zip_scan)
- Scripturi: `scripts/run_strix.py`, `scripts/strix_to_neuralscan.py`
- Plan complet: `C:\Users\Alexandru\.openclaw\workspace\plan.md`
- Stare: `C:\Users\Alexandru\.openclaw\workspace\state.md`

## Prima mișcare recomandată pentru Codex

P6a (CI) sau P6b (README) — ambele mici, prioritate ridicată, zero risc. După fiecare task: teste + commit cu mesaj clar + raport scurt (ce, dovada, ce a rămas).
