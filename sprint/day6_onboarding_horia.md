# Onboarding Horia — dev flow (email gata de trimis)

> Flow: Alex întreabă Horia → „da" → creezi cheia (comanda de mai jos) → completezi <KEY>
> în email → trimiți. Total: ~3 minute.

## Pas 1 — creezi cheia (doar după „da" de la Horia)

```bash
curl -X POST https://neuralscan-production.up.railway.app/admin/keys \
  -H "X-Admin-Key: <NEURALSCAN_ADMIN_KEY din .secrets.json>" \
  -H "Content-Type: application/json" \
  -d '{"email": "horias-email@example.com", "plan": "free"}'
```

Răspuns 201 → copiezi `key` (apare O SINGURĂ DATĂ) în emailul de mai jos.

## Pas 2 — emailul către Horia (EN, dev)

**Subject:** NeuralScan — want to try it? (API key inside)

**Body:**

Hi Horia,

I built a security scanner for AI-generated code (NeuralScan) and it's live.
I'm looking for a first tester with fresh eyes — dev feedback welcome.

**Your API key (shown once):**
```
<KEY>
```

**What it is:** an API key for https://neuralscan-production.up.railway.app
— identifies you, 30 req/min, your scan history at `/user/scans`.
Stored only as a hash; if you lose it, we rotate a new one in a minute.

**Try it (3 ways):**

1. Web UI (no code): https://neuralscan-production.up.railway.app/app
   — paste code or upload a ZIP, get plain-language report + fix prompts.

2. Scan a snippet:
```bash
curl -X POST https://neuralscan-production.up.railway.app/scan \
  -H "Content-Type: application/json" \
  -H "X-API-Key: <KEY>" \
  -d '{"code": "API_KEY = \"***\"", "filename": "app.py"}'
```

3. Scan a whole repo ZIP:
```bash
curl -X POST https://neuralscan-production.up.railway.app/scan/zip \
  -H "X-API-Key: <KEY>" \
  -F "file=@your-app.zip"
```

**Wanted feedback (if you have 10 min):**
- Does the report make sense? (severity, explanation, fix prompt)
- Anything that looks wrong / missing?
- Did the API behave as you'd expect? (errors, limits, speed)

**Honest caveats:** static regex scanner (7 categories) — not a pentest.
We also run Strix (AI pentest) as a paid deep-scan tier, in beta.
Code is sent to the server for scanning and never stored (metadata-only audit).

Thanks! — Alex
