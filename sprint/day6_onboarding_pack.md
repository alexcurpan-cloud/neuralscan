# Onboarding pack — primul tester NeuralScan (template)

> Pregătit 19-Aug. La primul „da" din outreach: creezi cheia via `POST /admin/keys`
> (acum merge direct în Postgres prod), o salvezi în `.secrets.json` și trimiți emailul.
> Timp de execuție: ~2 minute.

## 1. Pas 1 — creezi cheia (Argus, intern)

```bash
curl -X POST https://neuralscan-production.up.railway.app/admin/keys \
  -H "X-Admin-Key: <NEURALSCAN_ADMIN_KEY>" \
  -H "Content-Type: application/json" \
  -d '{"email": "<EMAIL-TESTER>", "plan": "free"}'
# -> 201, cheia apare O SINGURA DATA (ns_...)
```

- `free` = 30 req/min, 1 scan static în UI (pricing Free)
- Dacă testerul devine plătitor: revoci + creezi `pro` (300 req/min) sau discuți deep scan.

## 2. Email de onboarding (EN — segment: AI-built app builders)

**Subject:** Your NeuralScan API key — scan your AI-built app before you ship

**Body:**

Hi <NAME>,

Thanks for trying NeuralScan. Here's everything you need:

**Your API key:**
```
<KEY>
```
Store it like a password — it's shown only once. (You can revoke it anytime by
asking us — we'll rotate a fresh one.)

**Quick start (3 options):**

1. **Web app (no code):** https://neuralscan-production.up.railway.app/app
   — paste code or upload a ZIP, get a plain-language report + fix prompts.

2. **API — scan code:**
```bash
curl -X POST https://neuralscan-production.up.railway.app/scan \
  -H "Content-Type: application/json" \
  -H "X-API-Key: <KEY>" \
  -d '{"code": "API_KEY = \"sk-proj-...\"", "filename": "app.py"}'
```

3. **API — scan a whole ZIP/repo:**
```bash
curl -X POST https://neuralscan-production.up.railway.app/scan/zip \
  -H "X-API-Key: <KEY>" \
  -F "file=@your-app.zip"
```

**What you get:** severity (critical/high/medium/low), the exact line, a plain-English
explanation, and a fix prompt you can paste straight back into your AI tool.

**Privacy:** your code is sent to our server for scanning and never stored.
Metadata-only audit (key id, size, counts) — never the code itself.

**Plans:** Free = 1 scan + summary report · Pro $19/mo = unlimited static scans,
full reports, fix prompts, scan history · Deep Scan (AI pentest, beta) = credits,
$2-4/run.

Questions? Just reply to this email.

— NeuralScan team

## 3. După trimitere (tracking)

- [ ] Email trimis la: ______ (data: ______)
- [ ] Răspuns primit: ______
- [ ] A scanat ceva? (verifici în `/stats` după câteva zile)
- [ ] Convertit la Pro? (revoci free, creezi pro)

## 4. Notă cost/limite

- Free: 30 req/min per key — suficient pentru teste.
- Dacă testerul scanează mult, revoci și faci upgrade — fără redeploy, fără întrebări.
- Deep scan (Strix) NU e inclus în $19 — e credit separat ($49-99 cu limita explicită).
