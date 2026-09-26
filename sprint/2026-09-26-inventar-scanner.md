# Inventar scanner NeuralScan — 2026-09-26

> Comandat de Alex: „să vedem ce îmbunătățiri am mai putea face în liniile de cod, dacă e funcțional, dacă are toți parametrii buni.”
> Metodă: citit cod (src/*.py, 2.400 linii fără .venv), rulat suita de teste, rulat 2 probe proprii (zero cost, regex local).

## 1. Verdict funcțional

| Test | Rezultat | Dovadă |
|---|---|---|
| Suită de teste | ✅ **88/88 passed** în 1.26s | `.venv/bin/python -m pytest -q` |
| Probe acoperire (14 cazuri reale) | ✅ **12/14** corecte | `.openclaw/tmp/scan_probe.py` |
| API complet | ✅ /scan · /scan/zip · /health · /stats · /admin/keys · /user/scans | src/app.py |
| Securitate proprie | ✅ rate-limit/cheie, chei hash+revocare, zip-slip, ProxyFix, headers, audit fără cod | src/app.py |
| **Rulează undeva acum?** | ❌ **NU.** Prod 404 „Application not found” pe ambele domenii; local :5050 nu ascultă | curl /health, ambele domenii |

**Concluzie:** codul e sănătos și funcțional *ca bibliotecă/API*. Ca serviciu live — nu există nimic pornit. (Coerent cu decizia de oprire din 3-Sep, dar trebuie spus clar: „funcțional” ≠ „live”.)

## 2. Găuri reale, cu dovadă (nu presupuneri)

| # | Sev | Problemă | Dovadă |
|---|---|---|---|
| 1 | 🔴 | **`.env.local` / `.env.production` sunt SĂRITE complet** de zipscan. Suffixul (`.local`, `.production`) nu e în `CODE_EXTENSIONS`, iar `NAKED_NAMES` prinde doar `.env` exact. Astea sunt *exact* fișierele cu secrete. | probe2 §1: `scannable=False` |
| 2 | 🔴 | **ZIP cu `node_modules` → 400 „prea multe fișiere (max 300)”, zero rezultat.** Un export Lovable/Bolt conține node_modules. Fix-ul e exclude-uri (node_modules/.git/dist/venv), nu mărire de limită. | probe2 §2: `EROARE 400` |
| 3 | 🟠 | **Secrete ratate:** Stripe `sk_live_…`, SendGrid `SG.…` — deși README promite „exposed secrets”. GitHub PAT & Slack token sunt prinse, dar **etichetate greșit** `hardcoded_password` (pattern generic le înghite). | probe1: `[RATAT]`, tip greșit |
| 4 | 🟠 | **Dedup pe linie:** 2 secrete distincte pe aceeași linie → **1 singur raportat**. Cheia de dedup e `(type, line)`, iar `matched_lines_secrets` e global pe linie. | probe2 §3: AKIA + postgres URL → doar AKIA |
| 5 | 🟡 | **Command injection modern ratat:** `subprocess.run(cmd, shell=True)` nu e prins. În plus `[^)]{0,200}?` nu trece de paranteze imbricate. | probe1: `[RATAT]` |
| 6 | 🟡 | **Sort severitate alfabetic**, nu pe rang: `critical, high, low, medium`. Cosmetic, dar ordinea din raport arată greșit. | probe2 §4 + `scanner.py` sort key |
| 7 | 🔵 | **Categorii lipsă** (candidate pt „deep”): deserializare (pickle/yaml.load), `verify=False` TLS, CORS `*`, JWT `verify_signature=False`, XSS, `random` pentru tokenuri. | probe1 |
| 8 | 🔵 | `insecure_http` doar TLD `.com/.ro/.org/.net/.io` → ratează `.app`, `.dev`, IP-uri. | probe1 |

## 3. Parametri (limite) — sunt coerente?

- Rate limit: free 30/min · pro 300/min · anon 30/min · legacy 300 → **ok, cu bucket per cheie** (revocata nu otrăvește bucket-ul IP).
- Cap zilnic: free 50 · pro 500 → **ok**, dar `daily_scans_used` se bazează pe `key_id` scris la scan; anonimii rămân doar pe IP (corect, nu au ce abuza).
- Limite conținut: cod 100KB · max 200 findings/scan · ZIP 5MB / 15MB decomprimat / 300 fișiere / 1MB fișier.
  ⚠️ `MAX_FINDINGS_TOTAL_ZIP` (500) e definit în ambele fișiere (`app.py` + `zipscan.py`) — **duplicare de constantă**, nu se folosește cea din app.py. Risc de divergență.
- ⚠️ Rate limit pe `memory://` → **nu supraviețuiește la restart / multi-worker**. Pe Railway cu >1 worker, limita se înmulțește. Nu e critic acum, dar e o promisiune pe care infra n-o ține.

## 4. Ce propun (ordinea de cost/impact — toate ieftine, zero dependențe noi)

1. Fix #1 (`.env*`) + #2 (exclude-uri ZIP) — ~30 min, repară exact ce promite produsul.
2. Fix #4 (cheie dedup `(type, line, column)`) — 10 min.
3. #3: adaugă pattern-uri Stripe/SendGrid/Slack/GitHub + mută generic-password la `confidence: low` ca să nu mai fure eticheta.
4. #6 sort pe rang de severitate — 5 min.
5. #5 `shell=True` — 15 min.
6. Categorii noi (#7) → doar dacă decidem că produsul se vinde pe „acoperire”; altfel zgomot.

**Niciuna nu e cod nou de infrastructură. Toate sunt în liniile existente — exact ce a cerut Alex.**

---

## 5. STARE: REZOLVAT 2026-09-26 (Alex: „Rezolva gaurile reale”)

| # | Fix aplicat | Fișier | Dovadă |
|---|---|---|---|
| C1 | `.env` + toate variantele (`.local`, `.production`, `.development`, `.staging`, `.test`) scanate; sabloanele (`.env.example`/`.sample`/`.template`) sărite | `zipscan.py` | probe2 §1: toate `True`, `.env.example` `False` |
| C2 | Exclude-uri de directoare (`node_modules`, `.git`, `dist`, `build`, `.venv`, `vendor`, `.next`, …) aplicate **înainte** de limita de fișiere | `zipscan.py` | probe2 §2: ZIP cu 400× node_modules → `OK files_scanned=1` (era 400) |
| C3 | Pattern-uri specifice Stripe / SendGrid / Slack / GitHub / Google OAuth, puse **înaintea** genericelor + suprimare pe span (generic nu mai fură eticheta) | `scanner.py` | probe1: 14/14; `hardcoded_github_token`, `hardcoded_stripe_key` etc. corect |
| C4 | Dedup pe `(tip, linie, coloană)` + gardă pe `(tip, linie)` | `scanner.py` | probe2 §3: 2 secrete pe o linie → **2 findings** (era 1) |
| C5 | `shell=True` prins; `[^)]` → `[^\n;]` (paranteze imbricate) | `scanner.py` | probe1: `shell=True` → `[OK]`, `os.system(f"ping {f(x)}")` prins |
| C6 | Sortare pe rang de severitate, nu alfabetic | `scanner.py` | test `test_severity_sorted_by_rank_within_line` |
| C7 | `MAX_FINDINGS_TOTAL_ZIP` — duplicat nefolosit scos din `app.py` (sursa unică: `zipscan.py`) | `app.py` | grep: 1 singură definiție |

**Dovadă agregată:** `pytest -q` → **106/106 passed** (88 existente + 18 de regresie noi în `tests/test_regression_2026_09_26.py`).

**Neatins intenționat:** rate-limit pe `memory://` (nu ține la restart/multi-worker) → cere un store
partajat (Redis = dependență + cost nou) ⇒ **decizie de arhitectură, nu fix de linie**. Raportat, nu executat.

**Nefăcut (categorii noi #7 din §2):** deserializare, TLS `verify=False`, CORS `*`, JWT fără verificare,
XSS, `random` pentru tokenuri — ar crește acoperirea, dar și zgomotul; aștept decizia dacă produsul se
vinde pe „acoperire”.
