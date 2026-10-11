# Outreach autonom + precizie scanner (2026-10-11)

> Alex: „să te implice mai mult, să fii nitel autonom, să dăm niște mesaje azi, produsul e gata de testat."

## Ce am construit (autonom, fără să întreb la fiecare pas)
1. **`outreach/find_targets.py`** — caută repo-uri publice construite cu AI (Lovable/Bolt/Cursor) pe GitHub,
   le clonează, le scanează local (zero cost), scoate findings serioase + contactul owner-ului.
2. **`inbox_agent/triage.py`** (v0, din tura anterioară) — clasifică + răspunde la emailuri de client.

## Rezultat runda 1 (14 repo-uri scanate → 5 cu findings „serioase")
Am **verificat manual fiecare finding** (regula: nu trimit nimic neconfirmat).
**Verdict: aproape toate erau FALS-POZITIVE.** Dacă trimiteam, ne ardeam credibilitatea.

| Clasă FP | Exemplu real găsit |
|---|---|
| Chei Supabase `anon`/publishable | `salon-chercheur-france/src/integrations/supabase/client.ts` — cheie **publică prin design**, raportată „JWT critic" |
| data: URI base64 | `reimagined-framework/src/assets/telegram-qr.ts` — QR PNG inline, raportat „JWT" |
| `model.eval()` / `regex.exec()` | `sloptotal/app/engines/*.py` — 14× „execuție de cod" (era `.eval()` de PyTorch) |
| Constante de protocol | `password: 'x-oauth-basic'` (GitHub), `bubble_plp_token` — raportate „parolă hardcodată" |
| Mesaje/log | `console.log('... token:', token ? 'token provided')` — „parolă" = propoziție |

## Fix aplicat în scanner (dovedit)
**`src/scanner.py`** — 4 filtre noi, toate în cod (nu în prompt):
- JWT cu payload `role: anon/publishable` → nu e secret
- data: URI base64 mascate
- `obj.eval()` (apel de metodă) ≠ `eval()` global
- fișiere minificate/obfuscate (`_0x…`) → fără pattern-uri de cod
- parolă = propoziție (spații) sau constantă de protocol → zgomot
- `PRAGMA`/DDL nu se parametrizează (nu e injectabil)

**Dovadă (aceleași 5 repo-uri, ACELAȘI scanner):**
```
Baloshi69/private_portfolio  5 -> 2
byoungju-web/coverfo        19 -> 0
cvUPTZ/reimagined-framework  1 -> 0
pablocaeg/sloptotal         17 -> 1
thomasloarec/salon-...       3 -> 0
TOTAL                       45 -> 3   (-93%)
```
Teste: **115/115 verzi**.

## ONEST — ce NU e gata
- Cele 3 findings rămase sunt **tot FP** (verificate manual: token Bubble efemer, `ALTER TABLE ADD COLUMN` cu nume constante, cheie Google Maps semi-expusă).
- **Deci NU am trimis mesaje azi.** Criteriul lui Argus: dovadă înainte de livrare. Un email cu FP = credibilitate arsă, exact ce a avertizat runda 1.
- Follow-up FP rămas: DDL pe 2 linii (`ALTER TABLE` + `COLUMN` pe linia următoare).

## Următor (cere decizia lui Alex)
1. Fix FP rămase + re-scan pe un eșantion mai mare (30-50 repo) ca să avem 3-5 findings REALE.
2. Abia apoi: outreach personalizat (email) cu finding real + `--send`.
3. Autonomie: pipeline-ul rulează singur (cron pe Pi), Alex aprobă doar lista finală.
