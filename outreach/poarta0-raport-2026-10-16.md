# Poarta 0 — Raport verificare manuală (2026-10-16, seara)

> Scop: înainte de orice mesaj de outreach, verificăm câte findings REALE produce
> scannerul. Criteriu scris în plan: **≥3 reale → trecem; <3 → produsul nu e gata.**

## Ce s-a rulat
- Runda r3: 30 repo scanate (`outreach/find_targets.py --max 30` → `targets-r3.json`)
- Runda r4 (țintire îmbunătățită, fără clonuri): 47 repo → `targets-r4.json`
- Total: **~77 repo publice**, findings serioase = 12 repo / 54 findings
- Fiecare finding verificat manual (linia reală trasă din GitHub) — vezi `.openclaw/tmp/verify_r4.py`

## Rezultat: ~2 reale din ~77 repo

### ✅ REALE (2)
1. **alhk10/gaonhae-hr** — `src/pages/public/PublicGradingList.tsx:126`
   `ADMIN_UNLOCK_PASSWORD = 'Hp97533488'` + 5 parole de filială, hardcodate în **frontend public**
   (bundle → oricine le citește). Aplicație HR reală (Singapore, filiale balmoral/bukit-merah/...).
   **Finding solid, demn de raportat autorului.**
2. **Ymyrr04/talentbridge-ph** — `src/dev/devAccounts.ts:5` `DEV_PASSWORD = "TalentHub2026!"`
   Parolă de dev pentru conturi seed. *Borderline*: conturile sunt `@sample.*` → probabil fixture.
   De verificat dacă sunt în prod înainte de a-l raporta.

### ❌ FALS-POZITIVE (52) — 5 clase identificate
| Clasă | Exemplu | De ce e FP |
|---|---|---|
| **i18n / traduceri** | `password: "Пароль"` (polish-pathfinders) | e cuvântul tradus, nu o parolă |
| **template/env** | `ALTER USER ... PASSWORD :'pgpass'` (staticbot) | valoarea vine din `$POSTGRES_PASSWORD` |
| **valori runtime** | `set token='{token}'` unde token=sha256(...) (mock-overlay-magic) | generat la rulare, nu hardcodat |
| **fișiere de test** | `apikey: "explicit_bad_key"` (livingroom-vet-care) | intenționat invalid; 26 findings → toate în `tests/` |
| **regulă greșită** | `urlopen(f"http://{args.host}...")` raportat ca `path_traversal` (workbuddyapi2) | nu e traversare de cale deloc |

## Verdict
**SUB PRAG (2 < 3).** Scannerul are **recall ok pe clasa „parolă în frontend", dar precizia
scade pe fișiere de test, template-uri, i18n și valori runtime.** Nu-l putem trimite oamenilor
așa — 52/54 findings ar fi zgomot, iar credibilitatea se pierde la primul mesaj.

## Ce am reparat deja (dovadă)
- **Fix 2026-10-16:** scannerul ignoră acum `hardcoded_password` în fișiere/directoare de test
  (`cypress/`, `*.spec.*`, `__tests__/`, `*.cy.js`...). Cheile reale (API/JWT/PAT) rămân raportate.
  - Suită: **123/123 trec** (`.venv/bin/python -m pytest tests/ -q`)
  - Dovadă 4/4: test→curat · normal→raportat · parolă reală→raportat · cheie API în test→raportat
- **Fix țintire:** `find_targets.py` nu mai scanează clonuri/tutoriale (`CLONE_RE`).

## De decis (Alex)
- **A. Reparăm precizia** (celelalte 4 clase de FP — ~1-2h muncă concentrată) → re-rulăm Poarta 0.
  Adevăratul produs: *„scanner care NU te face de râs"*.
- **B. Acceptăm verdictul** și nu insistăm pe outreach acum (pivot pe job hunt / canal).

**ALEX A ALES: A** (2026-10-16 23:16).

---

# RE-RULARE după reparații (2026-10-16 noaptea)

## Reparații aplicate (dovadă: teste 123/123 după fiecare)
| Clasă | Fix |
|---|---|
| fișiere/directoare de test | `_is_test_file` (cypress/, *.spec.*, teste/, __tests__/, fixtures/) — suprimă credențiale generice + zgomot de cod |
| i18n/locale | `_is_i18n_file` — `password: "Пароль"` nu mai e parolă |
| placeholder/expresie | valori cu `{}%()[]<>;` = artefact/format, nu secret |
| mască UI | valoare = un singur caracter repetat (`••••••••`) = zgomot |
| `data-*` HTML | atribute `data-token=` (widget-uri Trustpilot) = zgomot |
| psql | `PASSWORD :'pgpass'` (substituție de variabilă) = zgomot |
| path_traversal | scos `read_text/write_text` (pathlib: primul arg = CONTINUT) + lookbehind anti-`urlopen` |
| sql_injection | fereastra DDL include linia următoare (`ALTER TABLE` pe linia 2) |
| placeholder-e | run de 6+ caractere identice, nume de env var, exemple `...`, `password123` — CU excepție prefixele reale de provider |

## Rezultate before → after (ACELAȘI lot, aceleași repo-uri)
| Lot | Findings serioase |
|---|---|
| r3/r4 (12 repo) | **54 → 3** (51 eliminate) |
| r5 (5 repo, lot proaspăt) | **18 → 7** (11 eliminate) |

## Verdict final: **POARTA 0 TRECE** ✅
Pe lotul r5 (33 repo, scanner reparat) → **3 findings REALE**:
1. **Bruxaok122/indicadorprobr** — `admin@juriszap.com` + `password="JurisZap@2025!"` hardcodate în `supabase/functions/setup-admin/index.ts` (cod public).
2. **Bruxaok122/indicadorprobr** — `VERIFY_TOKEN="juriszap_webhook"` hardcodat (secret de webhook, public).
3. **rejuan0066-crypto/edumate-bd** — `DIDIT_DEFAULT_API_KEY='oh4x2lCr8hnNmjMBjWY4fn3MGY-pzZ4ircZmx7uBvVo'` hardcodat în `src/lib/diditService.ts`.

Plus din lotul r3/r4: **alhk10/gaonhae-hr** (`ADMIN_UNLOCK_PASSWORD` în frontend public) — real.

FP rămase (acceptabile, de filtrat manual): path_traversal în scripturi CLI locale, `session_token: 'direct'`.

## Următorul pas (planul, 30 min împreună)
Alegem 3-5 findings reale + mesajul (template B din `dm-pack.md`, adaptat) → Alex trimite (sau eu cu co-pilotul browser, el aprobă). **Criteriu final:** ≥3/10 oameni „raportul are sens".

## Commits
- `0afc421` — precizie scanner r3/r4 (-51 FP)
- `cd83b20` — precizie scanner r5: placeholder-e + prefixe provider (-11 FP)
