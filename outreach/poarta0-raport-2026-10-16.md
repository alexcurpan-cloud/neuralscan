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
