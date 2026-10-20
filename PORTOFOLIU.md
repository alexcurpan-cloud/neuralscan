# NeuralScan — case study de portofoliu (închis ca produs, 20-Oct-2026)

> Decizie Alex (20-Oct 08:26): **direcția se oprește ca produs.** Se păstrează ca
> dovadă de competență tehnică + material de portofoliu pentru job hunt.
> Nimic nu se șterge. Codul rămâne. Lecțiile rămân.

## Ce am construit (dovedit, nu declarat)
- **Scanner de securitate pentru cod generat cu AI** — Python, 130 teste verzi.
  Detectori: SQL injection, command injection, path traversal, secrete hardcodate,
  JWT/public-key, subprocess sigur.
- **Reducere reală de fals-pozitive:** precizie îmbunătățită prin fix-uri verificate
  pe cod real (`_jwt_is_public`, `_password_match_is_noise`, `_is_safe_subprocess_list_call`).
  123 → 130 teste, FP 32 → 7 pe lotul de validare.
- **Pipeline de descoperire:** GitHub code search → scanare locală (zero LLM) →
  verificare manuală obligatorie → contact proprietar. Scripturi:
  `outreach/find_targets.py`, `outreach/find_targets_secrets.py`.
- **Rezultat real:** 3 findings reale verificate linie cu linie (chei OpenAI hardcodate,
  credențiale admin în clar), 1 email trimis unui proprietar real.
  Proces corect: cheile nu au fost folosite/testate.
- **Infra:** deploy Railway prin CI (GitHub Actions), Postgres, chei API hash-uite,
  audit log, CLI de management.

## Ce am învățat (partea valoroasă)
1. **Un scanner nu e un produs.** Platformele își închid singure găurile:
   GitHub secret scanning (gratis pe public), Lovable RLS default + linter,
   Bolt RLS default + security check gratuit pe toate planurile, Supabase linter.
2. **Fereastra de piață se închide simultan pe toate fronturile**, nu treptat.
   Când o platformă adaugă un check, tool-ul extern devine redundant peste noapte.
3. **Verificarea manuală e obligatorie.** 3 din 3 findings „serioase" dintr-o rundă
   au fost fals-pozitive. Un tool care raportează fără verificare distruge încrederea.
4. **Distribuția e produsul.** 0 findings în 38 repo-uri nu a fost problema tehnică
   cea mai mare — problema a fost că nimeni nu a văzut produsul.
5. **Dovada bate promisiunea.** Fiecare afirmație din proiect are un fișier, o linie,
   un test sau un log în spate.

## Competențe demonstrate (pentru CV / interviuri)
- Python (scanere, parsing, CLI), securitate aplicativă (OWASP, triaj fals-pozitive)
- GitHub API + code search, Git avansat, CI/CD (GitHub Actions + Railway)
- Supabase/PostgREST, Postgres, RLS, model de amenințare
- Automatizare pipeline complet: descoperire → analiză → raport → contact
- Documentație de proces cu criterii de acceptare scrise înainte

## Unde e codul
- Scanner: `neuralscan/src/scanner.py` + `neuralscan/tests/`
- Pipeline: `neuralscan/outreach/`
- Sprint logs cu dovezi: `neuralscan/sprint/`
- Rapoarte Poarta 0: `neuralscan/outreach/poarta0-*.md`

## Status
**ÎNCHIS DEFINITIV ca produs SaaS la 20-Oct-2026, 08:43 (decizie finală Alex).**

Nu se tratează ca „aproape un SaaS". Sunt două afaceri diferite:
- **Produs SaaS** — oprit definitiv. Zero dezvoltare nouă, zero outreach.
- **Serviciu manual de audit** — posibil doar dacă Alex alege explicit modelul de consultanță,
  pentru 1–2 clienți. Nu este o continuare implicită a proiectului.

Codul rămâne funcțional ca unealtă internă. Investiția deja făcută nu decide direcția.
Motivul complet + dovezile: `sprint/2026-10-20-research-probleme.md` și `VIZIUNE.md`.
