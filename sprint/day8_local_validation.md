# Day 8 — Validare manuală NeuralScan (zero cost)

**Context:** Alex nu e în bani → validăm cererea reală ÎNAINTE de orice cost Railway.
**Deadline:** 2 săptămâni din 4 Sep 2026 → **go/no-go pe NeuralScan pe 18 Sep**.
**Regula de aur a recrutării:** fără link waitlist, fără conturi, fără cloud — direct:
„scanează gratis codul tău, spune-mi dacă raportul are sens".

---

## Task 1: CLI standalone — ✅ DONE (4 Sep, dovedit)
- `neuralscan/neuralscan-cli.py` (wrapper CLI) + `neuralscan/neuralscan-cli.zip` (12 KB)
- Conținut zip: neuralscan-cli.py + src/scanner.py + src/translator.py + README (2 comenzi)
- Zero dependințe externe: scanner.py + translator.py = doar stdlib, zero importuri reciproce
- Dovadă: `src/test_vulnerable.py` → 4/4 findings (hardcoded key, SQLi, cmd injection, weak crypto)
  + raport uman cu fix prompts; zip dezarhivat în /tmp → 2/2 findings, exit codes corecte (0 curat / 1 findings)
- Criteriu: `unzip` + `python3 neuralscan-cli.py cod.py` = raport citibil. ÎNDEPLINIT.

## Task 2: Mesaj recrutare testeri — DRAFT gata, de aprobat Alex
Draft-urile complete sunt în `sprint/day8_recruit_messages.md` (Reddit + Discord + DM).
Ideea: problem-story scurt, zero self-promo agresiv, call for feedback real.

## Task 3: Țintă 3-5 reacții reale — ÎN AȘTEPTARE
Comunități: r/lovable, r/bolt, r/replit + Discord-urile lor (canale feedback/showcase).
- [ ] Verific regulile anti self-promo per comunitate (ÎNAINTE de orice postare)
- [ ] Alex aprobă textul final + postează cu contul lui (sau zice altfel)
- [ ] Track răspunsuri: cine a rulat scan pe cod real, ce feedback a dat
- Criteriu: 3-5 conversații reale cu testeri care au rulat CLI-ul pe codul lor

---

## Go/No-Go (18 Sep 2026)
- **GO:** ≥3 feedback-uri utile (ce prinde bine, ce lipsește) + semnal că oamenii revin/îl vor din nou
- **NO-GO:** zero interes real după outreach activ 2 săptămâni → NeuralScan rămâne pe raft, fără regrete
- Indiferent de rezultat: learnings intră în `sprint/` + raport scurt pentru Alex
