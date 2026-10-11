# NeuralScan Inbox Agent v0 — Argus preia inbox-ul, Alex doar cazurile dificile
**Data:** 2026-10-11 · **Status:** v0 DONE (dovedit) · **Mod:** night_shift (Alex lucrează 19:00)

## Cererea lui Alex (11-Oct)
> „Poate facem ceva util pt NeuralScan ca produs, și să fie ulterior automatizat, să te ocupi tu de majoritatea lucrurilor — eu doar să vorbesc cu clienții mai dificili; de restul te ocupi tu, răspuns mail-uri sau chiar și apeluri."

## Gardul roșu/verde (AGENTS.md, 4 întrebări)
1. **Există deja ca standard/serviciu?** DA — **AgentMail API** (inbox deja configurat, dovedit live). → 🔴 consum, nu construi.
2. **Servește direct un workflow folosit azi?** DA — planul 90 zile F2: „fiecare free check → email capture → follow-up la 48h". Blocantul e ADOPȚIA, nu codul.
3. **Infra orizontală sau glue vertical?** Glue vertical (fluxul lui Alex, inbox NeuralScan). → 🟢
4. **Ambiguu / efort > 4h / dependență nouă?** Nu — v0 în ~1h, zero dependențe noi (urllib + DeepSeek).
**VERDICT: 🟢 CONSTRUIEȘTE** (thin wrapper care consumă AgentMail).

## Criterii de acceptare (scrise ÎNAINTE)
1. Clasifică un email de client într-una din: `free_check · pricing · support · partnership · difficult · spam`.
2. Rutează conform politicii: standard → răspuns automat; tehnic → schiță; comercial/legal → escaladare; spam → ignoră.
3. **Zero halucinație pe răspunsurile trimise automat** (text fix, nu generat de LLM).
4. Nu re-acționează pe un mesaj deja procesat (stare persistentă).
5. Dovadă pe date reale (fetch live din AgentMail) + pe fixtures deterministe.

## Dovadă (Rulez, nu povestesc)
**Fixtures (6 cazuri reale, `--fixtures`):** 6/6 corect rutate
```
[AUTO]     free_check/low  · jake.dev@gmail.com          (vrea scan gratuit)
[AUTO]     pricing/med     · maria@startuphub.ro         (cere preț) — răspuns RO→EN, cu planuri
[ESCALATE] difficult/high  · angry@customer.io           (refund + avocat) → risc: refund, lawyer, hack
[ESCALATE] partnership/med · partners@securityalliance.com (50k devs, cere call)
[IGNORE]   spam/low        · noreply@promo-blaster.biz   (backlinks)
[DRAFT]    support/med     · tom@buildfast.dev           (eroare 413 la zip 40MB)
```
**Live (`--live`):** fetch real din inbox `busyinspiration255@agentmail.to` → 200, mesajele reale procesate corect (5× DSN `mailer-daemon` → `IGNORE`/spam, nu deranjează).

## Politica de rutare (trăiește în COD, nu doar în prompt)
| Categorie | Acțiune | Răspuns |
|---|---|---|
| free_check, pricing | `auto_send` | **template FIX** (determinist, fără halucinație) |
| support (tehnic) | `draft` | schiță LLM → omul aprobă (poate fi greșit) |
| partnership, difficult | `escalate` | schiță pentru Alex, **nu se trimite** |
| spam | `ignore` | — |

Detecție de risc în cod (refund/legal/avocat/GDPR/breach/amenințări) → forțează `escalate`, chiar dacă LLM-ul zice altfel.

## ONEST — ce NU e gata
- **Apeluri telefonice:** imposibil fără furnizor plătit (Twilio/Vonage, ~$1-15/lună + per minut). → **[PROPUS]**, aștept decizia lui Alex. Zero cost = zero apeluri.
- **Răspunsurile automate nu sunt încă pornite spre clienți**: `--send` există dar NU l-am folosit pe inbox real (nu vreau să trimet un răspuns de test unui om real). Testat doar pe fixtures.
- **Inbox partajat:** folosim inbox-ul NeuralBrain (`busyinspiration255@agentmail.to`). Pentru NeuralScan public trebuie o adresă dedicată (decis de Alex).
- Clasificarea costă ~$0.001-0.003/email (DeepSeek).

## Pași următori (automatizare completă)
1. Alex confirmă adresa publică de contact + GO pe `auto_send` (free_check/pricing).
2. Cron pe **Pi** (livrare dovedită pe Discord) la 2-3h: rulează triage → trimite lui Alex DOAR escaladările + un rezumat (1 mesaj, nu 20).
3. Follow-up automat la 48h pentru free checks (F2 din planul 90 zile).
4. (opțional, după GO) voicemail/telefonie prin furnizor plătit.

## Fișiere
- `neuralscan/inbox_agent/triage.py` — motorul
- `neuralscan/inbox_agent/fixtures/sample_inbound.json` — 6 cazuri de test
- `neuralscan/inbox_agent/state.json` — stare (anti-dublură)
