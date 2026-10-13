# NeuralScan — varianta realistă: primul venit în 90 zile (2026-10-07)

> Scris de Argus. Premisa: solo, ture 12h, ADHD, buget mic.
> NU țintim $12B (joc de PhD + 10 ani + echipă). Țintim **venit care înlocuiește jobul**, apoi scală.
> Blocantul NU e codul (scanner 106 teste ✅) — e **adopția**. Deci: 80% distribuție, 20% produs.

## Criterii de succes (scrise ÎNAINTE — nu post-hoc)
- **Primar:** 1 client plătitor ($39 sau $99) în 90 zile.
- **Secundar:** ≥ 20 conversații reale + ≥ 10 free checks rulate.
- **Indicator timpuriu:** ≥ 3 oameni întreabă „cum ai făcut X?" sau răspund.
- **KILL:** 0 conversații în 4 săptămâni → wedge/canal greșit → se schimbă, nu se insistă.

## Faze
**F0 (săpt. 1) — testabil**
- Redeploy live: plan Railway Hobby (~$5/lună) + var repo `DEPLOY_RAILWAY=true`.
- Verificat independent: `/health` 200 + free check `/app` funcțional.
- Link corect peste tot: `neuralscan-production.up.railway.app` (bio vechi = 404).

**F1 (săpt. 1–2) — dovadă + prima atingere**
- 3–5 free checks pe apps AI reale publice → findings reale (dovada că prinde pe cod real).
- Intru în **1** Discord (Lovable/Bolt): ajut 3 oameni, ofer free check. Zero vânzare.
- Log tot în `memory/shared-knowledge/content-posts-tracking.md`.

**F2 (săpt. 2–6) — bucla**
- ~5 conversații/zi (bounded; batch pe zile bune, NU zilnic).
- Fiecare free check → email capture → follow-up la 48h.
- Track: conversații, checks rulate, răspunsuri.

**F3 (săpt. 6–12) — conversie**
- Ofertă Preflight ($39/$99). Primul client plătitor.
- Fiecare finding → 1 short-form + 1 pagină citabilă de AI (GEO).

## Cost
~$5/lună Railway + tokens DeepSeek (separat de abonament). Zero alt cost.

## Împărțirea muncii
- **EU, fără aprobare:** free checks, finding→content, log, pagină GEO, monitorizare, deploy tehnic.
- **ALEX decide:** plan Railway ($5) · var repo GitHub · GO pe buclă.
