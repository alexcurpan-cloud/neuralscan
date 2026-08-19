# Deep Scan — Kit vânzare manuală (Varianta A, aprobată 19-Aug)

> Decizie: NU construim job queue (#2) până la primul deep scan PLĂTIT.
> Validare: vinde manual → dacă cineva plătește $49-99 → construim butonul să-l scalez.
> Surse reale: run-uri Strix 13-Aug ($1.02, $2.16) + 18-Aug ($3.00, CWE-89 CONFIRMAT).

## Oferta (ce vindem)

**„AI Security Deep Scan"** — un AI pentest pe aplicația ta:
1. Rulăm Strix (AI pentest, sandbox Docker) pe codul/ZIP-ul tău
2. Găsim vulnerabilități VALIDATE (nu presupuse) — cu PoC unde e posibil
3. Îți dăm raport uman: severitate, linia exactă, explicație simplă + **fix prompt** de lipit înapoi în AI-ul tău
4. Onestitate: ce NU am putut confirma e listat separat (ex: „observat dar neconfirmat")

**Livrabil:** PDF/email cu raport (exemplu real: raportul vuln_app2 — CWE-89 SQLi confirmat, cost run $3.00)

**Preț:**
- **Primul client: $49** (promo validare) — 1 app, buget scan până la $5 LLM
- După: **$79-99/scan** sau pachete de credite
- **Horia: GRATUIT** (tester dev — feedback în schimb, nișă: prieten programator)

**Turnaround:** 24-48h de la primirea codului (worker manual, 1 concurrent)

## Flow operațional (manual, zero build)

1. Prospectul zice „da" → îmi dai contactul sau îmi zici tu
2. Primești/iei codul (ZIP, repo public, sau folder) — **cu acord scris** (legal: doar app-uri proprii/consimțite)
3. Rulez: `python scripts/run_strix.py --target <folder> --budget 5` + mapper `strix_to_neuralscan.py`
4. Verific raportul uman (onest: status completed, ce s-a confirmat/ce nu)
5. Livrez PDF + fix prompts → factură $49 (modalitate: de stabilit cu Alex — Revolut/transfer)

## Ținte (ordine)

| # | Prospect | Tip | Ofertă | Status |
|---|----------|-----|--------|--------|
| 1 | **Horia** | Dev, prieten | GRATUIT — 1 project al lui, feedback + testimonial | Alex îl întreabă |
| 2 | **Kids Event Finder / Padel League** (Reddit B2) | AI-builder, date reale useri | $49 promo — „am rulat un AI pentest pe app-ul tău" | 0 replies până azi |
| 3 | **Pensiuni (batch 16-Aug)** | Non-dev | Oferta lor e site + scan (varianta B/C din report Ionela) — deep scan intra ca componentă | Ionela = raport dat, urmărire |

## Reguli (din AGENTS.md + audit)

- **Legal:** DOAR app-uri proprii sau cu autorizare scrisă. Niciodată target fără acord.
- **Cost:** buget LLM per run $3-5, cap dur. Prețul acoperă costul + marjă.
- **Nu promite:** „0 vulnerabilități" nu există. Verdict onest: curat / risc / INCOMPLET (niciodată „curat" pe run incomplet).
- **Dacă prospectul cere deep scan pe site (URL)** → spunem NU pentru acuma (URL scanning amânat: autorizare/SSRF). Doar cod/ZIP.

## Criteriu de succes (Varianta A)

- [ ] 1 deep scan livrat (Horia, gratis) — deliverable validat
- [ ] 1 deep scan PLĂTIT ($49) — cerere dovedită
- → abia atunci: #2 job queue (butonul) devine build activ
