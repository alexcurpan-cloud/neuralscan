# Day 4 — Bilet Herald: draft build-in-public (Strix experiment)

> Către: Herald (agent content, draft → aprobare umană → post).
> Sursa de adevăr: run-ul de MÂINE. Nu posta înainte de aprobarea lui Alex.
> Placeholder-uri de completat: `<RUN_ID>`, `<COST_USD>`, `<VERDICT>`.

## Context real (dovedit, 13-Aug)

- Mapper SARIF→raport uman: `scripts/strix_to_neuralscan.py` — testat pe run neterminat, a zis onest „🟢 pare curat (sau scanul n-a produs findings finalizate)" în loc să inventeze 0 vulnerabilități. `scan_completed: null` — nu minte.
- Run de test existent: `strix_runs/vuln-app2_820d/` (cost $2.16, 0 findings, neterminat la 21:08).
- Runner: `scripts/run_strix.py` (cheie din .secrets.json, STRIX_LLM=openai/gpt-5.4).

## Ce se întâmplă mâine (14-Aug, zi de build)

1. `python scripts/run_strix.py -t neuralscan/samples/vuln_app2 -m quick --max-budget 5` (~$3-5)
2. `python scripts/strix_to_neuralscan.py <RUN_ID>` → human_report.json
3. Verdict real pe ecran: 🔴 findings SAU 🟢 onest „niciun rezultat finalizat"

## Draft post (vocea lui Alex, sub 200 cuvinte)

---
**NeuralScan v2: de la scan static la validare reală.**

Ieri am încetat să construiesc un scanner AI de securitate și am început să CONSUM unul: Strix, open-source, agenți care atacă efectiv codul.

Cost real: <COST_USD> pentru un run pe o aplicație vulnerabilă intenționat. Verdict: <VERDICT>.

Cel mai important output nu a fost verdictul — a fost onestitatea pipeline-ului. Când primul run n-a produs findings finalizate, mapper-ul n-a raportat „0 vulnerabilități, ești safe". A zis exact ce era: „scanul n-a produs findings finalizate". scan_completed: null. Fără teatru.

Asta e diferența între un tool de securitate și unul care te minte ca să pari util.

Rules: consumă, nu construi. Dovezi, nu povești. Dacă n-ai un rezultat, spui asta — nu inventezi unul.

#buildinpublic #ai #security #strix #neuralscan
---

## Reguli pentru Herald

- NU adauga cifre inventate. Daca placeholder-ul `<COST_USD>` nu e completat de Alex, nu posta.
- NU zice „0 vulnerabilitati" daca verdictul e „niciun rezultat finalizat".
- Daca run-ul de maine esueaza (Docker down, cheie, timeout) → draft alternativ „ce am invatat din esec", tot onest.
- Postezi DOAR dupa OK-ul lui Alex pe draft.
