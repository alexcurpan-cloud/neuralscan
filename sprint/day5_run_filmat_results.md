# Run filmat vuln_app2 — REZULTAT (18-Aug)

> Pipeline demonstrat end-to-end: cod vulnerabil → Strix (AI pentest) → SARIF → NeuralScan mapper → raport uman.
> Run: `strix_runs/vuln-app2_b47d` · resume la $4 cap · finalizat 18-Aug 14:24.

## Verdict final (human_report.json)

**🟠 Risc ridicat — vulnerabilitati importante. Prioritizeaza remedierea.**

## Finding confirmat

| Câmp | Valoare |
|---|---|
| ruleId | CWE-89 |
| Descriere | SQL Injection în `/user` — parametrul `name` concatenat în query (fără parametrizare) |
| Nivel SARIF | warning → HIGH în raportul uman |
| Fix prompt | Parameterized queries / prepared statements |

## Cost real

- **$3.00** (cap setat $4; agenții s-au pauzat la $2 la prima trecere, reluați cu `continue` + budget 4)
- 243 requests · 6.47M tokeni input · 29K+ output · reasoning medium

## Onestitate (ce NU s-a confirmat)

- **RCE `/ping`** (command injection via os.popen) — OBSERVAT dar NECONFIRMAT din cauza limitelor de resurse (buget/turns). Raportul final îl menționează ca recomandare de audit, nu ca finding confirmat.
- Debug mode (Flask debug=True) — observat, recomandat de dezactivat (inclus în recomandări).

## Istoric run (pentru poveste)

1. Run inițial `-m quick --max-budget 2` → agenții au confirmat SQLi narativ, dar s-au **pauzat la buget** ($2.1555) înainte de a scrie SARIF → verdict greșit 🟢 „pare curat"
2. **Resume** (`continue` în terminal) + buget 4 → agenții au finalizat validarea → SARIF cu CWE-89 → verdict corect 🟠
3. Lecție wrapper: mapper-ul depinde de `findings.sarif` — run pauzat la buget = SARIF gol = verdict fals pozitiv „curat". Pentru v2: mapper-ul ar trebui să semnaleze `status != completed` explicit, nu „pare curat".

## Material demo (landing/outreach)

- Clip: 2 filmări non-fullscreen (Alex) — de re-editat/refăcut dacă vrem clip curat (OBS/Snipping Tool)
- Povestea: „AI-ul nostru a găsit SQLi real într-o mini-app, în 3 dolari, cu raport pe înțelesul omului"
- Comparație cost 14-Aug: gpt-5.4 quick $1.93 / claude deep $4.20 / acest run $3.00
