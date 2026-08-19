# Build-in-public draft — NeuralScan dogfood run (19-Aug)

> Sursa: run filmat 18-Aug (Videos/neuralscan_demo_2026-08-18.mp4 → clip editat neuralscan_bip_2026-08-19.mp4)
> Date reale din: day5_run_filmat_results.md, human_report.json (run vuln-app2_b47d)
> Guardrails HERALD: fara secrete, fara over-claim, onestitate pe ce NU s-a confirmat.

---

## Post draft (EN — X / LinkedIn, ~230 cuvinte)

**Hook:** We built an AI security scanner. Then we let an AI pentest our own demo app.

**Body:**
We've been building NeuralScan — a security scanner that turns scary findings into
plain-language reports with fix prompts for people who build apps with AI.

Yesterday we dogfooded it end-to-end:
- Wrote a deliberately vulnerable Flask app (SQLi, command injection, debug mode on)
- Ran Strix (AI pentest) against it: 243 requests, 6.5M input tokens, **$3.00**
- Mapped the SARIF output into a human-readable verdict

**Result:**
- 🟠 HIGH RISK — **SQL Injection CONFIRMED (CWE-89)** in `/user`: the `name` param was
  concatenated straight into a query. Fix prompt included: parameterized queries.
- Honest part: `/ping` (command injection via os.popen) was *observed* but NOT confirmed —
  we ran out of budget before full validation. It's in the report as "audit this", not as a finding.
- Also caught: Flask `debug=True` left on in production.

**The bug that made the product better:**
The first run paused at the $2 budget cap before writing SARIF → our mapper said
"looks clean" — a false verdict. We fixed the mapper: an incomplete run now says
"🟡 Scan INCOMPLETE — no security verdict", never "clean".

**The point:** if YOU are about to ship an AI-built app, an $3 AI pentest + a readable
report beats pushing to prod and hoping. That's exactly what we're building.

Video: 76s cut with the actual run.

---

## Note pentru Alex (ce NU e in post)
- Cost real $3.00 (243 req / 6.47M tokeni in) — cifra e adevarata din run.
- Nu mentionez numele clientilor/niciun secret; doar povestea dogfood.
- Daca vrei varianta scurta (X, 1-2 randuri + clip), o fac din asta in 1 minut.
- Postarea ramane MANUALA de la tine (Herald nu auto-posteaza) — spui tu cand si unde.
