# Reddit post v2 — variantă educatională (respectă Rule 5 + Rule 10)

> De ce merge: nu e pitch, e o lecție tehnică cu cifre reale. Produsul e menționat o dată, natural.
> Comunitatea primește valoare: un pattern pe care să-l verifice în propriul cod.

## Titlu

I ran an AI pentest on my own vulnerable Flask app — it confirmed SQLi in /user. The more interesting bug was in my scanner, not the app.

## Body (copiază exact)

I wrote a deliberately vulnerable Flask app (SQLi, command injection, debug=True left on) and let an AI pentest agent (Strix) loose on it for 20 minutes. 243 requests, 6.5M input tokens, $3.00 total.

**What it found:**
- 🟠 SQL Injection CONFIRMED (CWE-89) in /user — the `name` param was concatenated straight into a query. Classic.
- `/ping` (os.popen) was observed but NOT confirmed — the run hit its budget before full validation. Reported as "audit this", not as a finding. I think that honesty matters — a tool that over-claims is worse than one that under-claims.
- Flask `debug=True` in prod. Everyone's favorite.

**The bug that taught me the most:**
The first run paused at the $2 budget cap *before* writing its results file. My mapper read the empty file and said "looks clean". A false negative, from my own pipeline. Fixed: an incomplete run now says "🟡 Scan INCOMPLETE — no security verdict", never "clean".

**Takeaway for anyone generating code with AI:** these are the exact classes of bugs AI codegen reproduces happily (string concatenation in SQL, debug flags, shell calls). Cheap to test for, expensive to ship.

We're building a scanner that turns findings like this into plain-language reports with fix prompts — but honestly, the lesson above is free. Has anyone else seen AI-generated code ship with these? Curious what you've caught in review.

*(Video of the actual run, 76s: attached)*
