# NeuralScan — Podcast Speech (BridgeMind) — English

> Status: ready 16-Aug-2026. Verified live: /health 200, landing up, /stats 401 (auth ok), 42/42 tests, Strix deep 0 vuln.
> Target length: ~2–2.5 min spoken. Q&A numbers at the end.

---

## The Speech

**Title: NeuralScan — The Security Guard Your AI-Generated Code Never Had**

**Intro (hook):**
"Every week, thousands of small businesses ship code they can't read. Code written by AI, by freelancers, by tools. And nobody — nobody — has checked whether it's safe. I'm Alex Curpan, and I built NeuralScan to fix exactly that."

**The problem:**
"AI wrote more code last year than most developers will write in a lifetime. But the people who pay for that code — small business owners, shopkeepers, guesthouse owners in the Romanian mountains — can't tell the difference between a solid script and one that leaks every customer's data. They're not developers. They shouldn't have to be. And yet they're the ones who sign their name on the risk."

**The product:**
"NeuralScan is a security scanner for AI-generated code, built for non-developers. You give it your code. It checks it against security patterns: hardcoded secrets, dangerous patterns — the stuff that gets your database dumped at 3 AM. And then, the part I'm most proud of: it produces a human-readable report. Not a wall of CVE jargon. Plain language. 'This is broken. This is risky. Here's what it means for you.'"

**The proof:**
"I don't expect you to take my word for it. NeuralScan is live right now — 42 out of 42 tests passing. But the validation I care about most: I ran an AI pentesting agent called Strix against NeuralScan's own code. Deep scan. The result: zero confirmed vulnerabilities. We scan AI code for a living — and an AI tried to break us. It couldn't. That's not marketing, that's a log file."

**The mission:**
"Right now I'm focused on a very specific customer: small hospitality businesses in Romania — guesthouses in Bran, Râșnov, Fundata — getting websites built with AI tools, with no idea if those sites are secure. One breach can kill a season. NeuralScan gives them a one-page answer: 'You're safe' — or 'Fix this before it bites you.'"

**The close:**
"AI is writing the future. Someone has to check the grammar. That's NeuralScan. If you have AI-generated code and you're not a developer — or if you're an agency that wants to prove the work you deliver is safe — come talk to me. I'll scan your project and show you exactly what's in it."

---

## 30-second elevator version

"Most small businesses can't audit the AI-generated code they're paying for. NeuralScan scans it for secrets and dangerous patterns, then gives a plain-language report: safe, or fix this now. Live on Railway, 42/42 tests, and it survived a deep AI pentest with zero vulnerabilities. Built for the people AI is supposed to help, not just for developers."

---

## Q&A numbers to have on hand

| Topic | Fact |
|---|---|
| Live status | neuralscan-production.up.railway.app — /health 200 OK |
| Tests | 42/42 passing |
| Validation | Strix AI pentest, deep run: 0 confirmed vulns on own code |
| Strix cost | quick $1.93 / deep $4.20 per run (real numbers, build-in-public) |
| Scanner coverage | 9 code patterns + 7 secrets patterns (v1.0.0) |
| Transparency | audit log SQLite + /stats admin endpoint (auth-protected) |
| Target customer | guesthouses/pensions Bran–Râșnov–Fundata (RO hospitality) |
| Mission | first paying client; proof, not promises |
