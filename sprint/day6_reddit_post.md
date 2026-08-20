# Reddit post — gata de copiat (20-Aug-2026)

**Subreddit-uri recomandate (în ordine):**
1. r/LLMDevs — target: devi care construiesc cu AI
2. r/ChatGPTCoding — comunitate mare, acceptă build-in-public
3. r/SideProject — dacă vrei validare de produs, nu doar tehnic

---

## Titlu

We built an AI security scanner. Then we let an AI pentest our own demo app. It found real SQLi in 20 minutes for $3.

## Body (copiază exact)

We've been building NeuralScan — a security scanner that turns scary findings into plain-language reports with fix prompts for people who build apps with AI.

Yesterday we dogfooded it end-to-end:
- Wrote a deliberately vulnerable Flask app (SQLi, command injection, debug mode on)
- Ran Strix (AI pentest) against it: 243 requests, 6.5M input tokens, **$3.00**
- Mapped the SARIF output into a human-readable verdict

**Result:**
- 🟠 HIGH RISK — **SQL Injection CONFIRMED (CWE-89)** in `/user`: the `name` param was concatenated straight into a query. Fix prompt included: parameterized queries.
- Honest part: `/ping` (command injection via os.popen) was *observed* but NOT confirmed — we ran out of budget before full validation. It's in the report as "audit this", not as a finding.
- Also caught: Flask `debug=True` left on in production.

**The bug that made the product better:**
The first run paused at the $2 budget cap before writing SARIF → our mapper said "looks clean" — a false verdict. We fixed the mapper: an incomplete run now says "🟡 Scan INCOMPLETE — no security verdict", never "clean".

**The point:** if YOU are about to ship an AI-built app, a $3 AI pentest + a readable report beats pushing to prod and hoping. That's exactly what we're building.

Video (76s, actual run): https://youtu.be/XXXX  ← pune linkul după upload, sau lasă fără video

---

## Când postezi manual
1. Deschide reddit.com → r/LLMDevs → New Post
2. Titlu + body de mai sus
3. Poți atașa clipul direct (Reddit acceptă video upload): C:\Users\Alexandru\Videos\neuralscan_bip_2026-08-19.mp4
