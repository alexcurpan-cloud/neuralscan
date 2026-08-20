# Hacker News — Show HN (gata de postat manual)

> Show HN e făcut EXACT pentru asta: "am construit ceva, uitați ce face".
> Regula HN: link-ul direct la produs e acceptat, dar trebuie să stea pe propriul merit.
> Postezi la news.ycombinator.com → submit → url: https://neuralscan.up.railway.app (sau landing-ul EN)
> Titlul NU trebuie să fie clickbait — HN pedepsește asta.

## Titlu

Show HN: NeuralScan – I let an AI pentest my own scanner's demo app; it confirmed SQLi for $3

## Comment (primul comentariu pe post, obligatoriu pt Show HN)

We built NeuralScan — a security scanner that turns AI pentest output (SARIF) into plain-language reports with fix prompts, aimed at people who build apps with AI (Lovable, Bolt, Cursor crowd).

Dogfood run yesterday:
- Deliberately vulnerable Flask app (SQLi, command injection, debug on)
- Strix (AI pentest): 243 requests, 6.5M input tokens, $3.00
- Verdict: 🟠 HIGH RISK — CWE-89 SQLi confirmed in /user. Fix prompt included: parameterized queries.

Honest bits:
- /ping (os.popen) observed but NOT confirmed — budget ran out. Report says "audit this", not a finding.
- First run paused at budget cap before writing SARIF → mapper said "looks clean". False verdict. We fixed it: incomplete runs now say "🟡 INCOMPLETE — no security verdict", never "clean".
- Free tier exists; deep scans cost ~$3-5 (Strix compute). We're pre-revenue, validating with early testers.

AMA about the pipeline — happy to share the ugly parts.
