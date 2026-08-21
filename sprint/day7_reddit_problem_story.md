# Draft Reddit problem-story — 21-Aug (PENDING aprobare Alex)

> Regula (invătata pe piele): problem-story, NU launch announcement. Link doar dacă cere cineva.
> Format: r/lovable sau r/boltnewbuilders — unde builderii își dau seama că n-au verificat codul.
> NIMIC nu se postează fără OK.

---

## Varianta A (r/lovable — problem story)

**Title:** I shipped a Lovable app and almost put an API key in production. Who actually checks AI-generated code before deploying?

**Body:**

Six weeks ago I built a small tool with Lovable. It worked great — I was proud of it. Then I got curious and ran a security check on the code it generated.

Turns out my "ready to ship" app had:
- an API key sitting in a config file, ready to be committed
- a shell command built from user input
- SQL queries assembled with string formatting

Nothing exploded — yet. But it would have, probably on day one of real traffic.

Since then I've been building a scanner that flags exactly this kind of thing before deploy. Not because AI code is bad — because nobody reads all of it, and the parts you don't read are where the secrets hide.

Question for the room: do you check your AI-generated code before shipping? What do you look for?

*(dacă cineva întreabă ce folosesc — atunci și doar atunci: link în comentariu)*

---

## Varianta B (mai scurtă, r/boltnewbuilders)

**Title:** PSA: your AI-generated app probably has a secret in it. Here's the 10-minute check.

**Body:**
Ran a quick scan on a Bolt app I was about to ship. Found an exposed key in 10 minutes.
The 10-minute check I now do before every deploy:
1. Search for `sk-`, `api_key`, `token =`, `.env` in committed files
2. Grep for `os.system(`, `eval(`, string-built SQL
3. If anything shows up: fix it, don't ignore it

What's your pre-deploy checklist?

---

## Guardrails
- [x] Fără pitch direct, fără link în post (doar la cerere)
- [x] Onest: poveste reală (NeuralScan dogfood — key găsită în notepad-uri, 14-Aug)
- [ ] Aprobat de Alex INAINTE de postare
