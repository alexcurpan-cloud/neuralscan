# Day 3 — Deploy Pack: Railway + Tally + Instagram (06-Aug-2026)

> Codul e deja live local + pe GitHub (commit c5f9239, repo public).
> Aici: pașii manuali pe conturile tale + texte gata de copiat.

---

## 1️⃣ Railway — redeploy cu Strat 0+1 (5 min)

**Recomandare: conectează repo-ul GitHub (e public acum) → deploy automat la fiecare push.**
Rezolvă și vechea problemă „GitHub Repo not found".

1. https://railway.app → dashboard → **New Project** → **Deploy from GitHub repo**
2. Alege repo-ul `alexcurpan-cloud/neuralscan`
3. Railway detectează automat `Procfile` → pornește cu gunicorn ✅ (fără setări extra)
4. **Settings → Variables** → adaugă:
   - Nume: `NEURALSCAN_API_KEYS`
   - Valoare: cheia din `.secrets.json` (ți-am dat-o în chat)
5. Deploy → verifică: https://neuralscan-production.up.railway.app/health → 200
6. Bonus: de acum, orice `git push` = redeploy automat. Nu mai trebuie manual.

**Verificare finală (după deploy):**
```
# fără cheie → 200 (anon)
# cu cheie greșită → 401
# cu cheie validă → 200
```

---

## 2️⃣ Tally — formularul waitlist (5 min)

**Link formular:** https://tally.so/r/D4EaAb (editare din contul tău tally.so)

**Actual:**
- Intro: „Scan the code your AI wrote and find out — in plain English — if it's safe to ship. Be among the first to try it. (Your code never leaves your machine.)"
- 1 întrebare: email

**Adaugă 3 întrebări** (după email, toate opționale ca să nu sperie):

| # | Întrebare | Tip | Opțiuni |
|---|-----------|-----|---------|
| 2 | What did you build with AI? | Alegere simplă | Lovable / Bolt / Cursor / Claude Code / Something else |
| 3 | Are you a developer? | Alegere simplă | No, not a developer / Yes, developer / Learning |
| 4 | Want an API key for integration? | Alegere simplă | Just the web tool / Yes, send me an API key |

**Outro (pagina de mulțumire):**
> You're on the list! 🎉 We'll send you early access + setup guide within 24h.
> In the meantime, try it free: neuralscan-production.up.railway.app

De ce: întrebarea 4 = exact lista de testeri pentru API keys (Strat 2). Întrebările 2-3 = profilul testerilor (măsurare).

---

## 3️⃣ Instagram — profil + prima postare (10 min)

**Bio (sub 150 chars):**
```
🔍 NeuralScan — free tool for non-devs
Built something with AI? Find out if it's safe to ship — in plain English.
🔗 neuralscan-production.up.railway.app
Built in Brașov 🇷🇴
```

**Prima postare (imagine: screenshot al scan-ului cu un finding critic + caption):**
```
Built an app with AI? There's one thing nobody tells you:

1 in 3 AI-generated projects ships with exposed secrets or security issues.
If you're not a developer, you have no way to check.

NeuralScan scans your code and explains problems in plain English — with a fix prompt you can paste back into your AI tool.

Free, no signup: neuralscan-production.up.railway.app

Built for non-devs, in Brașov 🇷🇴

#AIGeneratedCode #NoCode #VibeCoding #Security #NeuralScan #IndieHacker
```

**Story (opțional, pentru azi):**
> „1 in 3 AI-built apps leaks secrets. I built a free tool that shows you in plain English. Link in bio 🔍"

---

## Ordine recomandată
1. Railway (5 min) — ca link-ul public să aibă protecțiile noi
2. Tally (5 min) — ca waitlist-ul să culeagă ce ne trebuie
3. Instagram (10 min) — ca outreach-ul de azi să aibă un canal nou
