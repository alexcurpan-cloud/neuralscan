# Plan — 1 pagină · „Ce face ca toată tărășenia să aibă sens"
> Pregătit de Argus: 15-Oct-2026 seara (Alex era în tură). Se execută **mâine după-amiază, 16-Oct** (Alex liber).

## De ce suntem aici (adevărul, nu povestea)
- Lecția 18-Sept: produsul **nu a fost văzut de niciun om**. Nu l-a respins piața — nu l-am arătat nimănui.
- Azi am verificat: **produl e LIVE** (`neuralscan-production.up.railway.app` → HTTP 200, landing OK). Deci *se poate* arăta.
- Scannerul a prins un finding **REAL** pe cod real (9-Oct): parolă de admin hardcodată în repo public.
- DAR: runda 11-Oct arată că ultimele findings rămase erau **tot fals-pozitive**. Precizia reală nu e încă dovedită în afara testelor.

## Obiectivul UNIC (nu două, nu cinci)
**Primul „da, asta e util" de la un om real.**
Nu „câți utilizatori", nu „câți bani" — un singur om care atinge produsul și confirmă că a găsit ceva real și că înțelege ce să facă mai departe.

## Criterii de acceptare (scrise ÎNAINTE)
| Verdict | Condiție |
|---|---|
| ✅ CONCLUDENT | ≥3 din 10 oameni reali: „raportul are sens" + au găsit ceva *real* |
| ✅ FUNCȚIONAL | fiecare scanare se termină, fără erori, în < 2 min |
| ❌ INVALIDAT | 0 din 10 → produsul nu-și găsește rostul |

**Toate 3 sunt rezultate bune.** „Invalidat" salvează luni de construit în gol.

## Cum ajungem acolo — 2 căi, le încercăm pe rând
**A. Pull** — punem link-ul unde stau deja oamenii cu problema (comunități, DM). Slab: cere conturile lui Alex, postările au fost șterse de mods.
**B. Push (miza cea mai bună)** — scanăm NOI repo-uri publice construite cu AI → găsim un finding REAL → îi spunem autorului, gratis, în privat. Omul confirmă sau nu. **Nu cere conturi sociale, produce dovadă directă.**

## Poarta 0 — OBLIGATORIE înainte de orice mesaj
Re-scan pe **30–50 repo** cu scannerul actual (`outreach/find_targets.py`) → verificăm **manual fiecare finding**.
- ≥3 findings REALE → trecem la pasul următor.
- <3 reale → **produsul nu e gata**. Ăsta e răspunsul, și e util.

## Ce măsurăm (tabel simplu, zero complicații)
| # | Cine (repo/autor) | Finding | Real? (verificat) | Clar pt. om? | A răspuns? | Ce a lipsit |
|---|---|---|---|---|---|---|

## Mâine după-amiază — concret
1. **Argus (pot începe și acum, în fundal):** rulează Poarta 0 pe 30–50 repo, verifică manual, scoate lista scurtă de findings reale.
2. **Împreună (30 min):** alegem 3–5 findings reale + mesajul (template B din `dm-pack.md`, adaptat).
3. **Alex:** trimite mesajele (sau le trimit eu cu co-pilotul browser, cu el aprobând).
4. **Așteptăm răspuns.** Fiecare răspuns se trece în tabel. 48h → follow-up o dată.

## Onest — ce ne poate opri
- Precizia scannerului pe frontend TS (zgomot) — de asta Poarta 0 există.
- Rata mică de răspuns la mesaje reci (normal; de asta țintim oameni care AU postat problema).
- Eu **nu pot trimite DM-uri singur** — cere contul lui Alex. Pot conduce browserul, el aprobă.

## Sensul (răspunsul la „ce facem noi aici")
Nu construim „încă un scanner". Testăm **o singură promisiune**: *un om care își construiește app-ul cu AI găsește o problemă reală de securitate și înțelege ce să facă mai departe.*
Dacă e adevărată → avem produs. Dacă nu → știm, și ne oprim la timp.
