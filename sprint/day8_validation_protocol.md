# Protocol de validare NeuralScan („ca pe carte") — deadline 18 Sept

> Metoda: Lean Startup / Customer Discovery + The Mom Test. Scop: decizie GO/NO-GO pe DATE, nu pe sentimente.
> Regula de aur: nu întreba „ai folosi asta?" (toți zic da politicos) — întreabă despre COMPORTAMENTUL trecut.

## 1. Ipoteza (scrisă clar)
> „Dezvoltatorii care construiesc aplicații cu tool-uri AI (Lovable/Bolt/Replit) au o problemă reală cu securitatea codului generat, suficient de mare încât să: (a) ruleze un scanner local pe codul lor, (b) îl folosească din nou, (c) plătească pentru un scan profund."

## 2. Ipoteza cea mai riscantă (ce testăm de fapt)
Nu „le place ideea?" — ci: **vor ACȚIONA pe un raport de securitate și vor PLĂTI pentru mai mult?**
Aici pică 90% din tool-urile de securitate: oamenii zic „interesant" și nu fac nimic.

## 3. Scara dovezilor (de la slab la puternic)
| Semnal | Putere | Cum îl măsurăm |
|---|---|---|
| Views / like-uri / „cool idea" | ⚪ Zgomot | Nu contează |
| Semnătură pe waitlist | 🔸 Slab | Formular |
| **A rulat tool-ul pe cod real** (activare) | 🟡 Mediu | Ne spune ce a găsit |
| **A revenit / l-a folosit din nou** (retenție) | 🟠 Puternic | Același om, a 2-a rulare în 2 săptămâni |
| **A cerut o funcție / l-a recomandat** | 🟠 Puternic | Feedback specific |
| **A PLĂTIT** (sau intent de plată cu bani pe masă) | 🔴 Cel mai puternic | Deep scan manual $49 sau „cumpără acum" |

## 4. Etape (13→18 Sept, ~30 min/zi)
**Etapa A (13-14 Sept) — Outreach țintit:**
- 2 postări (format-întrebare) în comunități potrivite: r/SideProject + 1 Discord de AI dev
- 10-15 DM-uri scurte către oameni care AU postat recent despre probleme cu cod AI-generated (nu spam — răspuns la problemele lor)

**Etapa B (15-17 Sept) — Conversații Mom Test (5-10 min):**
Întrebări despre TRECUT, nu despre viitor:
1. „Ce faci azi când îți e teamă că app-ul tău are o problemă de securitate?"
2. „Care a fost ultima dată când ai avut o problemă de securitate sau un secret ajuns aiurea? Ce ai făcut?"
3. „Ai plătit vreodată pentru ceva legat de securitate? Cât?"
4. „Cine se ocupă de asta la tine în proiect?" (dacă «nimeni» → e problemă neadresată = oportunitate)
→ La final: „Vrei să rulezi scannerul pe codul tău acum?" (comportament, nu intenție)

**Etapa C (17-18 Sept) — Testul de plată:**
Cui a rulat tool-ul → ofertă concretă: „**Deep scan manual, 49 USD** — îți fac un audit complet pe app-ul tău." (Varianta A din plan: manual întâi.)
- Chiar dacă nu cumpără nimeni: răspunsul la „de ce nu?" e aur.

## 5. Criterii de decizie (18 Sept)
- **GO:** ≥5 oameni au rulat tool-ul pe cod real + ≥2 au revenit/cerut ceva + ≥1 intent real de plată (sau 1 plată)
- **GO PARȚIAL (pivot pe segment):** rulări multe, dar zero interes de plată → produsul e util dar nu vandabil ca atare (candidat: open-source + servicii)
- **NO-GO:** <3 rulări după outreach activ 5 zile → nu e problemă urgentă pentru ei acum; se arhivează fără regrete (codul și cunoștințele rămân)

## 6. Anti-patterns (ce NU facem)
- ❌ Nu numărăm views/like-uri ca validare
- ❌ Nu întrebăm prieteni (răspund politicos)
- ❌ Nu construim features „ca să validăm" (construcția nu e validare)
- ❌ Nu interpretăm tăcerea ca „poate mai încolo" — tăcerea e un dat
- ❌ Nu prelungim deadline-ul „încă o săptămână" (decizia la 18 Sept, indiferent de rezultat)

## 7. Ce învățăm oricum (garantat)
- Cum arată un raport care CONTELEAZĂ pentru un non-securist (îmbunătățește translatorul)
- Care segment răspunde (builders vs agenții vs firme)
- Dacă problema e „durere reală" sau „nice to have" — și asta valorează mai mult decât tool-ul
