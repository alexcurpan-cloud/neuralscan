# Community Pack — atac pe comunități (fără link, fără promo) · 2026-10-11

> Decizie Alex: „Atacăm pe comunități, deocamdată NU pe mail."
> Regula care guvernează totul: **toate comunitățile de mai jos interzic explicit promovarea.**
> Deci nu postăm „uite tool-ul meu". Postăm o **întrebare/problemă reală** și oferim tool-ul
> DOAR dacă cineva cere. Zero linkuri în primul mesaj.

## Comunități verificate (reguli citite, nu presupuse)

| Comunitate | Link | Mărime | Regula cheie |
|---|---|---|---|
| Lovable Discord | discord.gg/lovable-dev | 174.510 membri | Canale: support, showcasing builds, announcements (lovable.dev/discord) |
| Bolt (BoltBot) Discord | discord.gg/bolt | 6.872 membri | „No Self-Promotion or Advertising" (boltbotrules) |
| Boltcord (suport Bolt) | discord.io/boltcord | — | „**No advertising.** You can't promote anything in this server... not allowed to send advertisements to users through their DMs" |
| r/lovable | reddit.com/r/lovable | — | Rule 7: no referral/discount; moderare strictă (postările noastre au fost șterse în trecut) |

**Concluzie dură:** „uite tool-ul meu" = șters/ban peste tot. Singura cale care trece filtrul:
**a ajuta întâi**, tool-ul apare doar în conversație, la cerere.

## Planul (întrebare, nu promovare)
1. Intră, citește 10 min ce întreabă lumea (probleme reale de securitate/cod AI).
2. Răspunde LA 3 OAMENI concret (valoare pură, zero tool).
3. Postează întrebarea de mai jos în canalul potrivit (support / showcase / feedback).
4. La cine răspunde „da, vreau" → DM cu tool-ul + cele 3 întrebări de feedback.
5. Log în tabelul de mai jos.

## 1) Lovable Discord — post de întrebare (canal #support sau #general)

```
Quick question for people shipping Lovable apps 👋

I keep seeing the same things in apps built with AI: API keys hardcoded in
frontend files, SQL built by string concatenation, admin auth that lives in
localStorage. The app looks clean until you actually read the code.

How are you handling this before you ship?
- Do you review security, or only when something breaks?
- What's the sketchiest thing you've found in your own generated code?

(I ended up building a small local scanner for exactly these patterns — happy
to share if useful. Mostly curious how others here deal with it.)
```

## 2) Bolt / Boltcord — comentariu de ajutor (pe un thread real, NU post nou)

```
Same thing caught me out — the generated code looked fine but had an API key
inlined in a client file. What helped me was grepping for the obvious stuff
(strings like sk-, AIza, "password") before every deploy.

If it helps, I have a tiny local script that flags these patterns (key by key,
with the risky line). No account, nothing leaves your machine — say the word
and I'll send it. What are you building?
```

## 3) r/lovable / r/SideProject — post-întrebare (fără link, fără nume de tool)

```
How do you handle security in code you shipped mostly by AI?

I've been building with AI assistants and noticed a pattern I can't unsee: the
code always LOOKS clean (formatted, commented, confident) but when I read it I
keep finding API keys hardcoded in files, SQL built by string concatenation,
shell commands assembled from user input.

So I'm curious:
1. Do you review security before shipping, or only when something breaks?
2. What have you caught that surprised you?
3. Anyone using tooling for this, or is it all manual eyeballing?

(Happy to share what I use if it's useful — mostly here to hear how you all
handle it.)
```

## DM — după „da, vreau" (fără link de vânzare în primul mesaj)

```
Nice — here you go: [link]. No signup; paste your code and hit Scan.
Two things I'm trying to learn:
1. Does the report make sense? (severity + fix suggestion)
2. What did it miss?
Tell me honestly — good or bad, both help. 🙏
```

## Ce NU facem (altfel = ban)
- ❌ Link în primul mesaj / „check out my tool"
- ❌ Același text în 2 comunități (rescrie titlul + primul paragraf)
- ❌ DM către useri care nu au cerut (Bolt interzice explicit)
- ❌ Mai mult de 1-2 postări/zi

## Tracking (completează la fiecare contact)

| Data | Comunitate | Ce am postat | Cine a răspuns | A cerut tool? | Feedback | Follow-up |
|---|---|---|---|---|---|---|
|  |  |  |  |  |  |  |

## ONEST
- **Eu nu pot posta** — necesită contul tău Discord/Reddit (nu postez în numele tău).
- PC-ul e acasă, tu ești la Lukoil → co-pilot pe browser nu e disponibil acum; **postezi de pe telefon** când ai un minut.
- Alternativă: când ești la PC, pot conduce eu browserul (Playwright) și tu doar aprobi fiecare mesaj.
