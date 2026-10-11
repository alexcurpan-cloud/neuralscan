# DM Pack — outreach direct în privat (nu în comunități) · 2026-10-11

> Decizie Alex: „Copy-paste-ul trebuie să fie direct în PM, tocmai că în comunități nu am vizibilitate."
> Deci: **nu postăm public**, scriem **DM**. Dar DM-ul trebuie să treacă filtrul „om serios", nu spam.

## Regula care face diferența
**Scriem DOAR oameni care AU arătat deja problema** (au postat „mi s-au expus cheile", „e sigur app-ul meu?", „cum securizez?").
DM către om rece = spam → report/ban. DM către om cu problema = ajutor → răspuns.
Dovadă: caută în r/lovable, r/boltnewbuilders, r/vibecoding, r/nocode, Discord Lovable/Bolt.

## Cele 4 template-uri (copy-paste)

### A) DM după ce a postat despre problema (principalul)
```
Hey — saw your post about [cheile expuse / app-ul nesigur / nu știi dacă e ok].
I hit the same wall: the generated code looked clean, but had a key inlined in
a client file. Took me a while to even know what to look for.

I made a small local tool that scans for exactly this (hardcoded keys, SQL
injection, command injection) and explains each one in plain language + a fix
you can paste back into your AI tool. Nothing leaves your machine, no signup.

Want me to run it / send it? Free — I just want honest feedback on whether the
report makes sense.
```

### B) DM către un builder AI (fără problemă expusă, dar public relevant)
```
Hey — saw you're building with [Lovable/Bolt/Cursor]. Quick question since I'm
working on this myself: do you check the generated code for security before
you ship, or mostly when something breaks?

I keep finding the same things (API keys in frontend, SQL by string concat).
Built a small local scanner for it. If you want, I'll scan one of your projects
free — you tell me if the report is useful or noise. Cool?
```

### C) DM după „da, vreau"
```
Nice — here it is: [link]
No signup; paste your code (or upload a zip) and hit Scan. Takes 2 min.

Two things I'm trying to learn:
1. Does the report make sense? (severity + the fix suggestion)
2. What did it miss / what would make you use it weekly?

Honest is best — bad feedback helps me more than "looks good". 🙏
```

### D) Follow-up (48h, doar dacă nu a răspuns)
```
No pressure at all — just closing the loop. If it's useful, great; if not,
tell me what would make it useful and I'll leave you alone. 🙂
```

## Ținte reale găsite (verifică recența înainte de DM!)
| # | Unde | Post | Subiect | Recență |
|---|---|---|---|---|
| 1 | r/nocode | `1jjvvxk` | „API keys exposed in chat and publicly visible" | Mar 2025 — vechi |
| 2 | r/lovable | `1mx3vsk` | „How do you ensure security in your apps?" | Aug 2025 |
| 3 | r/boltnewbuilders | `1jdkv11` | „Anyone have their API keys exposed on Frontend?" | Mar 2025 — vechi |
| 4 | r/vibecoding | `1rhlgdt` | „Audited a friend's Lovable app, found an exposed API key" | Mar 2026 — RECENT |
| 5 | r/lovable | `1lc68ac` | „Adding secret api key in custom app" | Iun 2025 |
| 6 | r/vibecoding | `1ryy6c6` | „how to ACTUALLY secure your vibecoded app" | Mar 2026 — RECENT |

> ⚠️ Prioritare = cele recente (4, 6) + comentatorii de pe ele. Cei vechi (2025) sunt probabil inactivi.

## Cum găsesc ținte (5 min/zi, pot face eu)
Caut zilnic postări/comentarii noi unde oamenii descriu exact problema noastră
(chei expuse, app nesigur, „e safe?"). Îți dau lista cu link direct → tu dai DM.
Reddit API e blocat pe IP-ul nostru fără OAuth → folosesc search public (Brave).

## Ce NU facem
- ❌ DM la rece, în masă (report → ban cont)
- ❌ Link în primul mesaj DM pe Reddit (arată a spam)
- ❌ Bolt/serverul Bolt: regulile interzic explicit reclama în DM → acolo doar varianta B, ca „help"
- ❌ Mai mult de ~5 DM-uri/zi

## ONEST
- **Nu pot trimite DM-uri eu** — cere contul tău (Reddit/Discord). Le pregătesc, tu le trimiți.
- Când ești la PC, pot conduce browserul și tu doar lipești/aprogi (co-pilot Playwright).

## Tracking
| Data | Platformă | Către | Ce am trimis | A răspuns? | A cerut tool? | Feedback |
|---|---|---|---|---|---|---|
|  |  |  |  |  |  |  |
