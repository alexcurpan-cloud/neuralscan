# NeuralScan

Plasa de siguranță pentru cei care nu pot citi codul.

## Ce e
Scanner de securitate cu raport în limbaj SIMPLU, pentru non-devi care
construiesc cu AI (Lovable, Cursor, Bolt, Claude Code, Replit). Prinde
riscuri în codul scris de AI, le explică FĂRĂ jargon și dă un fix-prompt
de copiat înapoi în agent.

## Pentru cine
Non-devul speriat că i-a scris AI-ul o gaură în cod. NU e pentru devi
(ăia au deja gitleaks/semgrep). Diferența = traducerea + încrederea.

## Cum funcționează (pe scurt)
1. Primește codul (fișier / folder / mai târziu zip sau link repo).
2. Scanează cu unelte gratuite (gitleaks, semgrep) — local, nu se stochează.
3. Un LLM ieftin traduce rezultatele în limbaj simplu + scrie fix-prompt-ul.
4. Îți dă un raport calm: ce e riscul, cât de grav, cum îl repari.

## Ce prinde acum (6 categorii)
- Secrete expuse (chei/parole în cod)
- SQL injection
- Command injection
- Debug/RCE (cod care poate fi executat de la distanță)
- Criptare slabă
- HTTP (trafic necriptat)

## Structura proiectului
- src/ codul aplicației
- tests/ cazuri de test (inclusiv smoke test)
- samples/ cod străin pt derisk (NU se urcă în git)
- docs/ context + note

## Status (iul 2026)
- MVP funcțional: prinde 6/6 categorii, verificat cu dovadă.
- UI + raport în RO; traducere EN în lucru (aliniere piață globală).
- Waitlist Tally live.

## Planul acum (nu sări peste)
1. SMOKE test: cod propriu + o cheie plantată → confirmă că țeava merge. 10 min.
2. DERISK: 1-2 proiecte STRĂINE (nescrise de mine) → crapă? / prinde ceva
 real? / cât țipă degeaba (false positives)? Precizia = jobul greu, nu detecția.
3. POWER TEST: cod real al unor oameni reali, concierge, urmăresc REACȚIA.
Pass/fail se scrie ÎNAINTE de test. REGULĂ: nu construi feature-uri noi
până nu validez cererea cu useri reali.

## Principii
- Buget 0: doar unelte free / pay-per-use. Zero abonamente.
- Trust: codul e procesat local, nu se stochează.
- Non-dev-first + protocol de dovadă (verific, nu cred pe cuvânt).

## Ce NU e (parcat)
NU e securitate de agent la runtime (prompt injection / output guard /
observability) — ăla e ocean roșu cu giganți (Lakera, Fiddler etc.).
Rămân pe codul non-devului.
