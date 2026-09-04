# Stripe pentru NeuralScan — plan gata de executat (2 zile)

> Status: [ ] pregătit — SE EXECUTĂ DOAR LA TRIGGER: primul client plătit spune „da".
> Decizie 19-Aug (Varianta A): vânzare manuală întâi; plăți automate după cerere dovedită.
> Model: Buildpad folosește Stripe (confirmat de Alex — „powered by Stripe" la checkout).

## Trigger
- [ ] Primul client plătit (Horia / Randy / NexusSEO / altul) → se pornește asta

## Ce vindem (aliniat cu pricing-ul existent)
| Produs Stripe | Tip | Preț | Note |
|---------------|-----|------|------|
| Pro (scan-uri statice nelimitate) | abonament | $19/lună | rate limit 300/min (deja în cod) |
| Deep Scan credit | one-time | $49-99 | Strix $2-4/run, marjă 50-70% |

## Ziua 1 — cont + produse + checkout
1. Cont Stripe (RO, verificare acte) — 0 cost upfront
2. Stripe Dashboard → Products → Pro (recurring $19) + Deep Scan (one-time $49)
3. **Stripe Checkout (hosted pages)** — NU construim flow propriu (zero PCI, zero card handling)
4. Buton „Upgrade" pe landing → Payment Link / Checkout Session

## Ziua 2 — legare cu sistemul nostru
5. Webhook Stripe → endpoint local: `checkout.session.completed` / `invoice.paid`
6. La plata Pro: `users` → `plan=pro` (tabelul există deja — Strat 2)
7. La Deep Scan: credite adăugate pe owner (tabel nou mic sau câmp)
8. Test cu card test `4242 4242 4242 4242` (sandbox Stripe)
9. UI: status plan pe /app + revocare/upgrade din admin keys (deja există revocare)

## Cost
- 0 upfront · taxe per tranzacție: 2.9% + €0.30 (standard Stripe RO)

## Ce NU facem (deliberat, din NS-LAUNCH-RISKS)
- Self-serve signup complet cu email verification
- RLS nativ / Stripe Billing complex
- Abonamente cu trial/upgrade automat — manual first, apoi rafinăm

## Reutilizează (deja există)
- users + api_keys + owner-scoping (Strat 2, 84/84 teste)
- Revocare cheie → 401 imediat (test_revoke_via_api_401)
- Rate limit per plan (free 30 / pro 300 per min)
- Admin keys (creare/revocare în prod)
