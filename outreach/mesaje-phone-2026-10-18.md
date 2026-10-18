# Outreach — pachet de trimis de pe TELEFON (2026-10-18, day_shift)

> Verificat live azi 07:05: toate 3 fișiere răspund 200, issues ON pe toate 3 repo-urile,
> owner-i activi (push 16–17 Oct), **zero email public** → singurul canal = issue public.
> Regulă: în text NU apare valoarea secretului, doar fișier + linie + ce e.

## Pași (telefon, ~12 min)

1. Deschide `github.com` în browserul telefonului → verifici dacă ești logat (avatar dreapta sus).
2. Dacă nu ești logat: **Sign in** cu user + parolă (sau passkey). Orice cont GitHub merge — repo-urile sunt ale altora.
3. Deschide linkul `.../issues/new` al repo-ului (mai jos).
4. **Title** = lipește titlul. **Body** = lipește textul. → **Submit new issue**.
5. Repetă pentru celelalte 2. Ordine: 1 → 2 → 3 (risc financiar descrescător).

**Dacă un repo nu are buton de issue** (issues dezactivate între timp) → sari la următorul și spune-mi.

---

## 1 · rejuan0066-crypto/edumate-bd  (cheie API plătită — risc financiar)

Link: https://github.com/rejuan0066-crypto/edumate-bd/issues/new

Title:
`Didit API key hardcoded in client code (src/lib/diditService.ts)`

Body:
```
Hi! Checking AI-generated repos, found a real issue in yours — purely to help.

src/lib/diditService.ts, line 32 hardcodes DIDIT_DEFAULT_API_KEY. That's client code, so the
key ends up in the browser bundle → anyone can use your Didit account (KYC calls cost money,
and they touch identity data). The same key also appears in
supabase/functions/env.manifest.json.

Fix: rotate the key in the Didit dashboard, move it server-side (env var / edge function),
rebuild. Rotating matters more than moving it — it's public now.

I can send the exact line privately. Want the free full scan report too?

— Alexandru (independent dev, Romania)
```

---

## 2 · alhk10/gaonhae-hr  (parolă de admin în frontend public)

Link: https://github.com/alhk10/gaonhae-hr/issues/new

Title:
`Hardcoded admin password in a public file (src/pages/public/PublicGradingList.tsx)`

Body:
```
Hi! Found this while checking AI-generated code — purely to help, no strings attached.

src/pages/public/PublicGradingList.tsx, line 126 hardcodes ADMIN_UNLOCK_PASSWORD as a
plain string. That file ships to the browser, so anyone can read the value from the page
bundle and unlock the admin grading view.

Fix: change the password (it's public now) and move the check server-side / to an env var.

I can send you the exact value and the related file paths privately — where should I send
them? I'm building a security scanner for AI-built apps and this is one of the checks;
happy to run the full report on this repo for free if you want it.

— Alexandru (independent dev, Romania)
```

---

## 3 · Bruxaok122/indicadorprobr  (3 credențiale expuse)

Link: https://github.com/Bruxaok122/indicadorprobr/issues/new

Title:
`Hardcoded credentials in setup-admin / whatsapp-webhook (public repo)`

Body:
```
Hi! Checking AI-generated repos, found something in yours — purely to help, no strings attached.

1) supabase/functions/setup-admin/index.ts, line 21: admin email + password are hardcoded
   as plain strings.
2) supabase/functions/whatsapp-webhook/index.ts, line 9: VERIFY_TOKEN hardcoded.
   The same token also appears in src/pages/WebhookPage.tsx, line 21.

Repo is public, so treat all three as leaked. Fix: rotate the password and the token, move
them to Supabase secrets (supabase secrets set ...), redeploy. Also change the admin password
if that account was ever created.

I can send the exact lines privately — where? (Building a scanner for AI-built apps; happy to
run the full report on this repo, free.)

— Alexandru (independent dev, Romania)
```

---

## Tracking (completează după trimitere)

| Data | Repo | Canal | Trimis | Răspuns | A cerut raport? | Feedback |
|---|---|---|---|---|---|---|
| 2026-10-18 07:14 | rejuan0066-crypto/edumate-bd | issue **#1** | ✅ | — | — | open, verificat API |
| 2026-10-18 07:26 | alhk10/gaonhae-hr | issue **#1** | ✅ | — | — | open; titlu corectat după ce a fost parazitat de copy |
| 2026-10-18 07:32 | Bruxaok122/indicadorprobr | issue **#1** | ✅ | — | — | open, verificat API |

**Dovadă (API, 07:33):** toate 3 → `#1 open`, autori `alexcurpan-cloud`, titluri curate.

Follow-up: o singură dată, la **48h → marți 20-Oct 09:00**, ton „no pressure". Job cron programat.

## Lecție de proces (18-Oct)
Mesajele lungi cu titlu + body + confirmări în ACELAȘI text de chat → copy-ul de pe telefon ia tot blocul.
**Regulă nouă:** titlul se trimite SINGUR, pe un mesaj separat, fără niciun alt rând în el.

## Program următor (cerut de Alex 18-Oct)
- **19-Oct = night_shift** → lucrăm dimineața până seara.
- **După tura de noapte: 3 zile libere** → build + validare în volum.
- **19-Oct 09:00 = follow-up CONIQ** (memento deja setat).
