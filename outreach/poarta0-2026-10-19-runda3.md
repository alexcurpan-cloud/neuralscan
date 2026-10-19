# Poarta 0 — runda 3 (19-Oct-2026, code search + filtru de valoare)

Token GitHub: `public_repo`, expiră 7 zile. Script: `outreach/find_targets_secrets.py`.
Runda 1 și 2 = 0 findings reale (env var names, chei Firebase publice, constante i18n).
Runda 3 (25 repo scanate din 111 candidate) = **3 candidați reali**, verificați manual pe cod.

## Candidați REALI (verificați linie cu linie)

| # | Repo | Ce e expus | Fișier | Ultim push | Contact |
|---|---|---|---|---|---|
| 1 | `tonszazo-lang/raqqa` | cheie OpenAI `sk-proj-_nBz…` hardcodată | `config.py:9` | 2025-11-18 | tonszazo@gmail.com |
| 2 | `NemroNeno/LinkedIn_messaging_agent` | cheie OpenAI `sk-proj-PDH5…` hardcodată | `op.py:21` | 2025-07-04 | mnabeel.bese22seecs.seecs.edu.pk |
| 3 | `365assist/bibleaf` | credențial admin hardcodat `admin@bibleaf.com` / parolă în clar | `lib/auth.ts:82`, `app/test-login/page.tsx` | 2025-06-13 | — (fără email public) |

**Nu am folosit/validat cheile** — nu se testează chei găsite; se raportează proprietarului.

## Respins ca fals-pozitiv (dovedit)
- `synaptent/aragora` (6) — `# nosec`, regex-uri, enum-uri (`createSecret`)
- `crisvard/kitoai` (1) — `sk_live_51SfTiJ…XXXX…XXXX` = placeholder
- `Ritenoob/ridedine` (1) — seed demo `demo1234` (trebuie adăugat filtru pe `seed.ts`)
- `mshalmanov/TinderBolt` (1) — `token="chatgpt-token"` = placeholder

## Regulă de proces
Pentru **chei leaked** NU se postează issue public (ar arăta tuturor unde e cheia).
Contact privat (email/DM) → 48h → un follow-up.

## Mesaje gata de trimis

### 1. tonszazo-lang/raqqa (email, EN)
Subject: Your OpenAI API key is committed in config.py (public repo)

Hi,

I scan public repos built with AI for exposed credentials — no automated spam, I checked this by hand.

`config.py` line 9 in your repo `raqqa` contains an OpenAI key (`sk-proj-_nBz…`) committed in plain text. Anyone who opens the file can use it on your account.

Two things, in this order:
1. Revoke the key in OpenAI dashboard → API keys (deleting the file is not enough, it stays in git history).
2. Replace it with `os.environ.get("OPENAI_API_KEY")` and add `config.py` secrets to `.env`.

I did not use or test the key. Happy to explain how I found it if useful.

Alex

### 2. NemroNeno/LinkedIn_messaging_agent (email, EN)
Subject: OpenAI API key committed in op.py (public repo)

Hi,

I check public repos for exposed credentials — this one I verified manually.

`op.py` line 21 has an OpenAI key (`sk-proj-PDH5…`) hardcoded in the `ChatOpenAI(...)` call. It is public and usable by anyone who reads the file.

Fix: revoke it in the OpenAI dashboard (removing the line is not enough — it stays in git history), then read it from an environment variable.

I did not use the key. Reply if you want the exact steps.

Alex

### 3. 365assist/bibleaf (fără email — issue privat sau contact din profil)
Subject: Admin credentials hardcoded in auth.ts

Hi,

`lib/auth.ts` contains a hardcoded admin account (`admin@bibleaf.com`) with a plaintext password, also duplicated in `app/test-login/page.tsx`. If the app is deployed, that account is a working admin login.

Recommendation: remove the hardcoded user, move test accounts behind a dev-only flag, and rotate the password.

I found this while checking public repos by hand. Alex

---

## DECIZIE (19-Oct 13:30, Alex)
- **Trimitem DOAR către `tonszazo-lang/raqqa`** — email pe `tonszazo@gmail.com`, din Gmail-ul lui Alex.
- `NemroNeno` — **skip**: emailul din commit e malformat (`mnabeel.bese22seecs.seecs.edu.pk`, lipsește @);
  trimiterea către colaboratori ar însemna să spunem unei terțe persoane unde e cheia.
- `365assist/bibleaf` — **skip**: auth mock cu localStorage + useri hardcodați (demo), fără email uman
  (commit-uri de la `vercel[bot]`). Severitate mică.
- Regulă confirmată: pentru chei leaked **nu** postăm issue public.

## Status
- [x] email trimis de Alex (Gmail), 19-Oct 14:05 — subiect verificat de Alex
- [ ] răspuns (48h) → se trece în tabel
