# NeuralScan — PACK pentru mâine dimineață (2026-10-02)

> Pregătit de Argus, 1-Oct, la cererea lui Alex („pune ce trebuie pe masa pentru mâine dimineață").
> Direcție DECISĂ: **studiu public** (scanăm repo-uri/app-uri publice → cifre → atragem oameni).
> Toate elementele de mai jos sunt **zero cost** și gata de executat.

---

## 1. HOSTING — verdict (opțiunea C, dovadă)

| Dovadă | Rezultat |
|---|---|
| requirements.txt | `flask`, `flask-limiter`, `gunicorn`, `pytest`, `psycopg[binary]` |
| Procfile | `gunicorn src.app:app --bind 0.0.0.0:${PORT:-8000}` |
| Cod | ~2.474 linii, SQLite implicit (Postgres DOAR opțional) |
| Redis / dependențe grele | ❌ niciunul |

**Verdict: intră pe free tier (Render / Fly.io / HF Spaces) fără schimbări majore.** Nu plătim hosting ca să pornim.
- Caveat: free tier → doarme / 1 worker; rate-limit pe memorie nu ține la restart (deja raportat 26-Sep). Pentru un demo de studiu = acceptabil.
- ⚠️ Hosting NU e necesar la start: scanarea din studiu se face **local, zero cost**. Link-ul public îl adăugăm doar dacă apare cerere.

---

## 2. FORMULAR DE INTAKE (gata de copiat în Tally / Google Forms)

> Rol: pârghia legală (consimțământ) + motorul de lead-uri. Un singur artefact le face pe toate.

1. **Link app / repo** — obligatoriu, text
2. **Tip** — dropdown: `App live` / `Repo public`
3. **Email de contact** — obligatoriu
4. **Cu ce l-ai construit?** — dropdown: Lovable / Bolt / Cursor / Replit / v0 / Altul
5. **✅ Consimțământ (obligatoriu):** „Îmi dai permisiunea să analizez codul/aplicația de la linkul de mai sus și să-ți trimit raportul?" → Da / Nu
6. *(opțional)* Ce te interesează cel mai mult? — secrete expuse / injecții / dependențe
7. *(opțional)* Vrei să apară în studiul public **anonim**? → Da / Nu

---

## 3. PROMISIUNEA — 3 variante (Alexul alege una)

- **A (recomandat, fără presiune):** „Îți scanez gratuit app-ul/repo-ul și îți trimit un raport de securitate — fără obligații."
- **B (direct, durere clară):** „Găsesc gratis unde poate fi spart app-ul tău făcut cu AI și îți spun exact ce să repari."
- **C (studiu):** „Testez securitatea app-ului tău (gratis) și public un studiu cu cifre despre cât de sigure sunt app-urile făcute cu AI."

→ Recomandare: **A** la contact direct, **C** ca text public al studiului.

---

## 4. SURSE — de unde recoltăm primele app-uri (din 26-Sep)

1. **Galerii de platformă** (ownerul e mândru → rată mare de răspuns):
   `launched.lovable.dev` · `madewithlovable.com` · `madeinlovable.com`
2. **Reddit** (își postează singuri app-urile): `r/lovable` · `r/vibecoding` · `r/VibeCodeDevs` · `r/replit` · `r/SideProject`
   ⚠️ NU posta pitch (șters de mods) → **comentează la postarea LOR** cu oferta de scan gratuit.
3. **Directoare:** Product Hunt · Delt.dev · MicroLaunch · Uneed

**Start recomandat:** A + B → primele 20.

---

## 5. PLAN EXECUTABIL — prima săptămână (Alex execută, Argus asistă)

| Zi | Alex | Argus |
|---|---|---|
| 1 | Decide N + sursă + promisiune; publică formularul | Construiește lista de candidați |
| 2 | — | Scanează local 20 (zero cost) → rapoarte |
| 3 | Trimite 10–15 DM/comentarii (ofertă gratuită + link formular) | Pregătește textele |
| 4 | Publică primul **agregat (cifre)** — YT Shorts/TikTok/LinkedIn | Compune cifrele din scanări |
| 5–7 | Răspunde conversațiilor, trimite rapoarte | Urmărește răspunsurile |

**Metric de succes: conversații / lead-uri. NU views.**

---

## 6. DECIZII RĂMASE (doar Alex le poate lua)
1. **N** — 10 / 20 / 50?
2. **Sursa** — de unde recoltăm primele?
3. **Promisiunea** — A / B / C?
4. **Platforma formularului** — Tally / Google Forms?
