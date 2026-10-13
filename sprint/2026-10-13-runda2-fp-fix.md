# Runda 2 free-checks + fix FP (2026-10-13, seară)

> Obiectiv Alex: „hai să vedem dacă deblocăm primul client plătitor".
> Regula: **niciun mesaj de outreach fără finding REAL verificat manual.**

## Ce am rulat
`outreach/find_targets.py --max 35` → 24 candidați găsit, 3 cu hits „serioase".
**Am verificat manual fiecare finding pe cod** (clonat + citit liniile). **Verdict: 3/3 = FALS-POZITIVE.** Din nou zero findings reale.

| Repo | Finding raportat | Verdict real (dovadă) |
|---|---|---|
| `MODOBOOK/modobook-uk` | `hardcoded_jwt` critical (×2) în `supabase/migrations/*.sql` | **FP** — **signed URL** Supabase pt un logo: `?token=eyJ...` payload `{url, scope:"download", exp:2036}`. Nu e credential de acces. |
| `MODOBOOK` + `ggsali/muscio-hub` | `hardcoded_password` high — `token: '123456'` | **FP** — date **SAMPLE** într-un template de preview email (`SAMPLE_DATA`, `reauthentication`). |
| `afterthought/crew` | `command_injection` critical (×5) în `plugin/lib/plan.py` | **FP** — `subprocess.run([...])` **formă de LISTĂ**, fără `shell=True`. Nu e injectabil. |

## Fix-uri aplicate în scanner (dovedite înainte/după, aceleași repo-uri)
1. **`_jwt_is_public`** — JWT cu payload `scope: download/upload` (Supabase storage signed URL) → nu mai e „JWT critic".
2. **`_password_match_is_noise`** — valoare pur numerică ≤ 8 cifre (`'123456'`) → placeholder SAMPLE, nu parolă.
3. **`_is_safe_subprocess_list_call`** (nou) — `subprocess.*([...])` fără `shell=True` → nu e injectie shell; `os.system`/`os.popen`/`exec`/`shell=True` rămân raportate.

**Dovadă (același scanner, înainte → după):**
```
MODOBOOK  critical/high: 3 -> 0
muscio    critical/high: 1 -> 0
crew      command_injection: 5 -> 0   (rămân 4 path_traversal, 3 în tests/ — sărite de find_targets)
```
**Teste: 115 → 123 verzi** (+8: 3 DDL 2-linii, 5 regresie FP).

## ONEST — ce NU s-a rezolvat
- **Tot 0 findings REALE** pe 24 repo-uri. Cauza nu e (doar) scannerul: eșantionul de repo-uri publice „built with AI" e în majoritate **demo/clone fără backend** (13/24 erau „lovable-clone"). Acolo nu există nimic de găsit.
- Wedge-ul „scanez repo public → găsesc vuln → DM owner" **nu produce**. 2 runde, 38 repo-uri, 0 findings reale → se apropie de criteriul KILL din planul 90 zile („0 conversații în 4 săptămâni → se schimbă wedge-ul").

## Decizie necesară (Alex)
1. **Canalul** — unde intrăm noaptea asta? Opțiuni din `outreach/send-now-2026-10-12.md` (Product Hunt Vibecoding / r/vibecoding / Discord Lovable). **Eu nu pot posta** (Reddit IP-blocat; PH/Discord = contul lui Alex). Pot verifica linkurile live + da copy-paste curat.
2. **Schimbăm wedge-ul?** Dacă da: ținta devine „builder cu app LIVE + useri reali" (r/nocode, r/boltnewbuilders, Discord), nu „repo public oarecare". Finding-ul se dă doar când îl cere cineva.
