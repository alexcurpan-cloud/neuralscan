# NeuralScan — plan de decizie (2026-10-02)

> Pregătit de Argus (1-Oct) pentru sesiunea de mâine. **Alex decide direcția, Alex execută; Argus asistă.**
> Regulă: fără presupuneri. Fiecare afirmație are dovadă sau e marcată `[PRESUPUNERE]`.

## 0. DECIS (1-Oct, Alex): direcția = STUDIUL PUBLIC
> Alex (1-Oct, 12:24): „să folosim anumite repo-uri sau aplicații, să facem teste pe ele și pe baza testelor să încercăm să atragem oameni. Cred că asta e cea mai bună idee."

**Forma concretă:** scanăm app-uri / repo-uri publice (made with AI) → scoatem cifre → publicăm rezultatul → proprietarii reacționează = conversații (lead-uri).
**Metric de succes:** conversații / lead-uri, NU views.

### Reguli nenegociabile (altfel = postări șterse / risc legal)
- DOAR app-uri publice sau cu **acord scris**; NICIODATĂ chei API / baze de date ale altcuiva.
- Publice = **agregate (cifre)**, nu numirea unui app anume fără acord.
- Când contactăm un proprietar → ofertă de **scan gratuit**, fără obligații.

## 1. Unde stă NeuralScan ACUM (dovedit 26-Sep)
| Aspect | Stare | Dovadă |
|---|---|---|
| Cod | ✅ sănătos | 106/106 teste; toate găurile reale reparate (C1–C7) |
| API | ✅ complet | /scan · /scan/zip · /health · /stats · /admin/keys |
| **Live** | ❌ NU | 404 pe ambele domenii; nimic pornit local |
| Motiv | oprit INTENȚIONAT (3-Sep) | trial Railway expirat |

**Concluzie:** „funcțional ca bibliotecă/API" ≠ „live ca serviciu". **Produsul există; distribuția nu.**

## 2. Lecția care guvernează decizia (18-Sep, de la Alex)
- Produsul n-a fost respins de piață — **nu l-a văzut nimeni**. Distribuția n-a existat de la început.
- ⇒ **Audiența e PRECONDIȚIE, nu pistă paralelă.** Nu plătim hosting ca să fim singurii vizitatori.
- Scopul real (Alex, 26-Sep 03:39): **să nu mai lucreze ture de noapte.** Client plătitor = ieșirea din ture.

## 3. Decizia centrală: plătim Railway sau nu?

**Opțiunea A — ZERO COST** *(recomandată ca start)*
- Nu plătim nimic. NeuralScan rulează local, scanări reale, zero cost.
- Alex: lansează formularul de intake (cu consimțământ) + începe **studiul public** [PROPUS 26-Sep].
- Deploy plătit **doar când există cerere reală** (trafic / oameni care cer link).
- Riscul: lipsește linkul „live". Mitigare: scanarea o facem noi, trimitem raportul.

**Opțiunea B — PLATIT MIC** (Railway ~$5/lună)
- Link live permanent → credibilitate la outreach.
- Riscul: **exact capcana din 18-Sep** — plătim o vitrină fără vizitatori. Cost recurent.

**Opțiunea C — HOSTING GRATUIT** *(de verificat de Argus)*
- Există free tier (Render / Fly / HF Spaces) pentru demo fără cost recurent?
- Argus verifică dacă Flask-ul intră pe free tier fără schimbări majore. Nu plătim, avem link.

## 4. Întrebări la care răspundem mâine (Alex decide)
1. ~~Direcția~~ ✅ **DECIS 1-Oct: studiul public** (scanăm repo-uri/app-uri publice → publicăm cifrele → atragem oameni).
2. **N** (10 / 20 / 50) + sursa app-urilor.
3. **Promisiunea exactă** (o propoziție).
4. **Hosting:** A / B / C.
5. **Formularul de intake** — îl construim mâine? (pârghia legală + motorul de lead-uri)

## 5. Ce poate face Argus mâine, fără să ceară voie
- Verifică dacă Flask-ul intră pe un free tier (opțiunea C) — zero cost.
- Pregătește scheletul formularului de intake (Tally / Google Form).
- **Nimic cu cost fără aprobarea lui Alex.**

## 6. Reamintire de buget
- Buget $2/zi. Railway nou = cost recurent → **decizia e a lui Alex, nu a mea.**
