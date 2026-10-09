# Free checks — runda 1 (2026-10-09) — 5 repo-uri publice AI-built

> Metodă: `neuralscan/neuralscan-cli.py <dir>` local (zero cost, zero API). Cod = public (legal).
> Scop: dovada că prinde pe cod real + material outreach/content. **Rezultate BRUTE, inclusiv cele proaste.**

## Rezultate

| Repo (public) | Fișiere | Findings | Reale | Zgomot |
|---|---|---|---|---|
| `rye-com/rye-lovable-demo` (Lovable, ecommerce) | 79 | 2 | 0 (token Stripe de TEST `tok_visa`) | 1 (package-lock) |
| `Sathish292004/E-comUpdatedVersion` (Lovable, storefront+admin) | 119 | 4 | **1 CRITIC REAL** | 3 (package-lock) |
| `TalismanForgeX/G2G-Properties` (Lovable, agenție imobiliară) | 80 | 0 | — | — |
| `gptme/gptme-webui` (built with lovable.dev) | 160 | 2 | 0 | 2 (lockfile + comentariu cod) |
| `adrianokerber/book-api-py` (Cursor, Python) | 1 | 0 | — | — |

## Finding REAL (genuin) — `Sathish292004/E-comUpdatedVersion`

`src/routes/admin.profile.tsx:13`:
```js
const DEFAULT_ADMIN_PASSWORD = "Sathsih@2004";
```
- Parolă de admin **hardcodată în repo public** + auth pe client (localStorage) → oricine citește repo-ul
  poate intra în panoul de admin. **Broken authentication real** (nu teoretic).
- Context: storefront + panou admin, e-commerce.

## PROBLEMĂ DE PRODUS găsită (onest): zgomot din lockfile
- 4 din 5 repo-uri JS au `hardcoded_jwt` în **`package-lock.json`** → **FALS-POZITIVE** (hash-uri de integritate, nu secrete).
- `insecure_http` în `smd.js` = comentariu (`http://example.com`) → FP.
- **Consecință:** pe orice repo JS real, raportul e dominat de zgomot → ne arde credibilitatea în outreach.
- **Fix necesar:** skip lockfiles (`package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`) + NU scana comentarii.

## Concluzie onestă
- Scannerul prinde **real** pe backend (Python/JS code) — dovadă: 1 finding critic genuin.
- Pe **frontend TS**, zgomotul din lockfile maschează rezultatul → de reparat ÎNAINTE de outreach serie.
- Corpus existent (24-Sept, 59 repo) rămâne baza solidă (92 incidente, ~2% FP) — dar rularea de azi
  arată clar că unealta trebuie curățată de lockfile-noise.

## Următor
1. Fix scanner: skip lockfile + comentarii → rapoarte curate.
2. Finding real (parolă admin) → outreach RESPONSABIL (DM privat autorului, nu post public).
3. Extind checks pe repo-uri cu **backend** (unde scannerul excelează).
