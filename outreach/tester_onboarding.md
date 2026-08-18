# Pachet onboarding — primul tester NeuralScan

> Cheie: `NEURALSCAN_TESTER_KEY` (în .secrets.json) — se activează pe Railway la confirmare.
> Format cheie: `ns_...` — se trimite testerului DOAR prin canal privat (WhatsApp/email direct), niciodată în chat public.

## Ce primește testerul (text de trimis, scurt și uman)

```
Bună [Nume]! Ți-am pregătit acces gratuit de test la NeuralScan — scannerul
nostru de securitate pentru site-uri/cod. Cu cheia asta poți scana ce vrei
(cod, site propriu) și primești un raport pe înțelesul omului, cu ce e
vulnerabil și cum se repară.

Cheia ta de test: [KEY]

Cum o folosești (exemplu cu site-ul tău):
  - ne trimiți codul/site-ul pe care vrei să-l verificăm
  - noi rulăm scanul și îți dăm raportul — tu nu faci nimic tehnic

Dacă vrei, te sun mâine și îți arăt un exemplu de raport pe un site real.
```

## Cum folosește API-ul (referință tehnică pentru noi)

```bash
# Scan cod
curl -X POST https://neuralscan-production.up.railway.app/scan \
  -H "Content-Type: application/json" \
  -H "X-API-Key: <KEY>" \
  -d '{"code": "API_KEY = \"sk-1234567890abcdef\"", "filename": "test.py"}'

# Health check
curl https://neuralscan-production.up.railway.app/health
```

- Rate limit cu cheie: 300 req/min (anonim: 30/min per IP)
- Input max: 100KB cod
- Răspuns: `findings` (tehnic) + `report` (non-dev, cu fix prompt)

## Flux pentru primul tester (cine zice „da")

1. Confirmare pe WhatsApp/telefon (de la Alex)
2. Activăm cheia pe Railway (`NEURALSCAN_API_KEYS` += tester key) + redeploy
3. Trimitem mesajul de mai sus cu cheia
4. Testerul trimite ce vrea scanat (cod / site) — noi rulăm
5. Raportul: `strix_runs/` sau scan direct NeuralScan → îl traducem omenește
6. Feedback: ce a înțeles, ce l-a convins, ce l-a blocat → tracking

## Preț (etapa actuală — model adoptat 18-Aug, validat extern)

- **Free:** 1 scan static + raport sumar (funnel)
- **$19/lună:** scan-uri statice nelimitate, rapoarte complete, fix prompts, istoric
- **Deep Scan (Strix, AI):** credite separate / plan $49-99 cu limită explicită — NU unlimited la $19 (cost real $2-4/run)
- Pensiuni locale: prima ofertă rămâne scan gratuit + raport (dovada plății vine din închiderea unui client)

## Ce NU facem

- NU scanăm site-uri ale altora fără acord explicit (legal)
- NU promitem „0 vulnerabilități" — raportul e onest (vezi demo: RCE neconfirmat = notat)
- NU stocăm codul scanat (doar metadate: key_id, mărime, findings count)
