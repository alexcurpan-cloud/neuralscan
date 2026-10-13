# Studiu public NeuralScan — schiță

> Capturat 26-Sep-2026, 03:24 (Alex, la final de tură de noapte). Status: **[PROPUS] — de transformat în plan pe 7 zile.**
> Nu e task aprobat; e ciorna ca să nu se piardă ideea peste noapte.

## Ideea
Un **studiu public**, nu un pitch: scanăm N app-uri publice făcute cu AI și publicăm **agregatele (cifrele)**, nu tool-ul.

## Pași
1. Alegem sursa + N (start **10–20**, țintă 50) — app-uri publice (Lovable/Bolt/Cursor, ProductHunt, X #buildinpublic)
2. Punem NeuralScan la punct pentru **scanare reală** (pipeline + raport)
3. Filmăm testele + rezultatele (sau videoclip generat cu AI) → cifrele în față
4. Publicăm agregatul → fiecare proprietar de app reacționează = conversații

## De ce (rezolvă 3 blocaje deodată)
- **Date la alt nivel:** date reale, ale noastre = conținut + credibilitate
- **Test cu useri reali:** proprietarii app-urilor scannate
- **Vizibilitate:** un studiu cu cifre **nu e self-promo** → moderatorii nu-l șterg

## Reguli de siguranță (nenegociabile)
- DOAR app-uri **publice** sau cu **acord scris**
- **NICIODATĂ** chei API / baze de date ale altcuiva

## Metric de succes
**Conversații / lead-uri**, NU views.

## Deschis (de decis mâine)
- N final (10 / 20 / 50)
- Sursa celor N
- Promisiunea exactă (o propoziție)

---

# RESEARCH: de unde recoltăm app-urile (25/26-Sep)

## ⚠️ Regula zero (altfel = dosar penal / postări șterse)
**NU scanăm app-uri la întâmplare.** Scanarea unui site terț fără acord = risc legal real.
Singura cale curată: **OWNER-UL ÎȘI DĂ ACORDUL**.
Pârghia = un **formular de intake** (Tally / Google Form) cu:
- link app + email + **bifă de consimțământ** explicit („îmi dai permisiunea să analizez app-ul de la linkul X").
Bifa aia = scutul legal **și** dovada de opt-in **și** conversația cu userul real. Un singur artefact le face pe toate.

## Surse (de la cea mai bună la cea mai grea)

### A. Galele platformelor — makerul A PUBLICAT deja app-ul (consimțământ cel mai ușor)
- **Lovable:** `launched.lovable.dev` (galerie tip Product Hunt, cu upvotes) · secțiunea „From the Community” de pe `lovable.dev` · `lovable.dev/videos/Community`
- **Galerii third-party:** `madewithlovable.com` · `madeinlovable.com`
- ✅ Aici ownerul e mândru; un DM „pot să-l scanez gratis?” are rată mare de răspuns.

### B. Reddit — își postează singuri app-urile
- `r/lovable` (thread-uri „Show your fully working app”) · `r/vibecoding` · `r/VibeCodeDevs` · `r/vibecodingcommunity` · `r/replit` · `r/SideProject` · `r/indiehackers` · `r/SaaS`
- ⚠️ NU posta pitch (ți-l șterg moderatorii). **Comentează la postarea LOR:** „bravo! vrei un scan gratuit de securitate? îți dau raportul, fără obligații.”

### C. Directoare / launch sites
- **Product Hunt** — API oficial + scrapere Apify (filtrezi lansările recente; tagline cu AI/Lovable/Bolt)
- **Delt.dev** — comunitate făcută special pt app-uri vibe-coded (Replit/Lovable/Bolt/Cursor)
- MicroLaunch · Uneed · Peerlist · BetaList · TinyLaunch

### D. Discord (comunitățile oficiale ale tool-urilor)
- Lovable · Bolt.new · vibecoding · Cursor · v0 → canalul #showcase. (Ai încercat; probabil ai pitch-uit, nu ai cerut.)

### E. X / LinkedIn
- `#buildinpublic` · „built with @lovable_dev” · „vibe coded” → DM scurt, personal.

### F. Hackathoane
- **Devpost** (proiecte publice, makeri receptivi) · Global Game Jam (site-uri locale)

## Recomandarea mea: start cu A + B (20 de app-uri)
1. `launched.lovable.dev` + `madewithlovable.com` → alege 20 → DM makerii
2. `r/lovable` + `r/vibecoding` (thread-uri „show your app”) → comentează cu oferta de scan gratuit
3. Restul (D–F) umple până la N

**Intake form-ul** construit întâi (e pârghia legală + motorul de lead-uri).

---

## De ce (motivul real, spus de Alex 26-Sep, 03:39)
**Scopul real: să nu mai lucreze ture de noapte.** Nu faimă, nu „dat în stambă" — un tool care îl scoate din ture. Realist: nu în săptămânile următoare.
Consecință de reținut: **clientul plătitor = ieșirea din ture.** Iar clientul are încredere doar în cineva care lucrează **curat** (anunță înainte, nu face nimic distructiv). Deci „profesionist" nu e frâna visului — e calea spre el.
