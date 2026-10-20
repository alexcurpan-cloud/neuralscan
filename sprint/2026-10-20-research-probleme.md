# Research 20-Oct-2026 — probleme unde platformele NU pot fi arbitru

> Comandă (Alex, 08:36): o zi de research, obiectiv unic — 3 probleme cu **cumpărător clar**,
> **frecvență observabilă**, **detecție care nu e deja gratuită în builder**, **motiv concret de plată**.
> Dacă nu ies 3 → alegem (a) fără regrete.
> Notă: verdictul anterior „s-a închis pe toate fronturile" a fost retractat — era bazat pe o sursă
> comercială (Launch Ready Code) cu statistici inconsistente intern (58% vs 47%).

## Metodă
4 direcții date de Alex, fiecare verificată pe surse publice (web search, 20-Oct).
Criteriul de trecere: toate 4 condițiile, ca **produs** (nu ca serviciu manual).

## Direcția 1 — IDOR / BOLA cross-tenant
| Criteriu | Verdict | Dovadă |
|---|---|---|
| Cumpărător clar | ✅ | SaaS B2B multi-tenant cu date de la mai mulți clienți |
| Frecvență | ✅ | „majoritatea finding-urilor cross-tenant" (appsecure, 4-Sep-2026); OWASP API Top 10 #1 |
| Detecție non-gratuită în builder | ✅ | Bolt/Lovable nu pot testa autorizare între două conturi reale; second-order IDOR „no automated tool understands multi-step workflow context" (codeant.ai, 11-Sep-2026) |
| Motiv de plată | ✅ | un singur leak cross-tenant = client pierdut + notificare GDPR |
| **Model** | ⚠️ **SERVICIU** | piața e servită de firme de pentest (appsecure, stingrai, axeploit) — manual, per proiect |

## Direcția 2 — Logică de business (refund, roluri, aprobări, entitlement)
| Criteriu | Verdict | Dovadă |
|---|---|---|
| Cumpărător clar | ✅ | SaaS cu plăți/subscripții, marketplace, fintech mic |
| Frecvență | ✅ | „a single logic flaw can result in financial loss, fraud, privilege escalation" (pentesthint, 12-Aug-2026) |
| Detecție non-gratuită în builder | ✅ | niciun builder nu testează combinații de fluxuri (discount + refund + wallet) |
| Motiv de plată | ✅ | pierdere directă de bani, măsurabilă |
| **Model** | ⚠️ **SERVICIU** | consultanță manuală, greu standardizabil; fiecare app are altă logică |

## Direcția 3 — Verificare continuă post-deploy
| Criteriu | Verdict | Dovadă |
|---|---|---|
| Cumpărător clar | ✅ | echipe cu CI/CD |
| Frecvență | ✅ | „control drift", AI code drift (Cycode, Checkmarx) |
| Detecție non-gratuită | ❌ | GitHub Actions + SCA/secret scanning acoperă o parte gratis |
| **Model** | ❌ **OCUPAT** | Cycode, Checkmarx, Orca, Snyk — companii finanțate, produse mature |

## Direcția 4 — Dovadă pentru client/investitor/compliance
| Criteriu | Verdict | Dovadă |
|---|---|---|
| Cumpărător clar | ✅ | startup care vrea SOC 2 / due diligence |
| Frecvență | ✅ | SOC 2 Type 2 = fereastră minimă 3 luni, evidence continuă (Vanta) |
| Detecție non-gratuită | ❌ | platformele colectează deja evidence din AWS/GitHub/Okta/Jira |
| **Model** | ❌ **OCUPAT** | Vanta, Konfirmity, Cyberbase — piață matură |

## Verdict (onest)
**2 probleme trec toate cele 4 criterii ca problemă** (IDOR cross-tenant, logică de business).
**0 trec ca produs scalabil.** Ambele sunt servicii manuale, vândute de firme de pentest.

**A treia problemă nu există** în cele 4 direcții — celelalte două sunt ocupate de companii finanțate.

## Ce înseamnă concret
- Criteriul „3 probleme" **nu a fost atins**. Onest: 2 probleme, ambele servicii.
- Un produs SaaS care să detecteze automat IDOR/business logic **nu există pentru că e greu** —
  nu pentru că nu e nevoie. Bariera e tehnică (context multi-step, conturi reale, date), nu de piață.
- Varianta realistă care trece criteriile: **serviciu de audit manual** (om + metodă), nu tool.
  Dar asta cere timp de om și nu scalează — alt model de business decât ce căutam.

## Recomandare
Conform regulii stabilite: **dacă nu ies 3 → (a) fără regrete.**
Rezultatul e 2/3, ambele servicii. Recomand (a), cu o nuanță:
dacă Alex vrea venit din zona asta, singura variantă validă e **consultanță manuală** (1-2 clienți,
nu produs) — nu un SaaS.

## Surse
- appsecure.security/blog/penetration-testing-for-multi-tenant-saas-architectures (4-Sep-2026)
- codeant.ai/blogs/idor-vulnerabilities (11-Sep-2026)
- blog.pentesthint.com/business-logic-vulnerabilities (12-Aug-2026)
- cycode.com/blog/ai-code-security (7-Jun-2026) · checkmarx.com (Oct-2026)
- vanta.com/collection/soc-2/soc-2-for-startups · konfirmity.com (Oct-2026)
