# Ofertă NeuralScan — audit plătit (Fiverr / Upwork) + listă caldă
> Creat 19-Oct-2026. Decizie Alex: canalele 1 (marketplace) și 3 (lista caldă de chei expuse).

## Partea 1 — Gig Fiverr (copy-paste)

**Title (80 char max):**
I will audit your AI-built app for exposed secrets and dangerous code

**Category:** Programming & Tech → Cybersecurity & Data Protection

**Search tags:** security audit, code review, api key, supabase, vibe coding

**Description:**

Built your app with Lovable, Bolt, Cursor, v0 or Replit? Then your code was written fast, and fast code leaks.

I audit AI-built apps for the two things that actually get people hacked:

1. EXPOSED SECRETS — API keys, database credentials, service-role tokens, admin passwords committed in your repo or shipped in your frontend. This is the #1 real problem in vibe-coded apps: I find live OpenAI, Stripe, Supabase and Firebase credentials in public repositories every week.
2. DANGEROUS CODE — auth that trusts the client, SQL built by string concatenation, file uploads without validation, endpoints with no rate limit.

You get a plain-English report, not a wall of scanner output:
- what is exposed, exact file and line
- why it matters (what an attacker does with it)
- what to ask your AI to fix, phrased so the fix actually works
- what to do first, in order

No jargon. No "critical/high/medium" theatre. If I find nothing real, I say so and you get your money back.

How it works: send me repo access (or a zip), your stack, and the live URL. I scan by hand plus tooling, then deliver the report within the promised time.

I do not fix your code and I do not need your production keys. I tell you exactly what to change.

**Packages:**

| | BASIC $49 | STANDARD $99 | PREMIUM $179 |
|---|---|---|---|
| Delivery | 2 days | 3 days | 5 days |
| Secret / API key scan | ✅ | ✅ | ✅ |
| Dangerous code review (auth, SQL, uploads, rate limits) | — | ✅ | ✅ |
| Prioritized fix list written for your AI assistant | ✅ | ✅ | ✅ |
| Verification re-scan after you fix | — | — | ✅ |
| 30-min call to walk through findings | — | — | ✅ |
| Revisions | 1 | 2 | 3 |

**Requirements (what I ask the buyer):**
1. Repo link (read-only invite) or zip export
2. Stack (Lovable/Bolt/Cursor/other + Supabase/Firebase/other)
3. Live URL, if deployed
4. Is the repo public or private?

**FAQ:**
- **Will you steal my keys?** No. I never use, test or copy credentials. I report the location and tell you to revoke them. On request I sign an NDA.
- **My repo is public — is that the problem?** It is how the keys get found. Public + committed secret = anyone can use it.
- **Can you fix the code?** No — that is a separate job. I give you the exact instructions, written for whatever AI you build with.
- **What if you find nothing?** You get a report saying so, with what I checked. If nothing real was found, I refund.
- **Do you need production access?** Never. Read-only repo access is enough.

## Partea 2 — Upwork (profile + job apply)

**Profile title:** Security audits for AI-built apps (Lovable, Bolt, Cursor, Supabase)

**Overview (short):**
I audit apps built with AI tools for exposed secrets and dangerous code — the class of bug that actually gets vibe-coded products breached. I have found live OpenAI, Stripe and Supabase credentials in public repositories by hand, and I write fixes in language a non-developer can act on.

**Proposal opening (for job posts):**
You built with AI — that is fine. The problem is not the AI, it is what gets committed with it: keys in the frontend, service-role tokens in the repo, auth that trusts the client.

I do a read-only audit and send a report: what is exposed, where, what an attacker can do with it, and the exact prompt to give your AI to fix it.

Fixed price, 48–72h. NDA on request. I never use or test credentials I find.

## Partea 3 — Lista caldă (chei expuse)

Flux: găsesc cheie reală → notificare privată (fără să public unde e) → dacă omul răspunde, ofertă de audit complet.
Reguli: nu testez chei, nu postez public locația, nu trimit la terți.

| Repo | Contact | Status |
|---|---|---|
| tonszazo-lang/raqqa | tonszazo@gmail.com | email trimis 19-Oct 14:05 |
| NemroNeno/LinkedIn_messaging_agent | email malformat → skip | skip |
| 365assist/bibleaf | fără email (vercel bot) | skip |

**Mesaj de follow-up (după ce confirmă problema):**
> Dacă vrei, pot face auditul complet al app-ului: nu doar cheia asta, ci tot ce e expus — auth, baza de date, endpoint-uri. Iți trimit raportul cu ce să ceri AI-ului să repare. 49 $ pentru versiunea de bază, 48h.
