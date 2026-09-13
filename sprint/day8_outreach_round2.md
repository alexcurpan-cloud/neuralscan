# Day 8 — Outreach runda 2 (texte finale, gata de postat)

> Format-întrebare (a funcționat mai bine decât cel de promovare). Tool-ul se oferă DOAR în comentarii, dacă cere cineva.
> Reguli: fără link-uri în postare, fără „check out my tool", zero self-promo agresiv.

## 1) r/SideProject (public larg de builderi)

**Title:** How do you handle security when you ship something built mostly by AI?

**Body:**
I've been shipping small projects with AI assistance and noticed a pattern I can't unsee — the code always *looks* clean (formatted, commented, confident), but when I actually read it I keep finding the same things:
- API keys hardcoded in files
- SQL built by string concatenation
- shell commands assembled from user input

It's not a "bad AI" problem — it's that security isn't a pattern models learned; it's a constraint they don't have. So I'm curious how others here deal with it:

1. Do you review the security of AI-generated code before shipping, or only when something breaks?
2. What have you caught that surprised you?
3. Anyone using tooling for this, or is it all manual eyeballing?

(For context: I got tired of eyeballing and built a small local scanner for exactly these patterns — happy to share if useful, mostly here to hear how you all handle it.)

## 2) Discord — AI dev / builders (canal feedback)

**Title:** 🛡️ How are you handling security in AI-generated code?

**Body:**
Quick question for the builders here 👋

I keep seeing the same handful of issues in code written with AI assistants: hardcoded API keys, SQL string concatenation, `os.system()` with user input. The code looks fine until you actually read it.

Curious how you handle it:
- Do you review before shipping, or just fix when something breaks?
- What's the worst thing you've caught in your own generated code?
- Any tooling you rely on?

(I've got a small local scanner that flags these patterns with plain-language explanations — can share if anyone's interested. Mainly want to hear what actually works for you.)

## 3) DM scurt — pentru cei care au RĂSPUNS la postări despre probleme (nu spam)

> Salut! Am văzut postarea ta despre [problema lor concretă]. Am avut fix aceeași situație — la mine se ascundea [pattern: chei hardcodate / query construit din string etc.]. Am făcut un scanner mic, local (rulează pe codul tău, nimic nu pleacă nicăieri). Dacă vrei, ți-l dau gratis — în schimb îmi spui dacă raportul are sens pentru tine. Zi „da" și ți-l trimit.

## Note de execuție
- Postări: 1-2 pe zi MAXIM (anti-spam), răspunde la fiecare comentariu în primele 2 ore
- NU același text în două locuri simultan (rescrie titlul/primul paragraf)
- La „da, vreau" → trimiți zip-ul + cele 3 întrebări (template existent în day8_recruit_messages.md)
- Notează fiecare contact în tracker (platformă, om, a rulat? feedback, follow-up)
