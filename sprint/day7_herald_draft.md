# Herald draft — 21-Aug-2026 (build-in-public, EN)

> Sursa: git log neuralscan (f9f6cc7, e817f1b, 3d54a87, 2f43b0b), STATE.md 20-Aug,
> smoke prod live 21-Aug (9/9), verificare post Reddit 1vtnbf5 (oEmbed 200).
> NIMIC nu se posteaza fara OK-ul lui Alex. Draft doar.

---

## Title (A/B)

**A:** "GitHub silently killed our Railway webhook 4 times. Here's the 2-minute fix."
**B:** "After 4 'random' auto-deploy failures, the root cause was a dead webhook — not config."

## Body (varianta A)

Building a security scanner for AI-generated code — and dogfooding it means the infra
has to be boring and reliable. Last week it wasn't.

**The symptom:** pushes to `main` stopped deploying to Railway. Toggle ON. Trigger
correct. Repo linked. Yet nothing deployed. Four times in one week.

**The root cause (finally):** GitHub silently deactivates App webhooks after repeated
delivery failures. The webhook looked fine in the UI — but GitHub had stopped sending
events. Railway never knew about the push.

**The fix (2 minutes):**
1. Delete the deployment trigger via Railway GraphQL (`deploymentTriggerDelete`)
2. Recreate it (`deploymentTriggerCreate`) — this re-registers the webhook
3. Test with an empty commit → deploy starts automatically

Proof: push `f9f6cc7` → deployment `0f849ca1` SUCCESS, no `railway up` involved.

**Also shipped this week:**
- Per-key daily scan caps (free 50/day, pro 500/day, UTC reset). Live proof: scan #51
  returned `429` with `daily_used=50`. 88/88 tests green.
- Locked dependencies for reproducible builds (CI green on every push).
- Prod smoke today: 9/9 endpoints (health, landing, scanner, ZIP scan, admin, stats
  on Postgres, key create → scan → revoke → 401).

**Honest caveats:** webhooks can die again; this is a playbook, not a silver bullet.
The scanner itself is regex-based — it finds *patterns*, not proof of exploitation
(that's what the Strix deep-scan wrapper is for, still manual).

Building in public at NeuralScan — scanner for AI-built apps, tested on itself.

---

## Guardrails check (Herald)

- [x] Fara secrete / token-uri / URL-uri interne (niciun key, niciun admin path)
- [x] Nu supra-revendica: "playbook, nu silver bullet"; regex vs deep-scan onest
- [x] Surse verificabile: git log + STATE.md + smoke live
- [ ] Aprobat de Alex INAINTE de orice postare (PENDING)
