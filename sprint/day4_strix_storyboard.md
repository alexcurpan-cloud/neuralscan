# Day 4 — Strix Live Run: Storyboard (6 cadre)

> Scop: filmezi cu **Win+G** în timpul run-ului de mâine → clip 2-3 min „de la static la validare reală".
> Reguli filmare: fereastra terminalului maximizată, font mare (Ctrl+Shift+Plus), fără notificări Windows.
> După filmare: `Win+Alt+R` oprește. Fișierul ajunge în `Videos/Captures`.

## Cadrele (în ordine, cu momentul exact)

| # | Moment | Ce se vede pe ecran | Durată |
|---|--------|--------------------|--------|
| 1 | Înainte de run | Docker Desktop running (whale verde) + `vuln_app2` deschis în VS Code (requirements.txt cu dependențe vulnerabile) | ~15s |
| 2 | Start | `python scripts/run_strix.py -t neuralscan/samples/vuln_app2 -m quick --max-budget 5` + bannerul Strix (ASCII art / versiunea 1.5.3) | ~15s |
| 3 | Mijloc run | Terminal cu activitate: agenții Strix atacând (loguri, tool calls, skill_loaded etc.) | ~30s |
| 4 | Final run | Exit code + `strix_runs/<run-id>/` generat (run.json, findings.sarif, strix.log) | ~15s |
| 5 | Mapper | `python scripts/strix_to_neuralscan.py <run-id>` → human_report.json apare (verdict + cost) | ~15s |
| 6 | Verdict | `Get-Content human_report.json` — verdictul pe ecran (🔴 findings SAU 🟢 „pare curat (sau scanul n-a produs findings finalizate)") | ~20s |

## Note onestitate (critice)

- **NU edita** verdictul. Dacă run-ul n-are findings, frame 6 arată mesajul onest al mapper-ului — asta e și punctul poveștii („nu inventăm rezultate").
- Costul real apare în human_report.json → îl citești pe voce în clip (ex: „$4.2, un singur run plătit").
- Dacă run-ul eșuează (Docker down / cheie) → oprești filmarea, nu mimezi succes. Povestea se poate muta pe „ce am învățat din eșec" — la fel de validă.

## După filmare (checklist)

- [ ] Clip salvat în `Videos/Captures`
- [ ] Run-ul complet: `strix_runs/<run-id>/` + human_report.json generat
- [ ] Trimți clipul + human_report.json → eu tai momentele-cheie dacă vrei
- [ ] Herald are biletul gata (`day4_herald_draft.md`) — aprobi draftul, el postează
