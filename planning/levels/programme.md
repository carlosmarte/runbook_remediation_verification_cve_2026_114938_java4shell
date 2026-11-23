# Programme / security-leadership plan (CISO office, programme manager, incident commander)

**You own:** the master plan (`../00-master-plan.md`), RACI, the scorecard, the exceptions register, escalation,
and the single source of numbers (`facts.json`).
**You receive:** evidence from every workstream (audits, estate scans, gate logs, traffic, crashes), blockers from
teams, decisions from executives.
**You deliver:** R1 daily then weekly, R0 weekly, R9 at closure; a ranked work queue (R2) to engineering management;
service tickets (R3) to teams.

## Steps

1. **T+0: mobilise.** Open the channel, confirm RACI (master plan §2), publish the scope statement and SLAs, set the
   reporting cadence (plan 11), create the evidence store with dated folders.
2. **T+1 h: start assessment and scanning in parallel** (plans 01, 02): fleet audit via platform, estate scan via
   security engineering, code-search sweep, posture check. Do not serialise them.
3. **T+2 h: first facts and reports.** `report-template/tools/j4s_facts.py … -o facts.json`; render R0 and R1 with
   the sections you have; state unknowns.
4. **T+4 h: push the fast path.** Any exposed internet-facing JVM gets the flag now (plan 04); edge rules go to count
   mode (plan 07). Track these two in the channel hourly.
5. **T+24 h: assessment exit.** Exposure matrix and ranked list (plan 01 §2 steps 6–8). Issue R0 with decisions
   requested; issue R2 to engineering management with the queue; open R3 tickets for every exposed or mitigated
   service.
6. **Daily (week 1): run the scorecard.** Regenerate facts; render R1, R6, R7. Chase `regressed` rows first (flag lost
   on redeploy), then remaining `EXPOSED`, then `EXPLICITLY_ENABLED`. Record blockers with owners and needed-by dates.
7. **T+2 d: mitigation SLA.** Everything still exposed gets an exception or an escalation to the executive sponsor.
   Confirm live `jcmd` evidence exists for every `MITIGATED_BY_FLAG` claim (plan 10).
8. **T+2–7 d: protection window.** Confirm monitoring alerts are test-fired (plan 08), IR plan rehearsed (plan 09),
   edge rules promoted per R10.
9. **T+2–14 d: code hardening.** Track untrusted decode sites per service (plan 03) and the first repos with the gate
   required (plan 06). Add these to the scorecard.
10. **Weekly: portfolio review** with engineering management on R2: sequencing, capacity, EOL migrations with dates,
    base-image availability from platform.
11. **Manage exceptions.** One register (R9 §5 shape): asset, reason, compensating control, approver, approved date,
    expiry. Nothing stays `EXPOSED` or `UNVERIFIED` without a row. Expired rows are escalations.
12. **Watch the side effects** (R1 §9): performance budget consumption, propagation incidents, gate false positives,
    WAF false positives, upgrade regressions. Adjust plans 04/06/07 when a side effect blocks progress.
13. **T+30 d: patch SLA review.** Exceptions for every remaining item; decide flag removal policy (plan 05 step 9).
14. **Closure.** Assemble the closure package (plan 10 §2 step 11), run the independent spot check, get R9 signed,
    hold the lessons-learned session, write the lessons back into these plans.

## Scorecard you maintain (from `facts.json`)

| Metric | Target | Source |
| :--- | :--- | :--- |
| `fleet.exposed_vbmi` | 0 by mitigation SLA | audits |
| `fleet.mitigation_coverage` | 100 % by mitigation SLA | audits |
| `fleet.patch_coverage` | 100 % by patch SLA | audits |
| `repos.blocking` | 0 | estate scan |
| `repos.unverified_share` | 0 (owner named for each) | estate scan |
| `repos.gate_adoption`, `posture.gate_required` | 100 % | estate scan, posture |
| `source.untrusted_prod` | all validated | source scans |
| `crashes.likely`, `traffic.suspicious` | 0 open | triage |
| regressions per week | 0 | inventory diff |

## Escalation rules

- Exposed internet-facing JVM older than 24 h without a change scheduled → executive sponsor the same day.
- Any `EXPLICITLY_ENABLED` → owner must remove within 4 h; otherwise platform removes it.
- Regression after mitigation → treat as a process failure of plan 06/08, not just a redo.
- LIKELY crash → incident commander takes over (plan 09); programme reporting continues in parallel.
