# 11 — Communication & Reporting Plan

**Objective.** Every audience hears the right thing at the right cadence from the same facts; nobody learns about
exposure from a customer or a journalist first.
**Basis.** `../report-template/` (R0–R10), `report-template/tools/j4s_facts.py` as the single source of numbers.
**Owner.** Programme manager; CISO approves external statements.

## 1. Audiences and cadence

| Audience | Needs | Report | Cadence | Channel |
| :--- | :--- | :--- | :--- | :--- |
| Board / executive committee | RAG, exposure, dates, decisions, cost | R0 | T+24 h, weekly, closure | exec briefing, written |
| CISO / security leadership | scorecard, trend, SLA, blockers, exceptions | R1 | daily week 1, weekly after | security standup, written |
| Engineering directors / managers | work queue, capacity, EOL migrations | R2 | weekly | eng leadership meeting |
| Service owners / teams | their hosts, repos, call sites, checklist | R3 | at triage, until PATCHED | ticket per service |
| Developers / reviewers | file:line findings, fix guidance | R4 | per PR / scan | PR comment, code scanning |
| Release / DevOps | gate results, posture | R5 | per release, weekly | pipeline output, written |
| Platform / SRE | host verdicts, before/after | R6 | daily in rollout, weekly | ops channel |
| AppSec / platform | estate verdicts, gate adoption | R7 | weekly | security channel |
| SOC / IR | crash and probe triage | R8 | on event | incident record |
| Audit / compliance / customers | attestation | R9 | closure, on request | formal document |
| Edge / WAF team | rule hits, false positives | R10 | per traffic cycle | ops channel |
| All staff (if relevant) | what changed for them (dev pins, CI) | short note | once | internal comms |
| Customers / regulators | affected? mitigated? by when? | statement derived from R9 | as required by contract/regulation | legal/comms |

## 2. Steps

1. **T+0: name the communicator** (programme manager) and the approver for external statements (CISO + legal).
2. **T+1 h: open channels**: incident channel, a status page section (internal), the evidence store, the report
   folder (`reports/YYYY-MM-DD/`).
3. **T+2 h: first R0 and R1** from whatever facts exist (`j4s_facts.py` tolerates missing sections). Say what is
   unknown. Fix the cadence table above in the channel topic.
4. **Daily (week 1)**: regenerate `facts.json` from the latest evidence; render R1, R6, R7; post the headline line
   (RAG, exposed count, coverage) in the channel; update the status page.
5. **Per service**: open a ticket with R3 rendered for that service's facts (filter audits/estate to the service);
   close it only on `PATCHED` with evidence.
6. **Per PR**: the gate posts R4-style findings via SARIF/code scanning; reviewers use R4 §"What to do in this PR".
7. **Weekly**: R0 to executives with decisions requested; R2 to engineering leadership; R5/R7 to platform; R10 to edge.
8. **On incident**: R8 within the first hour, updated at each phase; R0 headline if SEV-1.
9. **External statements**: derive strictly from R9 facts ("in scope / not affected / mitigated / patched by");
   no speculation about exploitation; legal review; record what was sent to whom.
10. **Closure**: R9 signed and distributed to audit; final R0; lessons-learned session with the plan owners;
    archive the reports folder with the evidence.

## 3. Message rules

- Numbers come from `facts.json`; prose is edited, numbers are not.
- Use the verdict words consistently; never call a flag-only state "safe".
- State unknowns as unknowns (hosts not audited, repos unverified) with an owner and date.
- Each report ends with actions and owners, not with "monitoring continues".
- One source of truth per cadence: the latest rendered report supersedes chat summaries.

## 4. Templates for short messages

- **Channel headline**: `J4S day {{meta.days_since_disclosure}} — {{status.rag}} · exposed JVMs {{fleet.exposed_vbmi}} · protected {{fleet.mitigation_coverage|pct}} · patched {{fleet.patch_coverage|pct}} · blocking repos {{repos.blocking}} · gate adoption {{repos.gate_adoption|pct}}` (render with `tools/render.py` from a one-line template file).
- **Service ticket title**: `[J4S] <service> — <verdict> — flag by <sla_mitigate_due>, patch by <sla_patch_due>`.
- **External**: "We identified N Java services in scope. All internet-facing services were mitigated by <date> and are
  being upgraded to patched builds by <date>. We have found no evidence of exploitation." Only when R8/R9 support
  each clause.

## 5. Exit criteria

- Cadence table followed for the whole programme (check the reports folder: one R1 per working day in week 1,
  weekly thereafter).
- Every exposed service had an R3 ticket; every PR with findings had R4 content.
- External statements on file with approvals.
- R9 distributed; lessons learned recorded in this folder's plans (update the pitfalls sections).
