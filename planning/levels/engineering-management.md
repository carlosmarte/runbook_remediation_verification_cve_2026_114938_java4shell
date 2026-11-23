# Engineering-management plan (VP Engineering, directors, engineering managers)

**You own:** capacity and prioritisation across the services your teams run, the upgrade and EOL-migration
schedule, gate adoption in your repositories, and the performance trade-offs of the mitigation in your products.
**You receive:** R2 (ranked queue), R5 (pipeline posture), R7 (estate verdicts) weekly; patched base images from
platform; decisions from executives on latency budgets and migration funding.
**You deliver:** owners and dates per service, merged upgrade PRs, gate workflows in every Java repo, before/after
performance evidence.

## Steps

1. **T+24 h: receive R2 and assign owners.** Every row in the work queue gets a named team, a tier and a due date
   (`EXPOSED` → today, `MITIGATED_FLAG` → patch by SLA, `UNVERIFIED_FLOATING` → resolve this week,
   `UNVERIFIED_NO_PIN` → name the runtime this week). Return the table to the programme manager for `narrative.json`.
2. **Protect the first 48 hours.** Clear the calendars of the teams that own exposed internet-facing services; the flag
   rollout and its benchmark (plan 04) is the only priority.
3. **Sequence the upgrades** (plan 05 §3): internet-facing pre-auth services first, then services where the flag
   costs most, then internal, then EOL migrations. Agree the sequence with platform's base-image publication dates.
4. **Own the EOL migrations.** Services on JDK 18–20 / 22–24 / 26 cannot be patched. Each needs a migration plan with
   a date, or a retirement decision; present the cost in R0 terms (engineer-weeks) for the executive decision.
5. **Make the gate non-negotiable** (plan 06). Target: 100 % of your Java repositories with the workflow present and
   required within the patch SLA. A reusable workflow or organisation ruleset turns this into minutes per repo.
   Track with R5 §2 / R7.
6. **Decide the performance budget per product** with the product owner (plan 04 §4). The budget is for 30 days;
   exceeding it means scaling out and patching sooner, never skipping the flag on an exposed service.
7. **Hold teams to evidence, not status.** A service is done when its R3 ticket carries the audit JSON showing
   `PATCHED_OR_SAFE_VERSION`, the estate scan showing `PATCHED`, and the gate run URL (plan 10 §1).
8. **Watch regressions.** A `regressed` row in R6/R1 means a redeploy dropped the flag in your area; fix the pipeline
   (plan 06), not only the instance.
9. **Weekly portfolio review** with the programme manager on R2: what moved, what is blocked, what needs an
   exception. Bring capacity numbers.
10. **Developer environment hygiene.** Ask teams to update `.sdkmanrc` / `.tool-versions` / `setup-java` pins; stale
    dev pins rebuild old images locally and show up as `dev`-scope vulnerabilities in R7.
11. **After closure.** Adopt platform-owned base images with automated bumps, keep the version gate permanently, and
    schedule JDK line upgrades before EOL so the next CVE has a patch path.

## What to read in each report

| Report | Look at | Act when |
| :--- | :--- | :--- |
| R2 | §2 work queue worst first; §3 capacity; §4 repos without gate | any `EXPOSED` older than a day; gate adoption flat |
| R5 | §2 all pipelines; `GATE_REQUIRED = no`; failing runs | required checks missing on protected branches |
| R7 | §3 blocking, §5 unverified | `UNVERIFIED_NO_PIN` without a named runtime |
| R6 | §5 before/after regressions | any regression in your services |
| R1 | §5 by business unit; §7 blockers | your unit is RED or your blockers are stale |

## Side effects to manage with your teams

- 04 latency/CPU: measured, budgeted, time-boxed.
- 07 propagation: shared hosts get per-service launch options where it matters.
- 08 upgrade regressions: test on the target JDK before switching images; across-line migrations get full regression.
- 10 gate false positives: fix the parser or add a scoped exemption with expiry; never `continue-on-error` after the pilot.
- 11 scanner noise: test and shaded findings are informational; untrusted pre-auth sites are not.
