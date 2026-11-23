# 00 — Master Programme Plan

**Objective.** Take the organisation from "disclosed" to "every Java runtime patched, every pipeline gated,
every compensating control retired" with no exposed JVM beyond the mitigation SLA.
**Runbook basis.** §8 (seven steps), §1 (scope), with the detailed plans 01–12 hanging off each phase.
**Owner.** Programme manager (or incident commander while any `EXPOSED_ON_VBMI_HOST` or `REACHABLE_HIGH` exists).

## 1. Phases and timeline

| Phase | Window | Goal | Exit criterion | Detailed plan |
| :--- | :--- | :--- | :--- | :--- |
| P0 Mobilise | T+0 – T+4 h | roles, channels, scope statement, first R0 | incident channel open, RACI agreed, assessment started | this file, 11 |
| P1 Assess & inventory | T+0 – T+24 h | know every JVM, image, repo and its exposure | fleet audit on ≥ 95 % of hosts; estate scan complete; exposure matrix filled | 01, 02 |
| P2 Mitigate | T+4 h – T+2 d | flag live on every exposed JVM, re-enables removed | `fleet.exposed_vbmi = 0`, `repos.blocking = 0`, live `jcmd` confirmation | 04, 10 |
| P3 Protect the window | T+1 d – T+7 d | edge rules in count→block, monitoring and IR ready | rules blocking on pre-auth routes with 0 false positives; alerts tested | 07, 08, 09 |
| P4 Trace & harden code | T+2 d – T+14 d | untrusted decode sites validated, reachability known | `source.untrusted_prod` all wrapped or justified; no `REACHABLE_HIGH` | 03 |
| P5 Patch | T+2 d – T+30 d | JDK at baseline everywhere; EOL lines migrated or scheduled | `fleet.patch_coverage = 100 %`, `repos.patched = repos.java` or exception | 05 |
| P6 Make it stick | T+7 d – T+30 d | gate in every Java pipeline, required check, SARIF | `repos.gate_adoption = 100 %`, `posture.gate_required = posture.repos` | 06 |
| P7 Close | T+30 d – T+45 d | flag removal, edge rule retirement, attestation | R9 signed; exceptions have expiry; side-effect measurements archived | 10, 11 |

Phases overlap. P2 starts as soon as the first exposed JVM is known; P3 starts as soon as an internet-facing
pre-auth decode is suspected, not after assessment finishes.

## 2. Workstreams and owners (RACI)

| Workstream | Responsible | Accountable | Consulted | Informed |
| :--- | :--- | :--- | :--- | :--- |
| Assessment & scanning (01, 02, 03) | Security engineering | CISO | platform, service teams | all |
| Mitigation rollout (04) | Platform / SRE + service teams | Head of platform | security, product owners (latency) | SOC |
| Patch & upgrade (05) | Service teams | Engineering directors | platform (base images), QA | security |
| CI/CD gate (06) | DevOps / release engineering | Head of platform | security (policy), teams (exemptions) | audit |
| Edge controls (07) | Edge / network security | CISO | API owners, SOC | service teams |
| Observability & IR (08, 09) | SRE, SOC | CISO | platform | leadership |
| Verification & evidence (10) | Security engineering | CISO | internal audit | audit |
| Communication (11) | Programme manager | CISO | all leads | all |

## 3. Step-by-step

1. **T+0 h — Declare.** Open the incident channel, name the programme manager and the technical lead, set the
   SLAs (`mitigate 2 d`, `patch 30 d` unless policy says otherwise), publish the scope statement (which business
   units, environments, clouds, on-prem, developer machines in or out).
2. **T+1 h — Start assessment (plan 01).** Kick off the fleet audit and the GitHub estate scan in parallel; they do
   not depend on each other.
3. **T+2 h — Stand up reporting (plan 11).** Create `facts.json` from whatever exists and issue the first R0 and R1,
   even if half the sections read "not yet available". Fix the cadence: R1 daily, R0 at T+24 h and weekly.
4. **T+4 h — Mitigate the obvious (plan 04).** Any internet-facing JVM with a vulnerable version on VBMI hardware
   gets the flag now; do not wait for the full inventory.
5. **T+8 h — Edge rules in count mode (plan 07)** on every public entry point that terminates Java traffic.
6. **T+24 h — Assessment complete (plan 01 exit).** Exposure matrix, risk ranking, owner per exposed asset. Issue
   R0 with real numbers. Decisions needed from executives go in R0 §4.
7. **T+1–2 d — Mitigation complete (plan 04 exit).** Verify with plan 10; publish R6. Every `EXPOSED_ON_VBMI_HOST`
   is gone or has a signed exception.
8. **T+2–7 d — Monitoring and IR live (plans 08, 09).** Alerts on crashes, probes, flag drift; runbook rehearsed.
9. **T+2–14 d — Tracing and code hardening (plan 03).** Validate untrusted decode sites; feed reachability JSON to
   the gate.
10. **T+2–30 d — Patch (plan 05).** Teams upgrade behind canaries; platform publishes patched base images; EOL
    migrations get their own plan and dates.
11. **T+7–30 d — Gate everywhere (plan 06).** Workflow copied to every Java repo, made a required check, SARIF uploaded.
12. **T+30 d — Patch SLA review.** Everything not at baseline has an exception with expiry and compensating control.
13. **T+30–45 d — Close (plan 10, 11).** Remove flags where patched, retire edge rules per plan 07 §6, archive
    side-effect measurements, issue R9 attestation, run the lessons-learned session.

## 4. Dependencies and critical path

```
inventory (01/02) ─► exposed list ─► flag rollout (04) ─► live verification (10) ─► R6/R0
                 └─► estate verdicts ─► blocking repos ─► gate (06) ─► required check
tracing (03) ─► reachability JSON ─► gate reachability check (06)
patched base images (05) ─► team upgrades (05) ─► flag removal (P7)
edge count mode (07) ─► FP review ─► block mode ─► retire after patch coverage 100 %
```

Critical path for the mitigation SLA: inventory of VBMI hosts → flag delivery mechanism per platform → restart
windows. Pre-approve the emergency change window in P0 (R0 decision 1).

## 5. Milestones and reports

| Milestone | Evidence | Report |
| :--- | :--- | :--- |
| M1 inventory complete | audits for ≥ 95 % hosts, estate scan JSON | R1, R6, R7 |
| M2 no exposed JVM | `fleet.exposed_vbmi = 0`, `repos.blocking = 0` | R0, R1, R6 |
| M3 edge rules blocking on pre-auth routes | R10 with 0 false positives over a cycle | R10 |
| M4 no untrusted decode without validation | source scan `untrusted_prod` all wrapped; no `REACHABLE_HIGH` | R4, R3 |
| M5 patch coverage 100 % (or exceptions) | `fleet.patch_coverage = 1.0` | R1, R6 |
| M6 gate adoption 100 % | `repos.gate_adoption = 1.0`, required checks | R5, R7 |
| M7 closure | R9 signed | R9 |

## 6. Risks to the plan

| Risk | Mitigation |
| :--- | :--- |
| Hidden JVMs (agents, sidecars, desktop/CLI tools, batch boxes) | `/proc` maps scan, not process-name grep (J4S-RT-01); include developer and build machines in scope decisions |
| Flag lost on redeploy | gate (06), drift alert (08), weekly R6 diff (10) |
| Latency regression from the flag | canary + benchmark before fleet rollout (04 §4, side effect 04) |
| EOL JDK lines with no patch | separate migration plan with dates (05 §5); flag stays until migrated |
| Gate false positives blocking releases | use the corrected parser; exemption register (06 §6, side effect 10) |
| WAF false positives on JWT/SAML | count mode first; per-route promotion (07) |
| Team capacity | portfolio view (R2) to sequence worst first; platform-owned base images reduce per-team work |

## 7. Exit criteria for the programme

- `fleet.exposed_vbmi = 0` and `fleet.unverified = 0` or every remaining item has a signed exception with expiry.
- `fleet.patch_coverage = 100 %` for in-scope hosts; EOL lines migrated or exception.
- `repos.blocking = 0`, `repos.unverified_* = 0` or owner named and audited, `repos.gate_adoption = 100 %`.
- No `REACHABLE_HIGH`; all `DYNAMIC_UNTRUSTED` sites validated.
- Edge rules retired or consciously retained; monitoring for crashes and probes stays.
- R9 attestation issued; evidence archived; lessons learned recorded.
