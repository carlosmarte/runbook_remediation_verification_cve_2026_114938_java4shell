# 07 — Planning Documents (`planning/`)

The runbook's single eight-step plan is decomposed into a master programme plan, twelve category plans and five
plans by organisational level. Every plan points at the concrete tooling in this repository.

## 1. Inventory

**SPEC-07-01.** The folder MUST contain:

| # | File | Answers | Runbook basis | Typical owner |
| :--- | :--- | :--- | :--- | :--- |
| 00 | `00-master-plan.md` | sequence, dates, owners, exit criteria | §8, §1 | programme manager / incident commander |
| 01 | `01-vulnerability-assessment-plan.md` | are we affected, where, how badly | §1–§3 | security engineering |
| 02 | `02-scanning-plan.md` | which scans run where, how often, with what noise handling | §2, §3, §5, §6, §7.3 | security engineering, platform |
| 03 | `03-input-provenance-tracing-plan.md` | which decode sites are reachable from untrusted input, via which touchpoints | §1 side effects, §6 | AppSec, service teams |
| 04 | `04-mitigation-rollout-plan.md` | how to get the flag live everywhere safely and prove it | §2, §8.5–8.6 | platform / SRE, service teams |
| 05 | `05-patch-upgrade-plan.md` | how to reach the baselines, migrate EOL lines, retire the flag | §1, §8.7 | engineering teams, platform |
| 06 | `06-ci-cd-integration-plan.md` | how to make the fix durable: gate, required checks, SARIF, exemptions | §7 | DevOps / release engineering |
| 07 | `07-edge-compensating-controls-plan.md` | how to deploy, tune and retire WAF / proxy rules | §4 | edge / network security |
| 08 | `08-observability-monitoring-plan.md` | what to measure and alert on | §2, §4, side effects 01–05 | SRE, SOC |
| 09 | `09-incident-response-plan.md` | what to do when a crash or probe indicates exploitation | side effects 01–02, §4 | SOC / IR |
| 10 | `10-verification-validation-plan.md` | how each step proves it is done; evidence standards | §2, §3, §8.6 | security engineering, audit |
| 11 | `11-communication-reporting-plan.md` | who hears what, when, in which report | `report-template/` | programme manager |
| 12 | `12-checklists.md` | tick-box lists A–I | all | everyone |
| 13 | `levels/` (`README.md`, `executive.md`, `programme.md`, `engineering-management.md`, `team.md`, `engineer-operator.md`) | the programme restated per level | all | each level |

## 2. Structure of a category plan

**SPEC-07-02.** Each plan 01–11 MUST open with bold `Objective`, `Runbook basis`, `Owner` (and `Timing` where
relevant), and MUST contain numbered sections for at least: inputs or a model/map, **Steps** (numbered,
imperative, each naming the command or artefact), **Outputs** (files that feed `j4s_facts.py`), **Exit criteria**
(observable, never "when the team says so"), and **Pitfalls** or **Side effects**. Plan 10 additionally carries an
evidence-standards table (acceptable vs. not acceptable proof) and per-phase acceptance criteria tied to the
master plan.

**SPEC-07-03 Conventions.** Every plan uses: `J4S-*` pattern IDs; side-effect numbers `01`–`11`; T-relative
timing (SPEC-01-15); the verdict vocabulary of document 00 §5; and report IDs `R0`–`R10`. `planning/README.md`
MUST reproduce the conventions table and the "facts every plan relies on" list from runbook §1.

## 3. Master programme plan

**SPEC-07-04 Phases.**

| Phase | Window | Exit criterion | Plans |
| :--- | :--- | :--- | :--- |
| P0 Mobilise | T+0 – T+4 h | incident channel open, RACI agreed, assessment started | 00, 11 |
| P1 Assess & inventory | T+0 – T+24 h | fleet audit on ≥ 95 % of hosts; estate scan complete; exposure matrix filled | 01, 02 |
| P2 Mitigate | T+4 h – T+2 d | `fleet.exposed_vbmi = 0`, `repos.blocking = 0`, live `jcmd` confirmation | 04, 10 |
| P3 Protect the window | T+1 d – T+7 d | edge rules blocking on pre-auth routes with 0 false positives; alerts tested | 07, 08, 09 |
| P4 Trace & harden code | T+2 d – T+14 d | `source.untrusted_prod` all wrapped or justified; no `REACHABLE_HIGH` | 03 |
| P5 Patch | T+2 d – T+30 d | `fleet.patch_coverage = 100 %`; EOL lines migrated or scheduled | 05 |
| P6 Make it stick | T+7 d – T+30 d | `repos.gate_adoption = 100 %`, gate required check everywhere | 06 |
| P7 Close | T+30 d – T+45 d | R9 signed; exceptions have expiry; side-effect measurements archived | 10, 11 |

Phases overlap; P2 starts with the first known exposed JVM and P3 with the first suspected internet-facing
pre-auth decode.

**SPEC-07-05 Contents.** The master plan MUST include: a RACI table per workstream; a numbered step-by-step
timeline from T+0 h to T+45 d; a dependencies/critical-path diagram (inventory → exposed list → flag rollout →
live verification → R6/R0; estate verdicts → blocking repos → gate → required check; tracing → reachability
JSON → gate; patched base images → team upgrades → flag removal; edge count → FP review → block → retire);
milestones M1–M7 with evidence and report; a risks table; and programme exit criteria (no exposed or
unverified JVM without signed exception, 100 % patch coverage or exceptions, zero blocking repos, 100 % gate
adoption, no `REACHABLE_HIGH`, edge rules retired or consciously retained, R9 issued).

## 4. Key normative content of category plans

**SPEC-07-06 Scanning plan (02).** MUST contain the scan map (layer → scan → tool → output → cadence) covering
runtime, Kubernetes, estate discovery/scan/posture, code search, source, bytecode, dependencies/reachability,
manifests, image resolution, crash and traffic; sections A–G per layer; a schedule; exit criteria.

**SPEC-07-07 Mitigation plan (04).** MUST contain the flag-choice table (`-XX:-UseBASE64Intrinsics` default;
`UseAVX` cap only when unavailable; `+UseBASE64Intrinsics` never), the delivery-mechanism table per platform
(Docker `ENV`, Kubernetes `env`/patch, Helm, systemd drop-in, app-server launch options, build tools, host env as
last resort with side effect 07), the merge-not-overwrite rule using `j4s_flag.sh add`, a benchmark protocol
(side effects 04/05), rollback, exit criteria.

**SPEC-07-08 Verification plan (10).** MUST contain the evidence-standards table with at least the claims: flag
live (only `jcmd`/`jinfo` as owner or root), JDK patched (`java -version` from the mapped runtime or
`$JAVA_HOME/release`, digest recorded), host not in hardware scope (`/proc/cpuinfo`), repository safe
(`PATCHED` with file:line plus required gate), code hardened (validation before every untrusted decode or
justification), gate enforced (`GATE_REQUIRED = yes`, last run success), edge rule works (staged replay of
`QUJD====`), no exploitation (triage window), programme closed (R9 with evidence register).

**SPEC-07-09 Incident response plan (09).** MUST be phased (detect/triage 0–15 min, contain 15–60 min, assess
1–8 h, eradicate/recover 8–72 h, close) with severity, indicators (LIKELY crash, EDGE-01/02 tokens, WAF block
spikes), roles and exit criteria.

**SPEC-07-10 Checklists (12).** MUST provide lists A Day-0, B per host, C per service (mirrors R3), D per
repository (mirrors R7), E pull request (mirrors R4), F release (mirrors R5), G edge rule (mirrors R10),
H incident (mirrors R8), I closure (mirrors R9).

## 5. Level plans

**SPEC-07-11.** Each `levels/*.md` is self-contained and states what that level owns, decides, reads and
receives, with explicit hand-offs ("you receive … / you deliver …"):

| Level | Owns | Reads |
| :--- | :--- | :--- |
| Executive | risk appetite, SLAs, budget, change windows, external statements | R0, R9 |
| Programme / security leadership | sequencing, RACI, scorecard, exceptions, escalation | R1, R2 |
| Engineering management | capacity, prioritisation, EOL migrations, gate adoption | R2, R5, R7 |
| Team / service owner | one service end to end: mitigate, trace, patch, prove | R3, R4, R6 |
| Engineer / operator (developer, SRE, SOC, edge, release, security engineer) | commands, PRs, restarts, rules, triage | R4, R6, R8, R10 |

## 6. Consistency rules

**SPEC-07-12.** A command shown in a plan MUST exist with those options in `scripts/`, `helpers/` or `github/`;
a `facts.json` key named in an exit criterion MUST exist in `DATA-DICTIONARY.md`; a report ID MUST exist in
`report-template/templates/`. Document 10 lists the check.
