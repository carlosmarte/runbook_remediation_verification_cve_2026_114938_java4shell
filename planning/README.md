# Planning — CVE-2026-114938 ("Java4Shell")

The runbook (`../cve_2026_114938_java4shell_remediation_verification_runbook.md`) is one long document
that mixes scope, scripts, edge rules, analyzers, gates and an eight-step plan. This folder breaks it into
separate plans, one per planning category, each written as step-by-step guidance with inputs, tools,
outputs, exit criteria and the side effects to watch. Every plan points at the concrete tooling in this
repository (`scripts/`, `helpers/`, `github/`, `patterns/`, `report-template/`, `docs/side-efforts/`).

## Plans

| # | Plan | Answers | Runbook sections | Typical owner |
| :--- | :--- | :--- | :--- | :--- |
| 00 | [Master programme plan](00-master-plan.md) | What happens in which order, by when, by whom; exit criteria | §8, §1 | Programme manager / incident commander |
| 01 | [Vulnerability assessment plan](01-vulnerability-assessment-plan.md) | Are we affected, where, how badly | §1, §2, §3 | Security engineering |
| 02 | [Scanning plan](02-scanning-plan.md) | Which scans run where, how often, with what noise handling (runtime, estate, code search, source, bytecode, dependencies, manifests, images) | §2, §3, §5, §6, §7.3 | Security engineering, platform |
| 03 | [Input provenance & tracing plan](03-input-provenance-tracing-plan.md) | Which decode call sites are reachable from untrusted input, through which touchpoints | §1 side effects, §6 | AppSec, service teams |
| 04 | [Mitigation rollout plan](04-mitigation-rollout-plan.md) | How to get `-XX:-UseBASE64Intrinsics` live everywhere safely and prove it | §2, §8.5, §8.6 | Platform / SRE, service teams |
| 05 | [Patch & upgrade plan](05-patch-upgrade-plan.md) | How to reach the patched baselines, migrate EOL lines, and retire the flag | §1, §8.7 | Engineering teams, platform |
| 06 | [CI/CD integration plan](06-ci-cd-integration-plan.md) | How to make the fix durable: gate, required checks, SARIF, exemptions | §7 | DevOps / release engineering |
| 07 | [Edge compensating controls plan](07-edge-compensating-controls-plan.md) | How to deploy, tune and retire WAF / proxy rules | §4 | Edge / network security |
| 08 | [Observability & monitoring plan](08-observability-monitoring-plan.md) | What to measure and alert on: exposure drift, crashes, probes, performance | §2, §4, side effects 01–05 | SRE, SOC |
| 09 | [Incident response plan](09-incident-response-plan.md) | What to do when a crash or probe indicates exploitation | side effects 01–02, §4 | SOC / IR |
| 10 | [Verification & validation plan](10-verification-validation-plan.md) | How each step proves it is done; evidence standards; before/after | §2, §3, §8.6 | Security engineering, audit |
| 11 | [Communication & reporting plan](11-communication-reporting-plan.md) | Who hears what, when, in which report | — (uses `../report-template/`) | Programme manager |
| 12 | [Checklists](12-checklists.md) | Tick-box lists for day 0, per host, per service, per repository, per PR, per release, closure | all | Everyone |
| 13 | [Plans by organisational level](levels/) | Executive, programme / security leadership, engineering management, team, engineer / operator | all | Each level |

## How the plans fit together

```
            01 Assessment ──► 02 Scanning ──► 03 Tracing
                 │                 │              │
                 ▼                 ▼              ▼
            04 Mitigation ◄──── 10 Verification ◄── 06 CI/CD gate
                 │                 ▲
                 ▼                 │
            05 Patch/upgrade ──────┘        07 Edge controls ──► 08 Observability ──► 09 Incident response
                                                                         │
            00 Master plan (sequence, dates, owners)   11 Communication (reports R0–R10)   12 Checklists
```

- **Assessment** decides scope and risk; **Scanning** produces the evidence; **Tracing** turns call sites into
  reachability verdicts.
- **Mitigation** (flag) is the fast path; **Patch** is the real fix; **Verification** proves both; **CI/CD** keeps
  them from regressing.
- **Edge controls**, **Observability** and **Incident response** cover the window in which the fleet is not yet
  patched.
- **Master plan**, **Communication** and **Checklists** are the glue; the **level plans** restate the whole
  thing for each audience.

## Conventions used in every plan

| Element | Meaning |
| :--- | :--- |
| **Objective** | the question the plan answers or the state it reaches |
| **Inputs / Outputs** | files and facts consumed and produced; outputs feed `../report-template/tools/j4s_facts.py` |
| **Steps** | numbered, imperative, each with the command or artefact to use |
| **Exit criteria** | observable conditions, never "done when the team says so" |
| **Side effects** | numbered references to `../docs/side-efforts/NN-*.md` |
| **Patterns** | `J4S-*` identifiers from `../patterns/SPEC.md` |
| **Timing** | relative to disclosure (T0 = 2026-11-17): T+hours / T+days; adjust to your SLA (`default mitigation 2 d, patch 30 d`) |
| **Verdict words** | runtime `EXPOSED_ON_VBMI_HOST`, `UNVERIFIED_ON_HOST`, `MITIGATED_BY_FLAG`, `PATCHED_OR_SAFE_VERSION`; repository `EXPOSED`, `EXPLICITLY_ENABLED`, `MITIGATED_FLAG`, `UNVERIFIED_FLOATING`, `UNVERIFIED_NO_PIN`, `PATCHED`; code `DYNAMIC_UNTRUSTED`, `DYNAMIC_INTERNAL`, `CONSTANT`, `UNKNOWN`; reachability `REACHABLE_HIGH`, `REACHABLE_CODE_ONLY`, `CONDITIONAL_LOW`, `UNREACHABLE_OR_N_A` |

## Facts every plan relies on (runbook §1)

- Affected: OpenJDK HotSpot and downstream builds, x86-64 with AVX-512 VBMI, JDK 17.0.6–17.0.21.0.2, 21 < 21.0.13.1,
  25 < 25.0.5.1, 27 < 27.0.1.1, EOL 18–20 / 22–24 / 26, Oracle 8u511b33-perf. Standard 8 and 11, and anything ≤ 16, are not.
- Not exposed by hardware: ARM64 (Graviton, Apple Silicon) and x86-64 without `avx512_vbmi`. They still carry the
  vulnerable code and must be patched before hardware changes.
- Mitigation: `-XX:-UseBASE64Intrinsics` (preferred) or `-XX:UseAVX=0..2` (broad cost). Confirmed only by the live JVM.
- Fix: upgrade to 17.0.21.0.3+, 21.0.13.1+, 25.0.5.1+, 27.0.1.1+ or vendor equivalent.
- Consequences if left alone: pre-auth RCE, JVM crash (DoS), heap disclosure ("JavaBleed").
