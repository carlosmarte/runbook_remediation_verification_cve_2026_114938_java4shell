# Report Templates — CVE-2026-114938 ("Java4Shell")

Reusable report templates and worked examples for every audience that needs to see the output of the
detection, verification and GitHub scanners in this repository, organised by organisational level and
SDLC phase. The templates turn raw scanner evidence (host audits, repository scans, source and bytecode
findings, gate logs, crash triage, edge traffic) into the insights each reader acts on: exposure rate,
mitigation and patch coverage, blocking repositories, unverified share, gate adoption, pre-auth decode
sites, regressions and exploitation indicators.

Source of truth: `../cve_2026_114938_java4shell_remediation_verification_runbook.md` (§1 scope and
baselines, §2–§3 runtime evidence, §4 edge controls, §5–§6 code evidence, §7 CI gate, §8 plan).
Pattern IDs refer to `../patterns/SPEC.md`; side effects to `../docs/side-efforts/`.

## Which report, for whom, when

| ID | Report | Audience (level) | SDLC phase | Cadence | Primary evidence |
| :--- | :--- | :--- | :--- | :--- | :--- |
| R0 | [Executive brief](templates/R0-executive-brief.md) | Board, CISO, CIO, BU executives | cross-phase | T+24 h, weekly, closure | fleet audits, estate scan |
| R1 | [Programme status](templates/R1-program-status.md) | Security leadership, programme manager, incident commander | release / operate governance | daily → weekly | everything + narrative |
| R2 | [Engineering portfolio](templates/R2-engineering-portfolio.md) | VP Eng, directors, managers | plan / release | weekly | estate scan, posture, fleet |
| R3 | [Service remediation report](templates/R3-service-remediation-report.md) | Service owner, team lead, on-call | develop → release → operate | per service until PATCHED | that service's audits, repo, source, jars, gate |
| R4 | [Developer code findings](templates/R4-developer-code-findings.md) | Developers, reviewers, AppSec champions | develop / code review (PR comment) | per scan / PR | source scan, jar scan, gate |
| R5 | [CI/CD release gate](templates/R5-ci-cd-gate-report.md) | Release managers, DevOps, CAB | build / test / release | per release candidate, weekly roll-up | gate log, posture, estate |
| R6 | [Runtime verification](templates/R6-runtime-verification-report.md) | Platform / SRE, SecOps | deploy / operate | daily in rollout, weekly after; before/after every change | host audits (before/after), k8s inventory |
| R7 | [GitHub estate scan](templates/R7-github-estate-scan-report.md) | AppSec, platform engineering, managers | plan / develop / build | weekly | `gh_j4s_scan`, `gh_j4s_actions`, code search |
| R8 | [Incident triage](templates/R8-incident-triage-report.md) | SOC, IR, forensics (+ CISO line) | operate / incident response | on every indicator | crash triage, edge traffic, affected-host audits |
| R9 | [Compliance attestation](templates/R9-compliance-attestation.md) | Internal audit, compliance, customers, regulators | closure | once, re-issued on scope change | final audits, estate, gate, exceptions |
| R10 | [Edge controls tuning](templates/R10-edge-controls-tuning-report.md) | Edge/WAF engineers, API owners, SOC | operate (compensating control lifecycle) | per traffic cycle in count mode, weekly in block mode | edge traffic analysis, rule hit counts |

### The same facts, four altitudes

| Level | Reads | Wants | Reports |
| :--- | :--- | :--- | :--- |
| Executive | one page, RAG, three numbers, decisions | are we exposed, by when is it fixed, what does it cost | R0, R9 |
| Programme / leadership | scorecard, trend, SLA, blockers, exceptions | is the plan on track, where to push | R1, R2 |
| Team / service | hosts, repos, call sites for *my* service, checklist | what exactly do I change and how do I prove it | R3, R6, R7, R5 |
| Engineer / operator | file:line, PID, token, rule | fix it in this PR / on this box / at this edge | R4, R6, R8, R10 |

### SDLC map

```
 plan ──── design ──── develop ──── build/test ──── release ──── deploy ──── operate ──── incident ──── closure
  R2        R7           R4            R5             R5/R1       R6          R6/R1        R8           R9
  R7                     R3            R4                                     R10          R10          R0
```

## How to produce a report

1. **Collect evidence** with the scanners (any subset is fine; templates hide sections without data):

   ```bash
   sudo ../scripts/audit_java4shell.py --pretty > audits/audit-$(hostname).json      # per host
   ../github/gh_j4s_scan.py --org acme --source --format json --out estate.json
   ../github/gh_j4s_actions.sh --org acme --format tsv --out posture.tsv
   ../scripts/scan_java4shell_source.py ./src --json > src.json
   ../scripts/scan_java4shell_jars.py build/libs --jsonl findings.jsonl
   ../scripts/gate_cve_2026_114938.py --scan-dir . --require-flag > gate.log 2>&1
   ../helpers/j4s_hs_err.py /var/log/app/hs_err_pid*.log --json > crashes.json
   ../helpers/j4s_b64check.py scan /var/log/nginx/access.log --min-len 64 --json > traffic.json
   ```

2. **Build the facts file** (derived insights, RAG status, SLA dates, consolidated actions):

   ```bash
   tools/j4s_facts.py --audit audits/*.json --audit-before audits-before/*.json \
     --gh-scan estate.json --actions posture.tsv --source src.json --jars findings.jsonl --gate gate.log \
     --crashes crashes.json --b64 traffic.json \
     --meta org="Acme Corp" --meta scope="Payments BU" --meta owner="CISO" --meta prepared_by="Platform Security" \
     --extra narrative.json --sla-mitigate-days 2 --sla-patch-days 30 -o facts.json
   ```

3. **Render** the template(s) you need:

   ```bash
   tools/render.py templates/R0-executive-brief.md facts.json -o out/R0-executive-brief.md
   for t in templates/R*.md; do tools/render.py "$t" facts.json -o "out/$(basename "$t")"; done
   ```

4. **Add judgement.** Decisions, owners, dates, exceptions and incident narrative live in `narrative.json`
   (`extra.*`) or are typed into the rendered Markdown. The numbers are not edited by hand.

`examples/build-examples.sh` runs steps 2–3 over the sample evidence in `examples/data/` and writes the
worked examples in `examples/`.

## Template syntax

Templates are Markdown with a minimal placeholder language understood by `tools/render.py`: `{{path}}`,
filters `{{path|pct}}` / `|int` / `|n` / `|yesno` / `|count` / `|join` / `|md` / `|default:TEXT`, loops
`{{#each list}} … {{.field}} … {{/each}}`, conditionals `{{#if path}} … {{else}} … {{/if}}`, comments
`{{! … }}`. The header comment of every template states audience, phase, cadence and the exact commands
that produce its inputs. All available paths are documented in [DATA-DICTIONARY.md](DATA-DICTIONARY.md).

## Conventions shared by every report

| Convention | Rule |
| :--- | :--- |
| **RAG** | RED: any exposed JVM on VBMI hardware, any repository deploying a vulnerable JDK unmitigated or re-enabling the intrinsic, any LIKELY crash. AMBER: vulnerable but flag-mitigated or unverified, untrusted decode sites, gate failing, POSSIBLE crashes, suspicious traffic. GREEN: none of the above *in the evidence supplied*. |
| **Verdicts** | runtime: `EXPOSED_ON_VBMI_HOST`, `UNVERIFIED_ON_HOST`, `MITIGATED_BY_FLAG`, `PATCHED_OR_SAFE_VERSION`. repository: `EXPOSED`, `EXPLICITLY_ENABLED`, `MITIGATED_FLAG`, `UNVERIFIED_FLOATING`, `UNVERIFIED_NO_PIN`, `PATCHED`, `NOT_JAVA`. code: `DYNAMIC_UNTRUSTED`, `DYNAMIC_INTERNAL`, `CONSTANT`, `UNKNOWN`; pre-auth flag. crash: `LIKELY`, `POSSIBLE`, `UNLIKELY`. |
| **SLAs** | default mitigation 2 days, patch 30 days from disclosure (2026-11-17); override with `--sla-*-days`. Breach is reported only when exposure remains. |
| **Baselines** | 17.0.21.0.3+, 21.0.13.1+, 25.0.5.1+, 27.0.1.1+; 18–20 / 22–24 / 26 are EOL with no patch; ≤ 16 unaffected except Oracle 8u511b33-perf. |
| **Mitigation** | `-XX:-UseBASE64Intrinsics` (preferred) or `-XX:UseAVX=0..2` (broad performance cost). The flag is confirmed only by the live JVM (`jcmd`), never by a manifest alone. |
| **Scope words** | *exposed* = exploitable now; *unverified* = vulnerable build, not exploitable on this CPU, or cannot be determined; *mitigated* = flag live; *patched* = baseline met. Never write "safe" for a flag-only state. |
| **Evidence** | every table row traces to a file, PID, repo or token the reader can open; every report lists its input files. |
| **Side effects** | each report names the side effects its actions trigger (`../docs/side-efforts/` 04–11). |

## Files

```
report-template/
├── README.md                 this file
├── DATA-DICTIONARY.md        every facts.json field and insight formula, with the producing command
├── templates/R0 … R10        the eleven templates
├── tools/j4s_facts.py        evidence -> facts.json (insights, RAG, SLA, actions)
├── tools/render.py           facts.json + template -> Markdown
└── examples/
    ├── data/                 synthetic evidence for a fictional organisation ("Acme") in the shapes the scanners emit
    ├── build-examples.sh     regenerates the examples below
    └── R0 … R10 *.example.md rendered worked examples
```

The example data is synthetic and labelled as such. It describes a fictional organisation on day 7 after
disclosure: two audited hosts, one still exposed; six repositories; one untrusted decode site; one LIKELY
crash; suspicious edge tokens. It is meant to show what each report looks like when the numbers are not
zero.
