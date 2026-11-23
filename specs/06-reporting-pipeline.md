# 06 — Reporting Pipeline (`report-template/`)

Turns scanner evidence into eleven audience-specific Markdown reports through a single facts file and a minimal
template language. Numbers come from evidence; judgement comes from the author via `narrative.json`.

## 1. Pipeline

**SPEC-06-01 Stages.**

1. **Collect** evidence with the scanners (any subset).
2. **Build** `facts.json` with `tools/j4s_facts.py`.
3. **Render** one or more `templates/R*.md` with `tools/render.py`.
4. **Add judgement** in `--extra narrative.json` or in the rendered Markdown. Numbers are never hand-edited.

`examples/build-examples.sh` runs stages 2–3 over `examples/data/` and MUST regenerate every
`examples/R*.example.md` and `examples/facts.example.json` without error (exit 0).

## 2. Evidence producers and shapes

**SPEC-06-02.** `j4s_facts.py` accepts exactly these inputs; shapes are the contracts in documents 02–04.

| Option | Producer | Shape |
| :--- | :--- | :--- |
| `--audit JSON...` | `scripts/audit_java4shell.py --pretty` (one file per host) | SPEC-02-15 |
| `--audit-before JSON...` | an earlier audit run | SPEC-02-15 |
| `--gh-scan JSON` | `github/gh_j4s_scan.py --format json` | SPEC-04-11 |
| `--actions TSV` | `github/gh_j4s_actions.sh --format tsv` | SPEC-04-18 |
| `--source JSON` | `scripts/scan_java4shell_source.py --json` | SPEC-02-21 |
| `--jars JSONL` | `scripts/scan_java4shell_jars.py --jsonl` | SPEC-02-26 |
| `--gate LOG` | `scripts/gate_cve_2026_114938.py > gate.log 2>&1` | SPEC-02-30 |
| `--crashes JSON` | `helpers/j4s_hs_err.py --json` | SPEC-03-14 (list of triage records) |
| `--b64 JSON` | `helpers/j4s_b64check.py scan --json` | list of `{line, analysis{...}}` or flat records |
| `--extra JSON` | author | free-form, merged under `extra` |
| `--meta KEY=VALUE` | author | see §4 |
| `--sla-mitigate-days N`, `--sla-patch-days N` | policy | defaults 2 and 30 |

Missing inputs are allowed: the corresponding section has `available: false` and templates hide it.

## 3. `facts.json` contract

**SPEC-06-03 Top-level keys.** `meta`, `status`, `fleet`, `trend`, `repos`, `posture`, `source`, `jars`, `gate`,
`crashes`, `traffic`, `actions`, `inputs`, `extra`. Every path a template may reference MUST be listed in
`DATA-DICTIONARY.md` with its formula and producing command.

**SPEC-06-04 Section formulas (normative summary; full detail in `DATA-DICTIONARY.md`).**

| Section | Required keys and formulas |
| :--- | :--- |
| `fleet` | `hosts`, `hosts_vbmi`, `jvms`, `jvms_vbmi`, verdict counts `exposed_vbmi`/`unverified`/`mitigated_flag`/`patched`, `vulnerable_versions`, `missing_flag`; **`exposure_rate = exposed_vbmi / jvms`**, **`mitigation_coverage = (mitigated_flag + patched) / jvms`**, **`patch_coverage = patched / jvms`**, `vbmi_host_share = hosts_vbmi / hosts`; `hosts_rows[]` with per-host status RED (any exposed) / AMBER (unverified or flag-only) / GREEN / NONE; `jvms_rows[]`, `exposed_rows[]`, `unverified_rows[]` worst-first |
| `trend` | processes matched by `(host, first 60 chars of cmdline)`; `improved`, `regressed`, `regressed_rows[]` by verdict rank (SPEC-01-10); before/after exposure, mitigation and patch metrics |
| `repos` | `total`, `java`, `by_verdict{}`, per-verdict counts; **`blocking = exposed + explicitly_enabled`**, **`exposed_share = blocking / java`**, **`unverified_share = (unverified_floating + unverified_no_pin) / java`**, `floating_share`, **`gate_adoption = repos with gate workflow / java`**, `without_gate[]`, `source_hits`, `preauth_hits`, `repos_with_preauth[]`, `rows[]` (pins as `version (STATUS)`, flag states or `MISSING`, gate, hits, preauth, first reason), filtered `exposed_rows[]`, `mitigated_rows[]`, `unverified_rows[]` |
| `posture` | `repos`, `with_gate`, `gate_required`, `gate_passing`, `gate_failing`, `var_active` (ACTIVE or CAPPED), `var_reenabled`, `cs_alerts`, `dependabot` (`n/a` counts 0) |
| `source` | `total`, `files`, `untrusted`, `internal`, `constant`, `unknown`, **`untrusted_prod`** (untrusted and not test), `preauth`, `test`, `prod`, `rows[]`, `untrusted_rows[]`, `review_rows[]`, `test_rows[]`, `preauth_rows[]` |
| `jars` | `classes`, `artifacts`, `shaded`, `test`, `prod`, `rows[]`, `artifact_rows[]` |
| `gate` | `status` PASSED/FAILED, `passed`, `failed`, `count`, `violations[]`, `by_kind{}` (`Dockerfile`, `Manifest`, `JVM_OPTS`, `JDK_VERSION`, `Reachability`), `version_violations[]`, `flag_violations[]`, `reachability_violations[]` |
| `crashes` | `files`, `likely`, `possible`, `unlikely`, `rows[]`, `flagged_rows[]`, `hosts_unmitigated` |
| `traffic` | `tokens`, `suspicious`, `jwt_like`, `edge_rule_counts{}`, `edge01`, `edge02`, `edge03`, `rows[]` (max 200, tokens truncated to 40 chars) |
| `actions[]` | consolidated recommendations in fixed order: flag → remove re-enable → patch unverified → upgrade flag-only → resolve floating → locate runtime → validate input → add gate → fix gate → incident handling → edge promotion |
| `inputs{}` | the file paths that fed the facts, exactly as passed on the command line (the evidence register); together with `meta.generated_at` this is the only run-dependent part of `facts.json`, so regenerated examples differ only in these fields |

**SPEC-06-05 `meta`.** Keys `org`, `scope`, `prepared_by`, `owner`, `distribution`, `classification`,
`report_id` (default `J4S-YYYYMMDD`), `report_date` (default today), `period`, `next_review` (+7 d), the runbook
identity constants (`cve`, `alias`, `upstream_id`, `cwe`, `cvss31`, `cvss40`, `disclosure_date`, `baselines`,
`mitigation_flag`), and computed `days_since_disclosure`, `sla_mitigate_days`, `sla_patch_days`,
`sla_mitigate_due`, `sla_patch_due`, `sla_mitigate_breached`, `sla_patch_breached`.

**SPEC-06-06 Stability.** Removing or renaming any key used by a shipped template is a breaking change and
requires a `DATA-DICTIONARY.md` update, a template update and regenerated examples in the same change.

## 4. RAG status

**SPEC-06-07.** `status.rag` is computed from the evidence supplied:

| RAG | Rule |
| :--- | :--- |
| **RED** | `fleet.exposed_vbmi > 0` or `repos.blocking > 0` or `crashes.likely > 0` or `posture.var_reenabled > 0` |
| **AMBER** | not RED and any of `fleet.unverified`, `fleet.mitigated_flag`, `repos.unverified_*`, `repos.mitigated_flag`, `source.untrusted_prod`, `gate.failed`, `crashes.possible`, `traffic.suspicious` |
| **GREEN** | otherwise (including "no evidence supplied", so templates MUST print `inputs`) |

`status.reasons[]` holds one sentence per triggered rule in severity order; `status.red|amber|green` are
booleans for templates. `helpers/j4s_report.py` MUST reach the same RAG for the same inputs (SPEC-03-16).

## 5. Template language (`tools/render.py`)

**SPEC-06-08 Syntax.** `{{path}}` dotted lookup; filters `{{path|pct}}` (ratio → percentage), `|int`, `|n`
(thousands), `|yesno`, `|count` (list length), `|join` (comma list), `|md` (escape pipes/newlines for tables),
`|default:TEXT`; loops `{{#each list}} … {{.}} {{.field}} {{@index}} … {{/each}}`; conditionals
`{{#if path}} … {{else}} … {{/if}}` (empty list, 0, "", missing are false); comments `{{! … }}`. Block tags
alone on a line do not leave blank lines.

**SPEC-06-09 CLI.** `render.py TEMPLATE facts.json [-o OUT] [--strict]`. Missing values render as `—` and are
listed on stderr; `--strict` makes any missing value an error (exit 1).

## 6. The eleven reports

**SPEC-06-10 Header comment.** Every template begins with a `{{! … }}` block stating: report ID and name,
Audience, SDLC phase, Cadence, Inputs (the exact `j4s_facts.py` options and producing commands), and Rule(s)
specific to that report.

**SPEC-06-11 Catalogue.**

| ID | Report | Audience (level) | Phase | Cadence | Primary evidence | Hard rules |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| R0 | Executive brief | board, CISO, CIO, BU executives | cross-phase | T+24 h, weekly until GREEN, closure | fleet, estate | one page; no file paths or PIDs; three numbers; decisions section |
| R1 | Programme status | security leadership, programme manager, IC | governance | daily → weekly | everything + narrative | scorecard, trend, SLA, blockers, exceptions, evidence register |
| R2 | Engineering portfolio | VP Eng, directors, EMs | plan / release | weekly | estate, posture, fleet; `extra.service_owners` | work queue worst-first |
| R3 | Service remediation | service owner, team lead, on-call | develop → operate | per service until PATCHED | that service's audits, repo, source, jars, gate | checklist mirrors plan 12 §C |
| R4 | Developer code findings | developers, reviewers, AppSec champions | develop / PR | per scan or PR | source, jars, gate | usable verbatim as PR comment; "must fix before merge" = `DYNAMIC_UNTRUSTED` |
| R5 | CI/CD release gate | release managers, DevOps, CAB | build / release | per RC, weekly roll-up | gate log, posture, estate | violations grouped by kind |
| R6 | Runtime verification | platform / SRE, SecOps | deploy / operate | daily in rollout, weekly after; before/after every change | audits (before/after), k8s | regressions first; live `jcmd` is the only proof of the flag |
| R7 | GitHub estate scan | AppSec, platform, managers | plan / develop / build | weekly; after org-wide change | `gh_j4s_scan`, `gh_j4s_actions`, code search | verdict distribution, unverified share, gate adoption |
| R8 | Incident triage | SOC, IR, forensics (+ CISO line) | incident | on every indicator | crashes, traffic, affected-host audits | LIKELY crash or EDGE-01/02 token turns remediation into an incident |
| R9 | Compliance attestation | audit, compliance, customers, regulators | closure | once; re-issued on scope change | final audits, estate, gate; `extra.attestation` | statement, evidence register, exceptions with expiry, signatories |
| R10 | Edge controls tuning | edge/WAF engineers, API owners, SOC | operate (count → block → retire) | per traffic cycle / weekly | traffic; `extra.edge` | false-positive samples; promotion criteria; retirement |

**SPEC-06-12 Altitude rule.** Executive reports read RAG and three numbers; programme reports read scorecards and
trends; team reports read hosts, repos and call sites for their service; engineer reports read file:line, PID,
token and rule. A template MUST NOT include detail below its altitude.

**SPEC-06-13 Shared conventions (every template).** Verdict words per document 00 §5; SLA text per
SPEC-01-15; baselines and mitigation per document 00 §2; scope words (never "safe" for flag-only); every table
row traces to an openable artefact; every report lists its input files; every report names the side effects its
actions trigger (`docs/side-efforts/` 04–11).

## 7. Worked examples

**SPEC-06-14.** `examples/data/` holds synthetic evidence for a fictional organisation ("Acme", day 7, two hosts
with one exposed, six repositories, one untrusted decode site, one LIKELY crash, suspicious edge tokens), in
exactly the shapes the scanners emit, clearly labelled synthetic. `examples/R*.example.md` are the rendered
outputs and MUST be regenerated whenever a template, `j4s_facts.py`, `render.py` or the sample data changes.

## 8. Documentation duties

**SPEC-06-15.** `report-template/README.md` MUST keep: the which-report-for-whom table, the four-altitudes table,
the SDLC map, the four-step production procedure with commands, the template syntax summary, the shared
conventions table, and the file tree. `DATA-DICTIONARY.md` MUST keep the evidence-producer table, every section's
key table, and the insight-definitions table (exposure rate, mitigation coverage, patch coverage, hardware scope
share, blocking repositories, unverified share, gate adoption, untrusted decode sites, pre-auth sites,
regressions, exploitation indicators).
