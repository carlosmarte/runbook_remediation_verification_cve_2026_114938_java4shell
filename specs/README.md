# Specification — CVE-2026-114938 ("Java4Shell") Remediation & Verification Toolkit

**Spec version:** 1.0.0 (2026-11-20)
**Status:** Active
**Source of truth:** `../cve_2026_114938_java4shell_remediation_verification_runbook.md` (the runbook), as realised
by the shipped components in `../scripts/`, `../helpers/`, `../github/`, `../patterns/`, `../report-template/`,
`../planning/` and `../docs/side-efforts/`.

This folder is the normative specification of the toolkit. It states what each component must do, what it
consumes and produces, the vocabulary every component shares, and the acceptance criteria that prove a change
has not broken the contract. Where the shipped code deliberately deviates from the runbook text, the deviation
is specified here as the requirement and the runbook text is recorded as superseded.

## Documents

| # | Document | Specifies |
| :--- | :--- | :--- |
| 00 | [Overview, scope and shared vocabulary](00-overview-scope-and-vocabulary.md) | Problem statement, vulnerability facts, system boundary, design principles, controlled vocabularies (verdicts, severities, flag states), requirement numbering |
| 01 | [Shared decision rules](01-shared-decision-rules.md) | Version classification, mitigation-flag detection, exposure and reachability verdict logic, hardware scope, exit-code convention. Every component must implement these identically. |
| 02 | [Detection scripts](02-detection-scripts.md) | `scripts/`: runtime verification, fleet audit (bash and JSON), source scan, bytecode scan, CI/CD policy gate |
| 03 | [Helpers and the `j4s` CLI](03-helpers-and-cli.md) | `helpers/`: single entry point, flag management, version classifier, process and Kubernetes investigation, Base64 token analysis, crash triage, inventory, status report |
| 04 | [GitHub estate scanners](04-github-scanners.md) | `github/`: repository discovery, remote repository scan and verdicts, code-search sweep, CI/CD posture |
| 05 | [Pattern catalogue](05-pattern-catalogue.md) | `patterns/`: the `J4S-<AREA>-<NN>` identifiers, file format, severities, phase map, known gaps |
| 06 | [Reporting pipeline](06-reporting-pipeline.md) | `report-template/`: evidence producers, `facts.json` contract, RAG rules, template language, the eleven reports R0–R10, worked examples |
| 07 | [Planning documents](07-planning-documents.md) | `planning/`: the master programme plan, twelve category plans, five level plans, conventions and timeline |
| 08 | [Side-effect documentation](08-side-effects.md) | `docs/side-efforts/`: the eleven documented effects, their structure, and how components must reference them |
| 09 | [Runbook reference components](09-runbook-reference-components.md) | Components the runbook defines in full but the repository does not ship as files: edge/WAF rules, Rust `j4s-extract`, Python `j4s_analyzer`, CI workflow examples |
| 10 | [Cross-cutting requirements and acceptance](10-cross-cutting-and-acceptance.md) | Portability, safety (non-intrusiveness), dependencies, data-contract stability, documentation duties, acceptance test matrix, change control |

## Requirement identifiers

Requirements are numbered `SPEC-<DOC>-<NN>` where `<DOC>` is the two-digit document number above, e.g.
`SPEC-02-07`. The words **MUST**, **MUST NOT**, **SHOULD** and **MAY** carry their RFC 2119 meaning. A
component is conformant when every MUST that names it holds; a SHOULD may be waived with a recorded reason.

## Reading order

1. Read 00 and 01 once; they define every term and rule the other documents use.
2. Read the document for the component you are changing.
3. Read 10 before merging: it lists the acceptance checks and which documents a change must update.

## Repository map (what is specified where)

```
cve_2026_114938_java4shell_remediation_verification_runbook.md   source of truth (facts, reference code)   -> 00, 01, 09
scripts/        6 detection scripts                              -> 02
helpers/        j4s CLI + 8 helpers                              -> 03
github/         4 GitHub scanners                                -> 04
patterns/       SPEC.md index + 41 pattern files                 -> 05
report-template/ 11 templates, 2 tools, data dictionary, examples -> 06
planning/       00–12 plans + 5 level plans                      -> 07
docs/side-efforts/ 11 side-effect notes                          -> 08
specs/          this specification                               -> README
```
