# Data Dictionary — report facts for CVE-2026-114938 ("Java4Shell")

Every template placeholder resolves against `facts.json`, produced by `tools/j4s_facts.py` from the
scanner outputs in this repository. This file states where each number comes from and how the derived
insights are computed, so a reader can audit a report back to its evidence.

## Evidence producers

| Section | Producer | Command | Shape consumed |
| :--- | :--- | :--- | :--- |
| `fleet`, `trend` | `scripts/audit_java4shell.py` | `sudo scripts/audit_java4shell.py --pretty > audits/audit-<host>.json` (one per host; `--audit-before` takes an earlier run) | `{cpu{arch, avx512_vbmi}, jvm_processes[{pid, source, parsed_version, version_status, flag_status, cmdline, exposure_verdict}], containers[]}`; host name from the file name unless the JSON has `host` |
| `repos` | `github/gh_j4s_scan.py` | `github/gh_j4s_scan.py --org ORG [--source] --format json --out estate.json` | `{scope, generated_at, repos[{repo, html_url, verdict, versions[{raw, normalized, status, kind, scope}], flags[{state, scope}], gate_ci, source_hits[{pre_auth_context}], reasons[], actions[], is_java, primary_language, pushed_at}]}` |
| `posture` | `github/gh_j4s_actions.sh` | `github/gh_j4s_actions.sh --org ORG --format tsv --out posture.tsv` | TSV columns `REPO LANG ARCHIVED BRANCH GATE_WORKFLOW GATE_LAST_RUN GATE_REQUIRED VAR_FLAG CODE_SCANNING DEPENDABOT TRACKING` |
| `source` | `scripts/scan_java4shell_source.py` | `scripts/scan_java4shell_source.py ./src --json > src.json` | `{root, total, dynamic_untrusted, findings[{file, line, column, call, argument, input_kind, sources[], preauth_context, is_test, reason, remediation}]}` |
| `jars` | `scripts/scan_java4shell_jars.py` | `scripts/scan_java4shell_jars.py build/libs --jsonl findings.jsonl` | JSONL `{artifact_path, entry_path, class_name, method_name, invoked_targets[], is_shaded, is_test_artifact, …}` |
| `gate` | `scripts/gate_cve_2026_114938.py` | `scripts/gate_cve_2026_114938.py --scan-dir . --require-flag > gate.log 2>&1` | text: `POLICY GATE PASSED` or `FAILED` followed by `  - [Kind:path] reason` lines |
| `crashes` | `helpers/j4s_hs_err.py` | `helpers/j4s_hs_err.py /var/log/app/hs_err_pid*.log --json > crashes.json` | list of `{file, signal, problematic_frame, jre_version, version_status, mitigation_present, explicitly_enabled, cpu_avx512_vbmi, base64_frames[], heap_corruption_markers[], verdict, score, reasons[]}` |
| `traffic` | `helpers/j4s_b64check.py` | `helpers/j4s_b64check.py scan access.log --min-len 64 --json > traffic.json` | list of `{line, analysis{token, length, alphabet, pad_count, strict_valid, anomalies[], edge_rules_hit[], suspicious, looks_like_jwt}}` (flat `{token, …}` records also accepted) |
| `extra` | you | `--extra narrative.json` | any JSON; templates read `extra.decisions`, `extra.business_units`, `extra.blockers`, `extra.exceptions`, `extra.milestones`, `extra.service`, `extra.incident`, `extra.edge`, `extra.attestation`, `extra.k8s`, `extra.code_search`, `extra.steps`, `extra.side_effects` |
| `meta` | `--meta k=v` | `--meta org="Acme" --meta scope="Payments" --meta report_date=2026-11-24` | see below |

## `meta`

| Key | Default | Meaning |
| :--- | :--- | :--- |
| `org`, `scope`, `prepared_by`, `owner`, `distribution`, `classification` | generic text | organisation context, override with `--meta` |
| `report_id` | `J4S-YYYYMMDD` | identifier printed on R1/R9 |
| `report_date` | today | drives `days_since_disclosure` and SLA breach flags |
| `period` | last 7 days | reporting window text |
| `next_review` | report_date + 7 d | |
| `cve`, `alias`, `upstream_id`, `cwe`, `cvss31`, `cvss40`, `disclosure_date`, `baselines`, `mitigation_flag` | runbook §1 constants | identity block |
| `days_since_disclosure` | computed | `report_date − 2026-11-17` |
| `sla_mitigate_days`, `sla_patch_days` | 2, 30 | policy windows; override per organisation |
| `sla_mitigate_due`, `sla_patch_due` | computed | disclosure + SLA |
| `sla_mitigate_breached`, `sla_patch_breached` | computed | `report_date > due` (templates combine with exposure counts) |

## `status`

| Key | Rule |
| :--- | :--- |
| `rag` = **RED** | `fleet.exposed_vbmi > 0` **or** `repos.blocking > 0` **or** `crashes.likely > 0` **or** `posture.var_reenabled > 0` |
| `rag` = **AMBER** | not RED and any of: `fleet.unverified`, `fleet.mitigated_flag`, `repos.unverified_*`, `repos.mitigated_flag`, `source.untrusted_prod`, `gate.failed`, `crashes.possible`, `traffic.suspicious` |
| `rag` = **GREEN** | otherwise (includes "no evidence supplied", so always read `inputs`) |
| `reasons[]` | one sentence per triggered rule, in severity order |
| `red` / `amber` / `green` | booleans for `{{#if}}` |

## `fleet` (runtime)

| Key | Formula / source |
| :--- | :--- |
| `hosts`, `hosts_vbmi` | audit files; `cpu.avx512_vbmi == true` |
| `jvms`, `jvms_vbmi` | `len(jvm_processes)`; those on VBMI hosts |
| `exposed_vbmi` | count `exposure_verdict == EXPOSED_ON_VBMI_HOST` (vulnerable version, `MISSING_FLAG`, VBMI CPU) |
| `unverified` | `UNVERIFIED_ON_HOST` (vulnerable version, no flag, CPU without VBMI or unknown) |
| `mitigated_flag` | `MITIGATED_BY_FLAG` (`-XX:-UseBASE64Intrinsics` or `-XX:UseAVX=0..2` on cmdline/env) |
| `patched` | `PATCHED_OR_SAFE_VERSION` |
| `vulnerable_versions` | `version_status == VULN_RANGE` regardless of flag/CPU |
| `missing_flag` | `flag_status == MISSING_FLAG` |
| **`exposure_rate`** | `exposed_vbmi / jvms` |
| **`mitigation_coverage`** | `(mitigated_flag + patched) / jvms` — the "protected" share |
| **`patch_coverage`** | `patched / jvms` — the only number that goes to 100% at closure |
| `vbmi_host_share` | `hosts_vbmi / hosts` — how much of the fleet is in hardware scope |
| `hosts_rows[]` | per host: counts per verdict, `status` RED (any exposed) / AMBER (unverified or flag-only) / GREEN |
| `jvms_rows[]`, `exposed_rows[]`, `unverified_rows[]` | per process, worst first |

## `trend` (needs `--audit-before`)

Processes are matched by `(host, first 60 chars of cmdline)`. `improved` / `regressed` compare verdict rank
`EXPOSED_ON_VBMI_HOST < UNVERIFIED_ON_HOST < MITIGATED_BY_FLAG < PATCHED_OR_SAFE_VERSION`. `regressed_rows[]`
is the list to act on first: a regression usually means a redeploy dropped the flag. `exposed_before/after`,
`mitigation_before/after`, `patch_before/after` repeat the fleet metrics for both runs.

## `repos` (GitHub estate)

| Key | Formula / source |
| :--- | :--- |
| `total`, `java` | all scanned; `is_java == true` |
| `by_verdict{}`, `exposed`, `explicitly_enabled`, `mitigated_flag`, `unverified_floating`, `unverified_no_pin`, `patched`, `not_java`, `error` | verdict counts (see `github/README.md` for verdict semantics) |
| **`blocking`** | `exposed + explicitly_enabled` — what fails the release gate today |
| **`exposed_share`** | `blocking / java` |
| **`unverified_share`** | `(unverified_floating + unverified_no_pin) / java` — the "we cannot tell from the repo" share |
| `floating_share` | `unverified_floating / java` |
| **`gate_adoption`** | repos with a workflow referencing the gate / `java` |
| `without_gate[]` | Java repos lacking it |
| `source_hits`, `preauth_hits`, `repos_with_preauth[]` | from `--source` scans: J4S-SRC-01 sites and those with J4S-SRC-04 context |
| `rows[]` | per repo: `pins` = runtime-scope EXACT/FLOATING versions as `version (STATUS)`, `flag` = runtime flag states or `MISSING`, `gate`, `hits`, `preauth`, first `reason` |
| `exposed_rows[]`, `mitigated_rows[]`, `unverified_rows[]` | filtered views, worst first |

## `posture` (pipelines)

Counts over the TSV: `with_gate` (`GATE_WORKFLOW != none`), `gate_required` (`yes`), `gate_passing` /
`gate_failing` (last run starts with `success` / `failure`), `var_active` (`VAR_FLAG` starts with `ACTIVE` or
`CAPPED`), `var_reenabled` (`EXPLICITLY_ENABLED`), `cs_alerts`, `dependabot` (numeric sums; `n/a` counts 0).

## `source` (code)

| Key | Meaning |
| :--- | :--- |
| `total`, `files` | decode call sites and distinct files |
| `untrusted`, `internal`, `constant`, `unknown` | `input_kind` counts: `DYNAMIC_UNTRUSTED` (argument traced to request/header/body/file/socket), `DYNAMIC_INTERNAL`, `CONSTANT`, `UNKNOWN` |
| **`untrusted_prod`** | untrusted sites not in test code — the number that must reach zero or be wrapped in validation |
| `preauth` | `preauth_context == true` (Authorization/JWT/SAML/Basic nearby, J4S-SRC-04) |
| `test`, `prod` | `is_test` split (J4S-BC-04 heuristic) |
| `rows[]`, `untrusted_rows[]`, `review_rows[]`, `test_rows[]`, `preauth_rows[]` | worst first: untrusted → internal → unknown → constant, pre-auth first within each; `review_rows` = non-untrusted production sites |

## `jars` (bytecode)

`classes` (records), `artifacts` (distinct `artifact_path`), `shaded` (`is_shaded`: relocated `java.util.Base64`
copies in dependencies, J4S-BC-05), `test`/`prod` (`is_test_artifact`), `rows[]`, `artifact_rows[]` (per
artifact: classes, shaded count, test flag).

## `gate`

`status` PASSED/FAILED, `passed`/`failed` booleans, `count`, `violations[]` (the `- ` lines), `by_kind{}` (leading
`[Kind` token: `Dockerfile`, `Manifest`, `JVM_OPTS`, `JDK_VERSION`, `Reachability`), and three filtered lists
`version_violations[]`, `flag_violations[]`, `reachability_violations[]`.

## `crashes`

`files`, `likely`, `possible`, `unlikely` (verdict counts, score ≥ 6 LIKELY, ≥ 3 POSSIBLE), `rows[]`,
`flagged_rows[]` (LIKELY + POSSIBLE), `hosts_unmitigated` (flagged crashes whose `jvm_args` lacked the flag).

## `traffic`

`tokens`, `suspicious`, `jwt_like`, `edge_rule_counts{}`, `edge01`/`edge02`/`edge03` (hits of J4S-EDGE-01 `={3,}`,
EDGE-02 `=` followed by alphabet, EDGE-03 long run + single `=`), `rows[]` (suspicious tokens, truncated to 40
chars, max 200).

## `actions[]`

Consolidated recommendations generated from the same rules as `status`, ordered flag → remove re-enable →
patch unverified → upgrade flag-only → resolve floating → locate runtime → validate input → add gate →
fix gate → incident handling → edge promotion. Templates print them verbatim; edit after rendering if needed.

## `inputs{}`

The file paths that fed the facts, printed in R1 and R9 as the evidence register.

## Insight definitions used across the templates

| Insight | Definition | Why it matters |
| :--- | :--- | :--- |
| Exposure rate | exposed JVMs / all JVMs | the only number that must be zero within the mitigation SLA |
| Mitigation coverage | protected (flag or patch) / all JVMs | progress of the stop-gap |
| Patch coverage | patched / all JVMs | progress of the real fix; flag removal waits for 100% |
| Hardware scope share | VBMI hosts / all hosts | how much of the estate is exploitable today; the rest becomes exposed on hardware refresh |
| Blocking repositories | EXPOSED + EXPLICITLY_ENABLED | what the release gate would stop today |
| Unverified share | floating + no-pin / Java repos | the size of the "cannot tell from the code" problem; drives platform-team work |
| Gate adoption | repos with gate / Java repos | whether the fix can be lost silently by a later PR |
| Untrusted decode sites (prod) | `DYNAMIC_UNTRUSTED` not in tests | where input validation is mandatory regardless of JDK |
| Pre-auth sites | SRC-04 context | the attack surface reachable without credentials: prioritise these services |
| Regressions | verdict got worse between runs | redeploys dropping the flag; the earliest signal that the control is not durable |
| Exploitation indicators | LIKELY crashes, EDGE-01/02 tokens | turns a remediation programme into an incident (R8) |
