{{! ============================================================================
R5 - CI/CD Release Gate Report
Audience : Release managers, platform/DevOps engineers, change advisory board
SDLC     : build / test / release
Cadence  : per release candidate, plus a weekly roll-up across pipelines
Inputs   : --gate gate.log (one pipeline) and/or --actions posture.tsv + --gh-scan estate.json (all pipelines)
============================================================================ }}
# {{meta.cve}} ({{meta.alias}}) — CI/CD Release Gate Report

{{meta.org}} · {{meta.scope}} · {{meta.report_date}} · status **{{status.rag}}**

{{#if gate.available}}
## 1. This pipeline

**Gate result: {{gate.status}}** — {{gate.count}} violation(s){{#if extra.pipeline}} for `{{extra.pipeline.name}}` ({{extra.pipeline.ref}}, run {{extra.pipeline.run}}){{/if}}.

| Category | Violations | Blocking? | Typical fix |
| :--- | ---: | :--- | :--- |
| JDK version below baseline / EOL line / Oracle 8u511b33-perf | {{gate.version_violations|count}} | yes | pin `{{meta.baselines}}` or vendor equivalent |
| Mitigation flag missing or explicitly re-enabled | {{gate.flag_violations|count}} | yes with `--require-flag` | `ENV JAVA_TOOL_OPTIONS="-XX:-UseBASE64Intrinsics"`; delete `-XX:+UseBASE64Intrinsics` |
| Reachability `REACHABLE_HIGH` (untrusted decode on unmitigated runtime) | {{gate.reachability_violations|count}} | yes | validate input, apply flag, or supply runtime context showing patched/non-VBMI |

{{#if gate.violations}}
### Violations

{{#each gate.violations}}
- {{.}}
{{/each}}
{{/if}}

### False-positive triage (docs/side-efforts/10)

| Symptom | Check | Resolution |
| :--- | :--- | :--- |
| Patched tag reported vulnerable (`17.0.21.0.3`) | the shipped gate compares five components; confirm you run `scripts/gate_cve_2026_114938.py`, not the runbook listing | upgrade the gate copy |
| Non-JDK version flagged (`alpine:3.20.1`) | hit is on a line without a Java term | add the term-gated check or an allowlist entry |
| ConfigMap/Ingress with the word `java` fails flag check | `kind:` is not a workload | exclude kinds other than Deployment/StatefulSet/DaemonSet/Job/CronJob/Pod |
| Flag lives in Helm values, not the manifest | render the chart (`helm template`) before gating | gate the rendered output |
{{/if}}

{{#if posture.available}}
## 2. All pipelines ({{posture.repos}} repositories)

| Measure | Count |
| :--- | ---: |
| Gate workflow present | {{posture.with_gate}} |
| Gate required as a status check on the default branch | {{posture.gate_required}} |
| Latest gate run passing | {{posture.gate_passing}} |
| Latest gate run failing | {{posture.gate_failing}} |
| Mitigation flag delivered through Actions variables | {{posture.var_active}} |
| Intrinsic re-enabled through Actions variables (**fix now**) | {{posture.var_reenabled}} |
| Open code-scanning alerts for J4S rules | {{posture.cs_alerts}} |
| Open Dependabot alerts naming the CVE | {{posture.dependabot}} |

| Repository | Gate workflow | Last run | Required | Actions var flag | Code scanning | Dependabot | Tracking |
| :--- | :--- | :--- | :--- | :--- | ---: | ---: | :--- |
{{#each posture.rows}}
| {{.repo}} | {{.gate_workflow}} | {{.gate_last_run}} | {{.gate_required}} | {{.var_flag|md}} | {{.code_scanning}} | {{.dependabot}} | {{.tracking}} |
{{/each}}
{{/if}}

{{#if repos.available}}
## 3. What the gate would say about each repository today

| Repository | Verdict | Runtime JDK pins | Flag | Gate in repo |
| :--- | :--- | :--- | :--- | :--- |
{{#each repos.rows}}
| {{.repo}} | `{{.verdict}}` | {{.pins|md}} | {{.flag}} | {{.gate|yesno}} |
{{/each}}

Repositories still without a gate workflow: {{repos.without_gate|count}}.
{{/if}}

## 4. Gate policy (reference)

```yaml
# .github/workflows/cve-2026-114938-gate.yml (runbook §7.2) — required check "java4shell-policy-gate"
- run: python3 scripts/gate_cve_2026_114938.py --scan-dir . --require-flag --jvm-opts "${JAVA_TOOL_OPTIONS:-}"
- run: python3 scripts/gate_cve_2026_114938.py --scan-dir . --reachability-json reachability-findings.json
- uses: github/codeql-action/upload-sarif@v3     # SARIF from scan_java4shell_source.py / gh_j4s_scan.py --sarif-dir
```

Exit code `1` blocks the release. Exemptions require an entry in the R9 exceptions register with an expiry date.

## 5. Actions

{{#each actions}}
{{@index}}. {{.}}
{{/each}}
