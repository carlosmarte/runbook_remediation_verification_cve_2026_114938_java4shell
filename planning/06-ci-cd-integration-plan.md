# 06 — CI/CD Integration Plan

**Objective.** Make the fix durable: every Java pipeline fails on a vulnerable JDK pin, a missing mitigation flag,
an explicit re-enable, or a `REACHABLE_HIGH` finding; findings appear on pull requests; exemptions are explicit and
time-boxed.
**Runbook basis.** §7.1 (gate), §7.2 (GitHub Actions and GitLab CI), §7.3 (patterns); side effect 10 (false
positives); `github/gh_j4s_actions.sh` for posture.
**Owner.** DevOps / release engineering with security defining policy. **Timing.** pilot T+2 d, org-wide by T+30 d.

## 1. Gate stages

| Stage | Command | Fails on | Where |
| :--- | :--- | :--- | :--- |
| Static policy | `python3 scripts/gate_cve_2026_114938.py --scan-dir . --require-flag --jvm-opts "${JAVA_TOOL_OPTIONS:-}"` | vulnerable JDK pin in Dockerfiles/manifests; flag missing where a Java workload is declared; `-XX:+UseBASE64Intrinsics` | every PR and push to protected branches |
| Source provenance | `scripts/scan_java4shell_source.py . --json --sarif src.sarif` (exit 2 on `DYNAMIC_UNTRUSTED`) | new untrusted decode sites (optionally blocking) | PRs touching Java/Kotlin/Scala |
| Bytecode + reachability | `scan_java4shell_jars.py` → `j4s_analyzer.cli` → `gate … --reachability-json` | `REACHABLE_HIGH` | builds that produce artifacts |
| SARIF upload | `github/codeql-action/upload-sarif@v3` | — (visibility) | after the scans |
| Image check (optional) | `docker run IMAGE java -version` + `helpers/j4s_version.py parse-output` | built image below baseline | image build jobs |

## 2. Steps

1. **Pilot on three repositories** (one Dockerfile-based service, one Helm-deployed, one library) using the
   workflow from runbook §7.2 (`.github/workflows/cve-2026-114938-gate.yml`) or the GitLab job. Run in
   non-blocking mode (`continue-on-error: true`) for one week and collect `gate.log` outputs.
2. **Tune false positives (side effect 10).** Confirm the shipped gate is used (five-component version parser,
   vendor-aware workload detection); add the rendered-chart step for Helm/Kustomize; exclude non-workload YAML kinds
   if your repos keep ConfigMaps next to Deployments; keep an allowlist file for non-JDK version strings if needed.
3. **Make it blocking.** Remove `continue-on-error`; set the job name (`java4shell-policy-gate`) as a **required
   status check** on the default and release branches (rulesets or classic protection).
   `github/gh_j4s_actions.sh` reports `GATE_REQUIRED` per repo.
4. **Add SARIF uploads** so source and estate findings appear in code scanning and on PR diffs; use rule IDs
   `J4S-*` consistently (the toolkit's SARIF writers do).
5. **Deliver the flag through CI too.** For pipelines that run tests on VBMI runners, set `JAVA_TOOL_OPTIONS` as a
   repository or organisation Actions variable; the posture check reads it (`VAR_FLAG`). Never set
   `-XX:+UseBASE64Intrinsics` in variables (the check flags `EXPLICITLY_ENABLED`).
6. **Roll out org-wide.** Generate the list of Java repos without the gate (`github/gh_j4s_scan.py … --format json` →
   `repos.without_gate`, or `gh_j4s_actions.sh --require-gate`) and open PRs adding the workflow; a reusable
   workflow (`workflow_call`) or an organisation ruleset "required workflows" cuts per-repo effort to minutes.
7. **Exemption process.** An exemption is a file in the repo (`.j4s-exemptions.yml`: rule, path, reason, approver,
   expiry) consumed by the gate wrapper, mirrored in the R9 exceptions register. Expired exemptions fail the gate.
8. **Wire reachability.** Where artifacts are built in CI, add the bytecode scan and the analyzer with runtime
   context (JDK status, flag, CPU class from plan 01) so mitigated services yield `REACHABLE_CODE_ONLY`, not blocks.
9. **Measure adoption weekly** with `gh_j4s_actions.sh` (R5 §2) and `gh_j4s_scan.py` (gate adoption); target 100 %
   of Java repos with a required, passing gate.
10. **Plan the retirement of `--require-flag`.** Once the fleet is patched (plan 05), the flag requirement can be
    dropped while the version gate stays permanently (it also catches the next JDK CVE's baseline update).

## 3. Reference: GitHub Actions and GitLab snippets

```yaml
# .github/workflows/cve-2026-114938-gate.yml  (runbook §7.2, abbreviated)
on: { pull_request: { branches: [main, 'release/**'] }, push: { branches: [main, 'release/**'] } }
permissions: { contents: read, security-events: write }
jobs:
  java4shell-policy-gate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.12" }
      - run: python3 scripts/gate_cve_2026_114938.py --scan-dir . --require-flag --jvm-opts "${JAVA_TOOL_OPTIONS:-}"
      - run: python3 scripts/scan_java4shell_source.py . --json --sarif src.sarif || true
      - uses: github/codeql-action/upload-sarif@v3
        if: always() && hashFiles('src.sarif') != ''
        with: { sarif_file: src.sarif }
```

```yaml
# .gitlab-ci.yml
cve_2026_114938_gate:
  stage: security-gate
  image: python:3.12-slim
  variables: { JAVA_TOOL_OPTIONS: "-XX:-UseBASE64Intrinsics" }
  script: python3 scripts/gate_cve_2026_114938.py --scan-dir . --require-flag --jvm-opts "$JAVA_TOOL_OPTIONS"
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH || $CI_COMMIT_BRANCH =~ /^release\//
```

## 4. Outputs

| Output | Consumer |
| :--- | :--- |
| Gate workflow in every Java repo; required check | R5, R7, posture |
| `gate.log` per run; SARIF in code scanning | facts, R4, R5 |
| Exemption files + register | R9 |
| Adoption trend | R1 scorecard |

## 5. Exit criteria

- 100 % of Java repositories have the gate workflow and it is a required check on protected branches.
- Latest gate run passing on every default branch, or a non-expired exemption.
- SARIF findings visible on PRs; `REACHABLE_HIGH` blocks where artifacts are built.
- No Actions variable re-enables the intrinsic.

## 6. Pitfalls

- A gate that fails on vendor tag formats trains teams to bypass it; fix the parser, do not loosen the policy.
- Gating unrendered Helm charts reports "flag missing" when it lives in values.
- Required checks on the default branch do not protect release branches unless listed.
- `continue-on-error` left on after the pilot is the most common reason a "gated" repo still ships vulnerable pins.
