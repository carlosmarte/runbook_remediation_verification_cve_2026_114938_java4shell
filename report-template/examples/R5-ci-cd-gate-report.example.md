# CVE-2026-114938 (Java4Shell) — CI/CD Release Gate Report

Acme Corp (fictional example) · Payments, Identity and Finance Ops production · 2026-11-24 · status **RED**

## 1. This pipeline

**Gate result: FAILED** — 4 violation(s) for `payments-api release` (refs/heads/main, run #2291).

| Category | Violations | Blocking? | Typical fix |
| :--- | ---: | :--- | :--- |
| JDK version below baseline / EOL line / Oracle 8u511b33-perf | 1 | yes | pin `17.0.21.0.3+ / 21.0.13.1+ / 25.0.5.1+ / 27.0.1.1+` or vendor equivalent |
| Mitigation flag missing or explicitly re-enabled | 1 | yes with `--require-flag` | `ENV JAVA_TOOL_OPTIONS="-XX:-UseBASE64Intrinsics"`; delete `-XX:+UseBASE64Intrinsics` |
| Reachability `REACHABLE_HIGH` (untrusted decode on unmitigated runtime) | 1 | yes | validate input, apply flag, or supply runtime context showing patched/non-VBMI |

### Violations

- [Dockerfile:payments-api/Dockerfile] JDK 21.0.12 (< 21.0.13.1) is unpatched
- [Dockerfile:payments-api/Dockerfile] Missing -XX:-UseBASE64Intrinsics (or -XX:UseAVX=0..2) in ENV/ENTRYPOINT/CMD
- [Manifest:payments-api/deploy/k8s/deployment.yaml] JVM workload missing -XX:-UseBASE64Intrinsics (e.g., via JAVA_TOOL_OPTIONS or container args)
- [Reachability:reachability-findings.json] J4S-0001 is REACHABLE_HIGH in com.acme.pay.auth.BasicAuthFilter.doFilter (payments-api/build/libs/payments-api-2.14.0.jar)

### False-positive triage (docs/side-efforts/10)

| Symptom | Check | Resolution |
| :--- | :--- | :--- |
| Patched tag reported vulnerable (`17.0.21.0.3`) | the shipped gate compares five components; confirm you run `scripts/gate_cve_2026_114938.py`, not the runbook listing | upgrade the gate copy |
| Non-JDK version flagged (`alpine:3.20.1`) | hit is on a line without a Java term | add the term-gated check or an allowlist entry |
| ConfigMap/Ingress with the word `java` fails flag check | `kind:` is not a workload | exclude kinds other than Deployment/StatefulSet/DaemonSet/Job/CronJob/Pod |
| Flag lives in Helm values, not the manifest | render the chart (`helm template`) before gating | gate the rendered output |

## 2. All pipelines (6 repositories)

| Measure | Count |
| :--- | ---: |
| Gate workflow present | 3 |
| Gate required as a status check on the default branch | 2 |
| Latest gate run passing | 2 |
| Latest gate run failing | 1 |
| Mitigation flag delivered through Actions variables | 1 |
| Intrinsic re-enabled through Actions variables (**fix now**) | 1 |
| Open code-scanning alerts for J4S rules | 2 |
| Open Dependabot alerts naming the CVE | 0 |

| Repository | Gate workflow | Last run | Required | Actions var flag | Code scanning | Dependabot | Tracking |
| :--- | :--- | :--- | :--- | :--- | ---: | ---: | :--- |
| acme/payments-api | none | none | no | MISSING | 2 | 0 | 1i/1pr |
| acme/legacy-sso | none | none | unknown | EXPLICITLY_ENABLED | n/a | n/a | 0i/0pr |
| acme/auth-gateway | cve-2026-114938-gate.yml | success 2026-11-23 main | yes | ACTIVE | 0 | 0 | 1i/0pr |
| acme/report-renderer | cve-2026-114938-gate.yml | failure 2026-11-22 main | no | NONE | 0 | 0 | 0i/1pr |
| acme/batch-recon | none | none | no | NONE | n/a | 0 | 0i/0pr |
| acme/notifications | cve-2026-114938-gate.yml | success 2026-11-21 main | yes | NONE | 0 | 0 | 0i/0pr |

## 3. What the gate would say about each repository today

| Repository | Verdict | Runtime JDK pins | Flag | Gate in repo |
| :--- | :--- | :--- | :--- | :--- |
| acme/payments-api | `EXPOSED` | 21.0.12 (VULN_RANGE) | MISSING | no |
| acme/legacy-sso | `EXPLICITLY_ENABLED` | 19-jdk (VULN_RANGE) | EXPLICITLY_ENABLED | no |
| acme/auth-gateway | `MITIGATED_FLAG` | 21.0.5 (VULN_RANGE) | ACTIVE | yes |
| acme/report-renderer | `UNVERIFIED_FLOATING` | 25-jre (FLOATING_PATCHABLE) | MISSING | yes |
| acme/batch-recon | `UNVERIFIED_NO_PIN` | - | MISSING | no |
| acme/notifications | `PATCHED` | 21.0.13.1 (PATCHED_OR_UNAFFECTED) | MISSING | yes |

Repositories still without a gate workflow: 3.

## 4. Gate policy (reference)

```yaml
# .github/workflows/cve-2026-114938-gate.yml (runbook §7.2) — required check "java4shell-policy-gate"
- run: python3 scripts/gate_cve_2026_114938.py --scan-dir . --require-flag --jvm-opts "${JAVA_TOOL_OPTIONS:-}"
- run: python3 scripts/gate_cve_2026_114938.py --scan-dir . --reachability-json reachability-findings.json
- uses: github/codeql-action/upload-sarif@v3     # SARIF from scan_java4shell_source.py / gh_j4s_scan.py --sarif-dir
```

Exit code `1` blocks the release. Exemptions require an entry in the R9 exceptions register with an expiry date.

## 5. Actions

1. Apply -XX:-UseBASE64Intrinsics to 1 exposed JVM(s) on VBMI hosts now (JAVA_TOOL_OPTIONS or launch args) and confirm with jcmd VM.flags.
2. Set JAVA_TOOL_OPTIONS=-XX:-UseBASE64Intrinsics in the runtime definition of 1 repositor(ies) and open upgrade PRs to 17.0.21.0.3+ / 21.0.13.1+ / 25.0.5.1+ / 27.0.1.1+.
3. Remove every -XX:+UseBASE64Intrinsics (J4S-FLAG-04) from manifests, start scripts and Actions variables.
4. Patch 1 JVM(s) on vulnerable versions that sit on non-VBMI CPUs before workloads move to Ice Lake / Zen 4 class hardware.
5. Schedule JDK upgrades for the 1 JVM(s) and 1 repositor(ies) that rely on the flag; keep the flag until java -version shows the baseline.
6. Resolve 1 floating image/package pin(s) to exact versions (docker run IMAGE java -version) and pin digests.
7. Locate the runtime for 1 Java repositor(ies) without a pin (platform image, host JDK, Helm values repo) and audit it with verify_java4shell_runtime.sh.
8. Add strict Base64 validation (length multiple of 4, no mid-string '=', at most two pads) before the 2 untrusted decode call site(s).
9. Add gate_cve_2026_114938.py to the pipelines of 3 Java repositor(ies) and make the check required on the default branch.
10. Resolve 4 CI gate violation(s) before the next release.
11. Treat LIKELY/POSSIBLE crash files as exploitation attempts: preserve hs_err and heap dumps, rotate secrets resident in those JVMs, correlate with edge hits.
12. Move edge rules J4S-EDGE-01/02 from count to block for routes that received suspicious tokens; keep EDGE-03 in count mode until false positives are tuned.
