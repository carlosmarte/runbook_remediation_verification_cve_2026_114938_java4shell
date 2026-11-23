# CVE-2026-114938 (Java4Shell) — Remediation Programme Status

**Report J4S-20261124** · 2026-11-24 · period 2026-11-17 to 2026-11-24 · day 7 since disclosure
**Status: RED** · owner CISO · prepared by Platform Security · next review 2026-12-01

## 1. Headline

- 1 JVM(s) exposed on AVX-512 VBMI hosts without patch or flag
- 2 repositor(ies) deploy a vulnerable JDK without the mitigation flag or re-enable the intrinsic
- 1 crash file(s) triaged LIKELY Java4Shell
- 1 repositor(ies) re-enable the intrinsic through Actions variables
- 1 unverified and 1 flag-mitigated JVM(s) still on vulnerable versions
- 2 repositor(ies) unverified, 1 mitigated by flag only
- 2 production call site(s) decode untrusted Base64
- CI gate failing with 4 violation(s)
- 1 crash file(s) triaged POSSIBLE
- 3 suspicious malformed-Base64 token(s) in traffic

## 2. Scorecard

| Indicator | Now | Target | SLA |
| :--- | ---: | ---: | :--- |
| JVMs exposed on VBMI hosts | 1 | 0 | by 2026-11-19 (2 d) |
| Mitigation coverage (flag or patch) | 60% | 100% | by 2026-11-19 |
| Patch coverage | 40% | 100% | by 2026-12-17 (30 d) |
| Repositories deploying a vulnerable JDK unmitigated | 2 | 0 | by 2026-11-19 |
| Repositories unverified (floating / no pin) | 1 + 1 | 0 | by 2026-12-17 |
| Release gate adoption (Java repos) | 50% | 100% | 2026-12-05 |
| Untrusted Base64 decode sites in production code | 2 | validated | by 2026-12-17 |
| Crash files LIKELY / POSSIBLE | 1 / 1 | 0 | continuous |
| Suspicious edge tokens (period) | 3 | monitored | continuous |

## 3. Movement since last run

| | Before | Now |
| :--- | ---: | ---: |
| Exposed JVMs | 3 | 1 |
| Mitigation coverage | 0% | 60% |
| Patch coverage | 0% | 40% |

1 JVM(s) improved, **0 regressed**, 3 new, 1 no longer running.

## 4. Progress against the runbook plan (§8)

| Step | Activity | Evidence | State |
| :--- | :--- | :--- | :--- |
| 1 | Inventory runtimes & containers | 2 hosts, 5 JVMs; 7 repositories scanned | done |
| 2 | Verify hardware & intrinsic state | 1 VBMI hosts; live flag checks via jcmd | done |
| 3 | Scan source, AST & compiled JARs | 4 call sites, 4 classes in 2 artifacts | done for payments-api; 4 repos pending |
| 4 | Trace input provenance & touchpoints | 2 untrusted, 1 internal, 1 constant, 1 pre-auth | done for payments-api |
| 5 | Apply immediate mitigation | 1 JVMs on flag; 1 repos on flag | in progress (1 of 2 exposed JVMs) |
| 6 | Verify safely & monitor side effects | crashes 3 triaged; edge tokens 5 analysed | in progress |
| 7 | Patch JDK & enforce CI gates | 2 JVMs patched; gate in 3/6 repos; gate FAILED | not started |

## 5. By business unit / team

| Unit | Services | Exposed | Mitigated | Patched | Owner | Due | Status |
| :--- | ---: | ---: | ---: | ---: | :--- | :--- | :--- |
| Payments | 3 | 1 | 1 | 1 | J. Rivera | 2026-11-24 | RED |
| Identity | 1 | 0 | 0 | 0 | P. Okafor | 2026-12-01 | RED (re-enabled flag, EOL JDK 19) |
| Finance Ops | 2 | 0 | 0 | 1 | M. Chen | 2026-12-17 | AMBER |

## 6. Open actions

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

## 7. Blockers and escalations

| Blocker | Impact | Owner | Needed |
| :--- | :--- | :--- | :--- |
| legacy-sso owner team disbanded | no one can change the Kubernetes manifest that re-enables the intrinsic | CTO office | named owner by 2026-11-25 |
| report-renderer gate failing on floating tag | releases blocked until the tag is pinned | Finance Ops platform | pin eclipse-temurin:25.0.5.1_2-jre |

## 8. Exceptions and risk acceptances

| Service | Reason | Compensating control | Approver | Expires |
| :--- | :--- | :--- | :--- | :--- |
| batch-recon (batch-02) | runs on a CPU without AVX-512 VBMI; nightly job, internal input only | host pinned to non-VBMI node pool; patch scheduled 2026-12-10 | CISO | 2026-12-17 |

## 9. Side effects being tracked

| Effect (docs/side-efforts) | Watch | Current reading |
| :--- | :--- | :--- |
| 04 CPU/latency from the flag | p99 latency, CPU on Base64-heavy endpoints | +6% p99 on auth-gateway /token after flag (staging 24h); CPU +3% |
| 06 Edge rule false positives | blocked legitimate auth / API calls (count mode) | count mode: 3 suspicious hits, 0 false positives in 48h |
| 07 JAVA_TOOL_OPTIONS propagation | unintended JVMs picking up the flag (build agents, CLIs) | metrics-agent on web-01 also picked up JAVA_TOOL_OPTIONS (harmless) |
| 08 Upgrade regressions / EOL migrations | failed canaries, services on 18–20/22–24/26 | notifications upgraded to 21.0.13.1 without regression; legacy-sso has no patch |
| 10 Gate blocking releases on false positives | gate failures reclassified as noise | 1 false positive reclassified (Helm values flag not seen by Dockerfile check) |

_Evidence files: audit=["/Users/rcmarte/.copilot/repos/runbook_remediation_verification_cve_2026_114938_java4shell/report-template/examples/data/audit-web-01.json", "/Users/rcmarte/.copilot/repos/runbook_remediation_verification_cve_2026_114938_java4shell/report-template/examples/data/audit-batch-02.json"]; audit_before=["/Users/rcmarte/.copilot/repos/runbook_remediation_verification_cve_2026_114938_java4shell/report-template/examples/data/before/audit-web-01.json"]; gh_scan=/Users/rcmarte/.copilot/repos/runbook_remediation_verification_cve_2026_114938_java4shell/report-template/examples/data/estate.json; actions=/Users/rcmarte/.copilot/repos/runbook_remediation_verification_cve_2026_114938_java4shell/report-template/examples/data/posture.tsv; source=/Users/rcmarte/.copilot/repos/runbook_remediation_verification_cve_2026_114938_java4shell/report-template/examples/data/src.json; jars=/Users/rcmarte/.copilot/repos/runbook_remediation_verification_cve_2026_114938_java4shell/report-template/examples/data/findings.jsonl; gate=/Users/rcmarte/.copilot/repos/runbook_remediation_verification_cve_2026_114938_java4shell/report-template/examples/data/gate.log; crashes=/Users/rcmarte/.copilot/repos/runbook_remediation_verification_cve_2026_114938_java4shell/report-template/examples/data/crashes.json; b64=/Users/rcmarte/.copilot/repos/runbook_remediation_verification_cve_2026_114938_java4shell/report-template/examples/data/traffic.json; extra=/Users/rcmarte/.copilot/repos/runbook_remediation_verification_cve_2026_114938_java4shell/report-template/examples/data/narrative.json; _
