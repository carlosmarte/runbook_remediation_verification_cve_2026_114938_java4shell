# CVE-2026-114938 (Java4Shell) — Remediation Attestation

| | |
| :--- | :--- |
| **Organisation / scope** | Acme Corp (fictional example) — Payments, Identity and Finance Ops production |
| **Attestation date** | 2026-11-24 · report J4S-20261124 |
| **Vulnerability** | CVE-2026-114938 (Java4Shell, upstream JDK-8393212), CWE-122 / CWE-787, CVSS 3.1 8.1 High / CVSS 4.0 9.2 Critical, disclosed 2026-11-17 |
| **Affected products** | OpenJDK HotSpot and downstream builds on x86-64 with AVX-512 VBMI: JDK 17.0.6–17.0.21.0.2, 21 < 21.0.13.1, 25 < 25.0.5.1, 27 < 27.0.1.1, EOL 18–20/22–24/26, Oracle 8u511b33-perf |
| **Current status** | **RED** |
| **Classification** | Internal / Confidential |

## 1. Statement

Acme Corp (fictional example) attests that, within the scope above, remediation of CVE-2026-114938 is **in progress** with status RED: 1 JVM(s) exposed on AVX-512 VBMI hosts without patch or flag; 2 repositor(ies) deploy a vulnerable JDK without the mitigation flag or re-enable the intrinsic; 1 crash file(s) triaged LIKELY Java4Shell; 1 repositor(ies) re-enable the intrinsic through Actions variables; 1 unverified and 1 flag-mitigated JVM(s) still on vulnerable versions; 2 repositor(ies) unverified, 1 mitigated by flag only; 2 production call site(s) decode untrusted Base64; CI gate failing with 4 violation(s); 1 crash file(s) triaged POSSIBLE; 3 suspicious malformed-Base64 token(s) in traffic; The compensating control `-XX:-UseBASE64Intrinsics` is applied as stated in section 3 and the remaining items carry the exceptions and dates in section 5.

## 2. Scope and coverage

| Population | Identified | Verified | Method |
| :--- | ---: | ---: | :--- |
| Hosts (physical/VM) | 2 | 2 | `scripts/audit_java4shell.py` per host (process maps, `java -version`, cmdline/env flags, live `jcmd`) |
| JVM processes | 5 | 5 | same |
| Container images / Kubernetes workloads | 4 images in ghcr.io/acme, 3 verified by digest | | `scripts/verify_java4shell_runtime.sh --k8s`, `helpers/j4s_k8s.sh` |
| Source repositories (Java) | 6 | 6 | `github/gh_j4s_scan.py` (default branch, runtime definitions, CI gate) |
| Source call sites decoding Base64 | 4 | 4 | `scripts/scan_java4shell_source.py` (provenance classification) |
| Compiled artifacts | 2 | 2 | `scripts/scan_java4shell_jars.py` (constant-pool references, shaded copies) |

## 3. Results

| Control | Result |
| :--- | :--- |
| JVMs exposed (vulnerable, unmitigated, VBMI hardware) | **1** |
| JVMs mitigated by `-XX:-UseBASE64Intrinsics` (upgrade pending) | 1 |
| JVMs patched or unaffected | 2 (40%) |
| JVMs on vulnerable builds on non-VBMI hardware | 1 |
| Repositories deploying a vulnerable JDK unmitigated | **2** |
| Repositories mitigated / unverified / patched | 1 / 1+1 / 1 |
| Release gate enforced | 3 of 6 Java repositories; last gate run: FAILED |
| Untrusted Base64 decode sites in production code | 2 (validation added: payments-api PR #1187 (merged 2026-11-24)) |
| Exploitation indicators | crashes LIKELY 1 / POSSIBLE 1; suspicious edge tokens 3 |

## 4. Evidence register

| # | Evidence | Produced by | Location / hash | Date |
| ---: | :--- | :--- | :--- | :--- |
| 1 | Host audits web-01, batch-02 | scripts/audit_java4shell.py | s3://acme-sec-evidence/j4s/audits/ (sha256 in manifest) | 2026-11-24 |
| 2 | GitHub estate scan org:acme | github/gh_j4s_scan.py | s3://acme-sec-evidence/j4s/estate.json | 2026-11-24 |
| 3 | Incident INC-2026-1142 record | SOC case system | case INC-2026-1142 | 2026-11-23 |
| | audit | scanner output | ["/Users/rcmarte/.copilot/repos/runbook_remediation_verification_cve_2026_114938_java4shell/report-template/examples/data/audit-web-01.json", "/Users/rcmarte/.copilot/repos/runbook_remediation_verification_cve_2026_114938_java4shell/report-template/examples/data/audit-batch-02.json"] | 2026-11-24 |
| | audit_before | scanner output | ["/Users/rcmarte/.copilot/repos/runbook_remediation_verification_cve_2026_114938_java4shell/report-template/examples/data/before/audit-web-01.json"] | 2026-11-24 |
| | gh_scan | scanner output | /Users/rcmarte/.copilot/repos/runbook_remediation_verification_cve_2026_114938_java4shell/report-template/examples/data/estate.json | 2026-11-24 |
| | actions | scanner output | /Users/rcmarte/.copilot/repos/runbook_remediation_verification_cve_2026_114938_java4shell/report-template/examples/data/posture.tsv | 2026-11-24 |
| | source | scanner output | /Users/rcmarte/.copilot/repos/runbook_remediation_verification_cve_2026_114938_java4shell/report-template/examples/data/src.json | 2026-11-24 |
| | jars | scanner output | /Users/rcmarte/.copilot/repos/runbook_remediation_verification_cve_2026_114938_java4shell/report-template/examples/data/findings.jsonl | 2026-11-24 |
| | gate | scanner output | /Users/rcmarte/.copilot/repos/runbook_remediation_verification_cve_2026_114938_java4shell/report-template/examples/data/gate.log | 2026-11-24 |
| | crashes | scanner output | /Users/rcmarte/.copilot/repos/runbook_remediation_verification_cve_2026_114938_java4shell/report-template/examples/data/crashes.json | 2026-11-24 |
| | b64 | scanner output | /Users/rcmarte/.copilot/repos/runbook_remediation_verification_cve_2026_114938_java4shell/report-template/examples/data/traffic.json | 2026-11-24 |
| | extra | scanner output | /Users/rcmarte/.copilot/repos/runbook_remediation_verification_cve_2026_114938_java4shell/report-template/examples/data/narrative.json | 2026-11-24 |

## 5. Exceptions and risk acceptances

| Asset | Reason | Compensating control | Risk owner | Approved | Expires |
| :--- | :--- | :--- | :--- | :--- | :--- |
| batch-recon (batch-02) | runs on a CPU without AVX-512 VBMI; nightly job, internal input only | host pinned to non-VBMI node pool; patch scheduled 2026-12-10 | CISO | 2026-11-23 | 2026-12-17 |

## 6. Controls mapping

| Framework | Control | How this remediation satisfies it |
| :--- | :--- | :--- |
| ISO 27001:2022 | A.8.8 Management of technical vulnerabilities | inventory (§2), risk-based remediation with SLA 2/30 days, verification (§3) |
| NIST SP 800-53 | RA-5, SI-2, CM-6 | scanning, flaw remediation, configuration (`JAVA_TOOL_OPTIONS`) enforced by CI gate |
| SOC 2 | CC7.1, CC7.2 | detection of vulnerable components; monitoring for exploitation (crash triage, edge rules) |
| PCI DSS 4.0 | 6.3.1, 6.3.3, 11.3 | critical patch within policy window or documented compensating control |
| CIS Controls v8 | 7.4, 7.7, 16.13 | automated remediation process, remediation of detected vulnerabilities, application-level input validation |

## 7. Sign-off

| Role | Name | Date | Signature |
| :--- | :--- | :--- | :--- |
| CISO / risk owner | A. Novak |  | |
| Head of platform engineering | D. Sato |  | |
| Internal audit (witness) | L. Haddad |  | |

_This attestation reflects the evidence listed in section 4 as of 2026-11-24. It will be re-issued if new Java runtimes enter scope or hardware changes bring non-VBMI hosts into the affected class._
