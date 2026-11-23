# CVE-2026-114938 (Java4Shell) — Service Remediation Report: payments-api

| | |
| :--- | :--- |
| **Service / owner / tier** | payments-api / J. Rivera (Payments Engineering) / 1 (customer-facing, PCI) |
| **Runtime** | ghcr.io/acme/payments-api:2.14.0 on eclipse-temurin:21.0.12_7-jre-jammy, Kubernetes prod/payments, nodes Ice Lake |
| **Internet-facing / pre-auth surface** | yes / HTTP Basic on /authorize, webhook signature header |
| **Status** | **RED** on 2026-11-24 |
| **Target** | flag live by 2026-11-19; patched (17.0.21.0.3+ / 21.0.13.1+ / 25.0.5.1+ / 27.0.1.1+) by 2026-12-17 |

## 1. Exposure summary

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

## 2. Where it runs (runtime evidence)

| Host | Arch | VBMI | PID | Source | JDK | Version status | Flag | Verdict |
| :--- | :--- | :--- | ---: | :--- | :--- | :--- | :--- | :--- |
| web-01.prod.acme.example | - | yes | 1842 | container:payments-api | 21.0.12 | VULN_RANGE | MISSING_FLAG | **EXPOSED_ON_VBMI_HOST** |
| batch-02.prod.acme.example | - | no | 912 | host | 17.0.9 | VULN_RANGE | MISSING_FLAG | **UNVERIFIED_ON_HOST** |
| web-01.prod.acme.example | - | yes | 2210 | container:auth-gateway | 21.0.12 | VULN_RANGE | MITIGATED_FLAG | **MITIGATED_BY_FLAG** |
| batch-02.prod.acme.example | - | no | 1401 | container:report-renderer | 25.0.5.1 | PATCHED_OR_UNAFFECTED | MITIGATED_FLAG | **PATCHED_OR_SAFE_VERSION** |
| web-01.prod.acme.example | - | yes | 3105 | host | 21.0.13.1 | PATCHED_OR_UNAFFECTED | MISSING_FLAG | **PATCHED_OR_SAFE_VERSION** |

Flag confirmation must come from the live JVM, not the manifest: `jcmd <pid> VM.flags -all | grep UseBASE64Intrinsics` (pattern J4S-FLAG-09).

## 3. How it is built and deployed (repository evidence)

| Repository | Verdict | Runtime JDK pins | Flag in runtime files | Gate | Reason |
| :--- | :--- | :--- | :--- | :--- | :--- |
| [acme/payments-api](https://github.com/acme/payments-api) | `EXPOSED` | 21.0.12 (VULN_RANGE) | MISSING | no | Dockerfile:1 pins eclipse-temurin:21.0.12_7-jre-jammy -> VULN_RANGE (Below 21.0.13.1 baseline) |
| [acme/legacy-sso](https://github.com/acme/legacy-sso) | `EXPLICITLY_ENABLED` | 19-jdk (VULN_RANGE) | EXPLICITLY_ENABLED | no | deploy/k8s/deployment.yaml:22 pins openjdk:19-jdk -> VULN_RANGE (JDK 19 is an EOL line; every build is vulnerable and no patch exists) |
| [acme/auth-gateway](https://github.com/acme/auth-gateway) | `MITIGATED_FLAG` | 21.0.5 (VULN_RANGE) | ACTIVE | yes | Dockerfile:3 pins amazoncorretto:21.0.5 -> VULN_RANGE (Below 21.0.13.1 baseline) |
| [acme/report-renderer](https://github.com/acme/report-renderer) | `UNVERIFIED_FLOATING` | 25-jre (FLOATING_PATCHABLE) | MISSING | yes | Dockerfile:1 floating pin eclipse-temurin:25-jre -> verify resolved build |
| [acme/batch-recon](https://github.com/acme/batch-recon) | `UNVERIFIED_NO_PIN` | - | MISSING | no | Java workload without a runtime JDK pin in this repository (runtime defined elsewhere: platform image, host JDK, Helm values repo) |
| [acme/notifications](https://github.com/acme/notifications) | `PATCHED` | 21.0.13.1 (PATCHED_OR_UNAFFECTED) | MISSING | yes | Dockerfile:1 eclipse-temurin:21.0.13.1_2-jre-jammy -> PATCHED_OR_UNAFFECTED |

## 4. Where the code decodes Base64 (source evidence)

4 call sites in 4 files: **2 untrusted**, 1 internal, 1 constant, 0 unknown; 1 in pre-authentication context; 1 in tests.

| File:line | Call | Argument | Input kind | Pre-auth | Test | Why |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `main/java/com/acme/pay/auth/BasicAuthFilter.java:48` | `Base64.getDecoder().decode` | `authorization.substring(6)` | DYNAMIC_UNTRUSTED | yes | no | argument derives from request header Authorization (J4S-SRC-03) in a servlet filter before authentication (J4S-SRC-04) |
| `main/java/com/acme/pay/webhook/SignatureVerifier.java:77` | `Base64.getDecoder().decode` | `header` | DYNAMIC_UNTRUSTED | no | no | argument derives from request header X-Signature (J4S-SRC-03) |
| `main/java/com/acme/pay/config/KeyLoader.java:31` | `Base64.getMimeDecoder().decode` | `pem` | DYNAMIC_INTERNAL | no | no | argument read from a configured file path at start-up; operator-controlled |
| `test/java/com/acme/pay/auth/BasicAuthFilterTest.java:59` | `Base64.getDecoder().decode` | `"dXNlcjpwYXNz"` | CONSTANT | no | yes | string literal argument in test code |

## 5. Compiled artifacts and dependencies (bytecode evidence)

4 classes in 2 artifacts reference `java.util.Base64` decoding; 1 are shaded/relocated copies, 1 are test artifacts.

| Artifact | Classes | Shaded | Test |
| :--- | ---: | ---: | :--- |
| `payments-api/build/libs/payments-api-2.14.0.jar` | 3 | 1 | no |
| `payments-api/build/libs/payments-api-2.14.0-tests.jar` | 1 | 0 | yes |

## 6. Release gate

Gate result: **FAILED** (4 violation(s)).
- [Dockerfile:payments-api/Dockerfile] JDK 21.0.12 (< 21.0.13.1) is unpatched
- [Dockerfile:payments-api/Dockerfile] Missing -XX:-UseBASE64Intrinsics (or -XX:UseAVX=0..2) in ENV/ENTRYPOINT/CMD
- [Manifest:payments-api/deploy/k8s/deployment.yaml] JVM workload missing -XX:-UseBASE64Intrinsics (e.g., via JAVA_TOOL_OPTIONS or container args)
- [Reachability:reachability-findings.json] J4S-0001 is REACHABLE_HIGH in com.acme.pay.auth.BasicAuthFilter.doFilter (payments-api/build/libs/payments-api-2.14.0.jar)

## 7. Remediation checklist

| # | Step | Command / change | Done | Evidence |
| ---: | :--- | :--- | :--- | :--- |
| 1 | Add the flag to the runtime | `ENV JAVA_TOOL_OPTIONS="-XX:-UseBASE64Intrinsics"` (Dockerfile) · `env: JAVA_TOOL_OPTIONS` (manifest) · `helpers/j4s_flag.sh snippet k8s-patch` | ☐ | |
| 2 | Verify live | `helpers/j4s_proc.sh flags <pid>` or `helpers/j4s_k8s.sh missing -n <ns>` → `ACTIVE` | ☐ | |
| 3 | Benchmark | p99 and CPU on Base64-heavy endpoints before/after (side effect 04) | ☐ | |
| 4 | Validate input before decode | reject length % 4 ≠ 0, `={3,}`, `=` inside the body (`helpers/j4s_b64check.py` `is_strictly_valid`) at each untrusted site | ☐ | |
| 5 | Upgrade the JDK | pin `17.0.21.0.3+ / 21.0.13.1+ / 25.0.5.1+ / 27.0.1.1+` or vendor equivalent; run the test suite on the new JDK | ☐ | |
| 6 | Pin and gate | exact tag or digest; add `.github/workflows/cve-2026-114938-gate.yml`; make it a required check | ☐ | |
| 7 | Re-audit | rerun `audit_java4shell.py` and `gh_j4s_scan.py`; attach JSON; verdict `PATCHED` | ☐ | |
| 8 | Remove the flag (optional, after fleet is patched) | revert step 1; re-benchmark | ☐ | |

## 8. Actions assigned

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

_Related: R4 developer findings for this repo, R6 runtime verification for its hosts, R8 if any crash or probe was seen._
