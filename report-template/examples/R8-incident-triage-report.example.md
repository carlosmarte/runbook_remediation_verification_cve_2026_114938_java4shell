# CVE-2026-114938 (Java4Shell) — Incident Triage Report INC-2026-1142

| | |
| :--- | :--- |
| **Incident** | INC-2026-1142 · severity SEV-1 · opened 2026-11-23 22:14 UTC |
| **Commander / reporter** | SOC lead on duty / Platform Security |
| **Status** | **RED** · containment |
| **Affected** | web-01 / payments-api (2 crashes), edge api.acme.example |

## 1. Assessment

3 crash file(s) triaged: **1 LIKELY**, 1 POSSIBLE, 1 UNLIKELY. 2 flagged crash(es) came from JVMs without the mitigation.
5 Base64 token(s) analysed from logs/headers: **3 suspicious** (J4S-EDGE-01 excess padding: 1, EDGE-02 padding inside body: 1, EDGE-03 long run + single pad: 1); 1 JWT-like.

Read as: a `LIKELY` crash (SIGSEGV/SIGBUS in a Base64 stub frame, heap-corruption markers, vulnerable JRE, no flag, VBMI CPU) on a host that also received malformed-padding tokens is an **exploitation attempt**; whether it succeeded cannot be decided from the crash alone (side effects 01–02: DoS and "JavaBleed" heap disclosure).

## 2. Crash files

| File | Verdict | Score | Signal | Frame | JRE | Version status | Flag | Re-enabled | VBMI | Reasons |
| :--- | :--- | ---: | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `/var/log/payments-api/hs_err_pid1702.log` | **LIKELY** | 8 | SIGSEGV (0xb) | `v  ~StubRoutines::base64_decode` | 21.0.12+7 | VULN_RANGE | no | no | yes | SIGSEGV in Base64 decode stub frame, heap corruption markers present, JRE 21.0.12 in vulnerable range, no mitigation flag in jvm_args, CPU exposes avx512_vbmi |
| `/var/log/payments-api/hs_err_pid1655.log` | **POSSIBLE** | 4 | SIGSEGV (0xb) | `J 4821 c2 com.acme.pay.webhook.SignatureVerifier.verify` | 21.0.12+7 | VULN_RANGE | no | no | yes | Base64 decoder in stack, JRE in vulnerable range, no mitigation flag, no heap corruption marker |

## 3. Suspicious tokens (sample, first 3)

| Log line | Token (truncated) | Length | Pads | Edge rules | Anomalies | JWT-like |
| :--- | :--- | ---: | ---: | :--- | :--- | :--- |
| 48213 | `QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIz…` | 76 | 4 | J4S-EDGE-01 | excess_padding | no |
| 48214 | `QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIz…` | 75 | 1 | J4S-EDGE-02 | padding_inside_body | no |
| 48219 | `QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIz…` | 89 | 1 | J4S-EDGE-03 | length_not_multiple_of_4 | no |

## 4. State of the affected hosts

| Host | VBMI | PID | JDK | Version status | Flag | Verdict |
| :--- | :--- | ---: | :--- | :--- | :--- | :--- |
| web-01.prod.acme.example | yes | 1842 | 21.0.12 | VULN_RANGE | MISSING_FLAG | **EXPOSED_ON_VBMI_HOST** |
| batch-02.prod.acme.example | no | 912 | 17.0.9 | VULN_RANGE | MISSING_FLAG | **UNVERIFIED_ON_HOST** |
| web-01.prod.acme.example | yes | 2210 | 21.0.12 | VULN_RANGE | MITIGATED_FLAG | **MITIGATED_BY_FLAG** |
| batch-02.prod.acme.example | no | 1401 | 25.0.5.1 | PATCHED_OR_UNAFFECTED | MITIGATED_FLAG | **PATCHED_OR_SAFE_VERSION** |
| web-01.prod.acme.example | yes | 3105 | 21.0.13.1 | PATCHED_OR_UNAFFECTED | MISSING_FLAG | **PATCHED_OR_SAFE_VERSION** |

## 5. Timeline

| Time (UTC) | Event | Source |
| :--- | :--- | :--- |
| 2026-11-23 21:58 | 3 requests with malformed Base64 Authorization headers from one IP | nginx access log lines 48213-48219 |
| 2026-11-23 22:01 | payments-api PID 1702 crashes, SIGSEGV in base64_decode stub | hs_err_pid1702.log |
| 2026-11-23 22:03 | container restarted by kubelet; second crash 22:09 (PID 1655) | kube events, hs_err_pid1655.log |
| 2026-11-23 22:14 | SOC opens INC-2026-1142; flag applied to payments-api 22:40 | incident channel |

## 6. Containment and eradication

| Step | Status | Owner |
| :--- | :--- | :--- |
| Apply `-XX:-UseBASE64Intrinsics` to every JVM on the affected hosts and restart | done 2026-11-23 22:40 | |
| Switch edge rules J4S-EDGE-01/02 from count to block on the affected routes | EDGE-01/02 blocking on /authorize since 23:05 | |
| Preserve `hs_err_pid*.log`, heap dumps, GC logs, access logs (chain of custody) | done (S3 forensics bucket) | |
| Rotate secrets resident in the crashed JVMs' heaps (tokens, keys, DB credentials) — JavaBleed assumption | in progress (JWT signing key rotated; DB creds pending) | |
| Hunt for the same token shapes across the fleet (`helpers/j4s_b64check.py scan` on all edge logs for the window) | in progress | |
| Upgrade the affected services to 17.0.21.0.3+ / 21.0.13.1+ / 25.0.5.1+ / 27.0.1.1+ | scheduled 2026-11-25 | |

## 7. Indicators

- Source IP 203.0.113.57 (RFC 5737 documentation range, placeholder)
- Authorization: Basic <76-char token ending ====>
- hs_err problematic frame StubRoutines::base64_decode

## 8. Decisions and actions

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

_Escalate to R0 if any crash is LIKELY on an internet-facing service. Close via R9 attestation once the hosts are PATCHED and secrets rotated._
