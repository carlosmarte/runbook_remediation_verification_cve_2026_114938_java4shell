# CVE-2026-114938 (Java4Shell) — Runtime Verification Report

Acme Corp (fictional example) · Payments, Identity and Finance Ops production · 2026-11-24 · status **RED**

## 1. Fleet summary

| Measure | Value |
| :--- | ---: |
| Hosts audited | 2 |
| Hosts with AVX-512 VBMI (in hardware scope) | 1 (50%) |
| JVM processes | 5 (on VBMI hosts: 3) |
| **EXPOSED_ON_VBMI_HOST** | **1** |
| UNVERIFIED_ON_HOST (vulnerable version, no flag, non-VBMI CPU) | 1 |
| MITIGATED_BY_FLAG | 1 |
| PATCHED_OR_SAFE_VERSION | 2 |
| JVMs with a vulnerable version (any CPU) | 3 |
| JVMs without the flag on the command line / env | 3 |
| Exposure rate / mitigation coverage / patch coverage | 20% / 60% / 40% |

### Exposure matrix

| | Vulnerable version, no flag | Vulnerable version, flag active | Patched / unaffected |
| :--- | :--- | :--- | :--- |
| **VBMI host** | EXPOSED_ON_VBMI_HOST — fix now | MITIGATED_BY_FLAG — upgrade | safe |
| **non-VBMI host** | UNVERIFIED_ON_HOST — patch before hardware moves | MITIGATED_BY_FLAG | safe |

## 2. Hosts

| Host | Arch | VBMI | JVMs | Exposed | Unverified | Mitigated | Patched | Containers | Status |
| :--- | :--- | :--- | ---: | ---: | ---: | ---: | ---: | ---: | :--- |
| web-01.prod.acme.example | x86_64 | yes | 3 | 1 | 0 | 1 | 1 | 2 | **RED** |
| batch-02.prod.acme.example | x86_64 | no | 2 | 0 | 1 | 0 | 1 | 1 | **AMBER** |

## 3. Exposed JVMs (act today)

| Host | PID | Source | JDK | Flag | Command |
| :--- | ---: | :--- | :--- | :--- | :--- |
| web-01.prod.acme.example | 1842 | container:payments-api | 21.0.12 | MISSING_FLAG | `java -Xmx2g -jar /app/payments-api.jar` |

Per process: `helpers/j4s_proc.sh flags <pid>` shows command-line vs live state; apply with `JAVA_TOOL_OPTIONS=-XX:-UseBASE64Intrinsics` (or launch args) and restart; confirm with `jcmd <pid> VM.flags -all | grep UseBASE64Intrinsics`.

## 4. All JVM processes

| Host | PID | Source | JDK | Version status | Flag (cmdline/env) | Verdict | Command |
| :--- | ---: | :--- | :--- | :--- | :--- | :--- | :--- |
| web-01.prod.acme.example | 1842 | container:payments-api | 21.0.12 | VULN_RANGE | MISSING_FLAG | EXPOSED_ON_VBMI_HOST | `java -Xmx2g -jar /app/payments-api.jar` |
| batch-02.prod.acme.example | 912 | host | 17.0.9 | VULN_RANGE | MISSING_FLAG | UNVERIFIED_ON_HOST | `java -Xmx8g -cp /opt/batch/lib/* com.acme.batch.NightlyReconciliation` |
| web-01.prod.acme.example | 2210 | container:auth-gateway | 21.0.12 | VULN_RANGE | MITIGATED_FLAG | MITIGATED_BY_FLAG | `java -XX:-UseBASE64Intrinsics -Xmx1g -jar /app/auth-gateway.jar` |
| batch-02.prod.acme.example | 1401 | container:report-renderer | 25.0.5.1 | PATCHED_OR_UNAFFECTED | MITIGATED_FLAG | PATCHED_OR_SAFE_VERSION | `java -XX:-UseBASE64Intrinsics -jar /app/report-renderer.jar` |
| web-01.prod.acme.example | 3105 | host | 21.0.13.1 | PATCHED_OR_UNAFFECTED | MISSING_FLAG | PATCHED_OR_SAFE_VERSION | `/usr/lib/jvm/temurin-21-jdk/bin/java -jar /opt/agent/metrics-agent.jar` |

## 5. Before / after

| | Before | After |
| :--- | ---: | ---: |
| Exposed JVMs | 3 | 1 |
| Mitigation coverage | 0% | 60% |
| Patch coverage | 0% | 40% |

Improved 1 · **Regressed 0** · New 3 · Gone 1 · Unchanged 1

## 6. Kubernetes (read-only inventory, `helpers/j4s_k8s.sh`)

| Namespace / workload | Container | Image | Image version status | Flag in spec | Node arch |
| :--- | :--- | :--- | :--- | :--- | :--- |
| prod/payments/payments-api | app | `ghcr.io/acme/payments-api:2.14.0` | VULN_RANGE (base 21.0.12) | PRESENT since 2026-11-23 | amd64 (Ice Lake) |
| prod/identity/legacy-sso | sso | `openjdk:19-jdk` | VULN_RANGE (EOL 19) | EXPLICITLY_ENABLED | amd64 (Sapphire Rapids) |

## 7. Verification method and limits

- JVMs are found by `libjvm.so` in `/proc/<pid>/maps` (J4S-RT-01); versions from `$JAVA_HOME/release` or `java -version` (J4S-VER-03); flags from cmdline/env (J4S-FLAG-02/03) and live `jcmd` (J4S-FLAG-09).
- `jcmd` attaches to the JVM (safepoint pause, milliseconds) and must run as the process owner or root; `jcmd-unavailable-or-restricted` means the live state is unknown, not safe (`docs/side-efforts/09`).
- A `MITIGATED_BY_FLAG` verdict from the command line is confirmed only when the live flag reads `-UseBASE64Intrinsics`.
- Non-x86-64 hosts (ARM64, Graviton, Apple Silicon) are out of hardware scope but still carry vulnerable binaries; they are reported as UNVERIFIED so a hardware migration cannot silently expose them.

## 8. Actions

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

