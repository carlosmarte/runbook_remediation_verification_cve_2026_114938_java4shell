# CVE-2026-114938 (Java4Shell) — GitHub Estate Scan

Acme Corp (fictional example) · scope `org:acme` · scanned 2026-11-24T08:12:44 · report 2026-11-24 · status **RED**

## 1. Verdict distribution

| Verdict | Repos | Share of Java repos |
| :--- | ---: | ---: |
| `EXPOSED` | 1 | |
| `EXPLICITLY_ENABLED` | 1 | |
| `MITIGATED_FLAG` | 1 | |
| `UNVERIFIED_FLOATING` | 1 | 16.7% |
| `UNVERIFIED_NO_PIN` | 1 | |
| `PATCHED` | 1 | |
| `NOT_JAVA` | 1 | — |
| `ERROR` | 0 | — |

**6 Java repositories** of 7 scanned · blocking (EXPOSED + EXPLICITLY_ENABLED) **2** (33.3%) · unverified 33.3% · gate adoption 50% · Base64 decode sites found 3 (2 pre-auth) in 2 repos.

## 2. Insights

- **Exposure is declared, not guessed.** `EXPOSED` means a runtime file (Dockerfile, manifest, service unit) pins a JDK in the vulnerable range and no runtime file sets the flag. Developer pins (`.sdkmanrc`), CI pins (`setup-java`) and docs do not count.
- **Floating tags are the largest unknown.** 1 repositories use `:21-jre`-style tags or distro packages; whether they are patched depends on the build date, so each needs an exact version from the image (`docker run IMAGE java -version`) or a digest pin.
- **Runtime defined elsewhere.** 1 Java repositories carry no runtime pin at all; their JDK is set by a platform image, Helm values repo or host. Those owners must be named.
- **Gate coverage.** 3 Java repositories have no workflow referencing the gate; a flag added today can be removed by the next PR unnoticed.

## 3. Blocking repositories (fix now)

| Repository | Verdict | Runtime JDK pins | Flag | Gate | Pre-auth decode | Reason |
| :--- | :--- | :--- | :--- | :--- | ---: | :--- |
| [acme/payments-api](https://github.com/acme/payments-api) | `EXPOSED` | 21.0.12 (VULN_RANGE) | MISSING | no | 1 | Dockerfile:1 pins eclipse-temurin:21.0.12_7-jre-jammy -> VULN_RANGE (Below 21.0.13.1 baseline) |
| [acme/legacy-sso](https://github.com/acme/legacy-sso) | `EXPLICITLY_ENABLED` | 19-jdk (VULN_RANGE) | EXPLICITLY_ENABLED | no | 1 | deploy/k8s/deployment.yaml:22 pins openjdk:19-jdk -> VULN_RANGE (JDK 19 is an EOL line; every build is vulnerable and no patch exists) |

## 4. Mitigated by flag (upgrade pending)

| Repository | Runtime JDK pins | Flag | Gate |
| :--- | :--- | :--- | :--- |
| [acme/auth-gateway](https://github.com/acme/auth-gateway) | 21.0.5 (VULN_RANGE) | ACTIVE | yes |

## 5. Unverified repositories

| Repository | Verdict | Pins seen | Language | Last push | Reason |
| :--- | :--- | :--- | :--- | :--- | :--- |
| [acme/report-renderer](https://github.com/acme/report-renderer) | `UNVERIFIED_FLOATING` | 25-jre (FLOATING_PATCHABLE) | Java | 2026-11-20 | Dockerfile:1 floating pin eclipse-temurin:25-jre -> verify resolved build |
| [acme/batch-recon](https://github.com/acme/batch-recon) | `UNVERIFIED_NO_PIN` | - | Java | 2026-10-11 | Java workload without a runtime JDK pin in this repository (runtime defined elsewhere: platform image, host JDK, Helm values repo) |

## 6. Full table

| Repository | Verdict | Runtime JDK pins | Flag | Gate | Decode sites | Pre-auth |
| :--- | :--- | :--- | :--- | :--- | ---: | ---: |
| [acme/payments-api](https://github.com/acme/payments-api) | `EXPOSED` | 21.0.12 (VULN_RANGE) | MISSING | no | 2 | 1 |
| [acme/legacy-sso](https://github.com/acme/legacy-sso) | `EXPLICITLY_ENABLED` | 19-jdk (VULN_RANGE) | EXPLICITLY_ENABLED | no | 1 | 1 |
| [acme/auth-gateway](https://github.com/acme/auth-gateway) | `MITIGATED_FLAG` | 21.0.5 (VULN_RANGE) | ACTIVE | yes | 0 | 0 |
| [acme/report-renderer](https://github.com/acme/report-renderer) | `UNVERIFIED_FLOATING` | 25-jre (FLOATING_PATCHABLE) | MISSING | yes | 0 | 0 |
| [acme/batch-recon](https://github.com/acme/batch-recon) | `UNVERIFIED_NO_PIN` | - | MISSING | no | 0 | 0 |
| [acme/notifications](https://github.com/acme/notifications) | `PATCHED` | 21.0.13.1 (PATCHED_OR_UNAFFECTED) | MISSING | yes | 0 | 0 |

## 7. Pipeline posture

| Repos | Gate workflow | Gate required | Passing / failing | Flag via Actions vars | Re-enabled via vars | J4S code-scanning alerts | Dependabot |
| ---: | ---: | ---: | :--- | ---: | ---: | ---: | ---: |
| 6 | 3 | 2 | 2 / 1 | 1 | 1 | 2 | 0 |

## 8. Code-search sweep

| Pattern set | Hits | Repositories | Severity ≥ MITIGATE |
| :--- | ---: | ---: | ---: |
| decoder | 23 | 5 | 2 |
| flags | 6 | 4 | 1 |
| images | 7 | 6 | 3 |
| oracle8 | 0 | 0 | 0 |

## 9. Method and limits

Default branch only; files read: Dockerfiles, compose/Kubernetes/Helm/Actions YAML, `.sdkmanrc`/`.java-version`/`.tool-versions`, `pom.xml`/Gradle, service units, start scripts, Terraform (cap 80 files per repo). Versions compared with the five-component rule against 17.0.21.0.3+ / 21.0.13.1+ / 25.0.5.1+ / 27.0.1.1+; floating tags are not resolved. Source hits use single-line patterns (J4S-SRC-01/04); for provenance run `scripts/scan_java4shell_source.py` on a checkout. See `github/README.md`.

## 10. Actions

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
