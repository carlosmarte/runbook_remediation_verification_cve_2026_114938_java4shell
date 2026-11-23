# CVE-2026-114938 (Java4Shell) — Engineering Portfolio

Acme Corp (fictional example) · Payments, Identity and Finance Ops production · 2026-11-24 · status **RED**

## 1. Portfolio in one table

| Verdict | Repos | Meaning | What the team must do |
| :--- | ---: | :--- | :--- |
| `EXPOSED` | 1 | Runtime pins a vulnerable JDK, no flag | Flag today, upgrade this sprint |
| `EXPLICITLY_ENABLED` | 1 | `-XX:+UseBASE64Intrinsics` present | Remove the flag today |
| `MITIGATED_FLAG` | 1 | Flag present, JDK still vulnerable | Upgrade within SLA (2026-12-17) |
| `UNVERIFIED_FLOATING` | 1 | Floating tag (`:21-jre`, distro package) | Rebuild after the fix, pin exact tag or digest |
| `UNVERIFIED_NO_PIN` | 1 | Runtime defined outside the repo | Name the platform/host; audit it |
| `PATCHED` | 1 | Baseline met | Remove flag when fleet is patched |

Java repositories: **6** (of 7 scanned). Release gate adopted by 50%. Pre-auth Base64 decoding found in 2 repositories.

## 2. Work queue, worst first

| # | Repository | Verdict | Runtime JDK pins | Flag | Gate | Pre-auth decode | Owner / team | Tier | Due |
| ---: | :--- | :--- | :--- | :--- | :--- | ---: | :--- | :--- | :--- |
| 1 | [acme/payments-api](https://github.com/acme/payments-api) | `EXPOSED` | 21.0.12 (VULN_RANGE) | MISSING | no | 1 | unassigned | - | - |
| 2 | [acme/legacy-sso](https://github.com/acme/legacy-sso) | `EXPLICITLY_ENABLED` | 19-jdk (VULN_RANGE) | EXPLICITLY_ENABLED | no | 1 | unassigned | - | - |
| 3 | [acme/auth-gateway](https://github.com/acme/auth-gateway) | `MITIGATED_FLAG` | 21.0.5 (VULN_RANGE) | ACTIVE | yes | 0 | unassigned | - | - |
| 4 | [acme/report-renderer](https://github.com/acme/report-renderer) | `UNVERIFIED_FLOATING` | 25-jre (FLOATING_PATCHABLE) | MISSING | yes | 0 | unassigned | - | - |
| 5 | [acme/batch-recon](https://github.com/acme/batch-recon) | `UNVERIFIED_NO_PIN` | - | MISSING | no | 0 | unassigned | - | - |
| 6 | [acme/notifications](https://github.com/acme/notifications) | `PATCHED` | 21.0.13.1 (PATCHED_OR_UNAFFECTED) | MISSING | yes | 0 | unassigned | - | - |

## 3. Capacity and sequencing

| Workstream | Items | Effort guide | Sequence |
| :--- | ---: | :--- | :--- |
| Flag rollout (`JAVA_TOOL_OPTIONS`, manifests, Helm values) | 1 repos + 1 running JVMs | hours per service; canary first on Base64-heavy endpoints | 1 |
| Remove explicit re-enable | 1 | minutes | 1 |
| JDK upgrade to 17.0.21.0.3+ / 21.0.13.1+ / 25.0.5.1+ / 27.0.1.1+ | 1 + 1 repos | 0.5–2 days per service incl. regression tests | 2 |
| EOL migrations (18–20 → 21, 22–24 → 25, 26 → 27) | see pins containing 18–20/22–24/26 | days to weeks | 3 (own plan) |
| Pin floating images / packages | 1 | hours | 2 |
| Identify runtime for no-pin repos | 1 | hours (platform team) | 2 |
| Add release gate workflow | 3 | 30 min per repo (copy `.github/workflows/cve-2026-114938-gate.yml`) | 2 |
| Input validation before decode | 2 call sites | hours per site + tests | 3 |

## 4. Repositories without a release gate

- acme/payments-api
- acme/legacy-sso
- acme/batch-recon

## 5. Pipeline posture (6 repositories)

| Gate workflow present | Gate required on default branch | Last run passing / failing | Flag in Actions variables | Re-enabled via variables | Open code-scanning J4S alerts | Dependabot alerts |
| ---: | ---: | :--- | ---: | ---: | ---: | ---: |
| 3 | 2 | 2 / 1 | 1 | 1 | 2 | 0 |

## 6. Risks to delivery

- Upgrade regressions: run the service test suite on the target JDK before switching the image (`docs/side-efforts/08`).
- Performance: measure CPU and p99 on Base64-heavy endpoints before and after the flag (`docs/side-efforts/04`).
- `JAVA_TOOL_OPTIONS` is host-global: prefer per-service launch args where several JVMs share a host (`docs/side-efforts/07`).
- Gate false positives on vendor tags are documented (`patterns/J4S-VER-01.md`); the shipped gate uses the corrected parser.

## 7. Recommended actions

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
