# 00 — Overview, Scope and Shared Vocabulary

## 1. Purpose

The toolkit takes an organisation from "CVE-2026-114938 disclosed" to "every Java runtime patched, every pipeline
gated, every compensating control retired", and lets it prove each step with machine-produced evidence. It does
this with self-contained scripts and documents that implement the runbook's checks against hosts, containers,
Kubernetes clusters, GitHub repositories, Java source, compiled artifacts, CI manifests, crash logs and edge
traffic, and that turn the results into reports for every organisational level.

## 2. Vulnerability facts (normative constants)

Every component that prints, compares or reasons about the vulnerability MUST use these values. They originate in
runbook §1 and are repeated in `report-template/tools/j4s_facts.py` (`meta` block) and `planning/README.md`.

| Constant | Value |
| :--- | :--- |
| CVE | `CVE-2026-114938` |
| Alias | `Java4Shell`; heap-disclosure variant referred to as `JavaBleed` |
| Upstream ID | `JDK-8393212` |
| Weakness classes | `CWE-122`, `CWE-787` |
| Severity | CVSS 3.1 8.1 High (`AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H`); CVSS 4.0 9.2 Critical |
| Disclosure date (T0) | 2026-11-17 |
| Root cause | Length underflow in the x86-64 AVX-512 VBMI tail/padding path of HotSpot's `java.util.Base64` decoding intrinsic on malformed trailing `=` padding, producing an oversized write mask and an out-of-bounds heap write before validation |
| Affected runtimes | OpenJDK HotSpot and downstream builds (Temurin, Corretto, Zulu, Liberica, SapMachine, Red Hat OpenJDK, Oracle Java SE, GraalVM) |
| Vulnerable version ranges | 17.0.6 ≤ v < 17.0.21.0.3; 21 < 21.0.13.1; 25 < 25.0.5.1; 27 < 27.0.1.1; every build of EOL lines 18, 19, 20, 22, 23, 24, 26; Oracle `8u511b33-perf` |
| Unaffected | Any version with major ≤ 16 except Oracle `8u511b33-perf`; 17.0.x with patch < 6 |
| Patched baselines | `17.0.21.0.3`, `21.0.13.1`, `25.0.5.1`, `27.0.1.1` (or vendor equivalent) |
| Hardware scope | x86-64 CPUs exposing `avx512_vbmi` (Intel Ice Lake and newer server parts, AMD Zen 4 and newer). ARM64 and x86-64 without VBMI are not exploitable but still carry the code |
| Primary mitigation | JVM flag `-XX:-UseBASE64Intrinsics` |
| Alternative mitigation | `-XX:UseAVX=0`, `1` or `2` (disables AVX-512 for the whole JVM; broad cost) |
| Anti-pattern | `-XX:+UseBASE64Intrinsics` (explicit re-enable) |
| Delivery variables | `JAVA_TOOL_OPTIONS`, `JDK_JAVA_OPTIONS`, `_JAVA_OPTIONS` (also `JAVA_OPTS` for Actions variables) |
| Default SLAs | mitigation within 2 days of T0, patch within 30 days of T0; overridable |
| Consequences | pre-auth RCE; JVM crash (DoS); adjacent-heap disclosure (JavaBleed) |

## 3. System boundary

### 3.1 In scope

- Read-only detection of exposure on Linux hosts, Docker containers and Kubernetes workloads.
- Static detection in Java source, JVM bytecode and archives, Dockerfiles, Kubernetes manifests and CI definitions.
- Remote, clone-free scanning of GitHub repositories, organisations and users through the REST API and `gh`.
- Mitigation assistance: idempotent flag insertion, ready-to-paste delivery snippets, dry-run Kubernetes patches.
- Investigation: crash-log triage, Base64 token anomaly analysis, per-PID runtime facts.
- Reporting: evidence merge into `facts.json`, RAG status, eleven audience-specific Markdown reports.
- Programme guidance: category plans, level plans, checklists, side-effect documentation, pattern catalogue.

### 3.2 Out of scope

- Sending exploit payloads or any request designed to trigger the bug. All verification is non-intrusive.
- Writing to GitHub, modifying running JVMs, or changing cluster state without an explicit `--yes`.
- Patching JDKs or building images. The toolkit verifies; it does not perform the upgrade.
- Resolving floating image tags to exact versions (requires pulling the image; the toolkit says so instead).
- Runtime taint tracking; provenance classification is static and heuristic.

## 4. Design principles

| Principle | Requirement |
| :--- | :--- |
| **Self-contained** | Every script runs from a plain checkout with Bash and the Python standard library only. No `pip install`, no third-party module, no build step (SPEC-10-01). |
| **Non-intrusive** | No component sends crafted Base64 to a target. Runtime checks read `/proc`, `docker`, `kubectl` and `jcmd` only (SPEC-10-05). |
| **Evidence, not opinion** | Every verdict traces to a file:line, PID, repository, image tag or token the reader can open. Reports list their inputs (SPEC-06-13). |
| **One rule, many places** | Version, flag and verdict logic is specified once (document 01) and implemented identically in every component; divergence is a defect (SPEC-01-01). |
| **Library and CLI** | Helpers are importable or sourceable as well as executable (SPEC-03-02). |
| **Honest unknowns** | When a fact cannot be determined (`jcmd` restricted, floating tag, no `/proc`), the output says so with a distinct label; it never defaults to "safe" (SPEC-01-12). |
| **Document the side effects** | Every action a component recommends names the side-effect note it triggers (SPEC-08-04). |
| **Runbook deviations are explicit** | Where code corrects the runbook, the correction is listed in the component README and in `patterns/` (SPEC-10-10). |

## 5. Controlled vocabularies

Components MUST use these exact strings. They are case-sensitive and appear in JSON, TSV, SARIF, table output and
reports. Adding a value requires updating this table, `report-template/DATA-DICTIONARY.md` and
`planning/README.md`.

### 5.1 Version status (per version string)

| Value | Meaning |
| :--- | :--- |
| `VULN_RANGE` | In a vulnerable range per the decision table (SPEC-01-03) |
| `PATCHED_OR_UNAFFECTED` | Meets or exceeds the baseline, or is on an unaffected line |
| `UNKNOWN` | No parsable version in the input |

### 5.2 Mitigation flag state (per command line, environment or manifest text)

| Value | Meaning | Used by |
| :--- | :--- | :--- |
| `ACTIVE` | `-XX:-UseBASE64Intrinsics` present | runtime verification, helpers, Actions variables |
| `CAPPED` | `-XX:UseAVX=0..2` present and the primary flag absent | same |
| `EXPLICITLY_ENABLED` | `-XX:+UseBASE64Intrinsics` present | same |
| `NOT_SET_ON_CMDLINE_OR_ENV` | none of the above found | runtime verification, `j4s_proc.sh` |
| `MITIGATED_FLAG` / `MISSING_FLAG` | two-valued form used by the fleet audit (`flag_status`) | `audit_java4shell.*` |
| `MISSING` / `NONE` / `n/a` | Actions variable present without the flag / no variable / no permission | `gh_j4s_actions.sh` |

### 5.3 Runtime exposure verdict (per JVM process)

| Value | Rule (see SPEC-01-07) |
| :--- | :--- |
| `PATCHED_OR_SAFE_VERSION` | version status is `PATCHED_OR_UNAFFECTED` |
| `MITIGATED_BY_FLAG` | not patched, flag status `MITIGATED_FLAG` |
| `EXPOSED_ON_VBMI_HOST` | not patched, flag missing, host CPU exposes `avx512_vbmi` |
| `UNVERIFIED_ON_HOST` | not patched, flag missing, CPU without VBMI or unknown |

Text-mode fleet audit uses `RISK` words `HIGH_EXPOSURE`, `CHECK_CPU_AND_PATCH`, `LOW` with the same meaning.

### 5.4 Repository verdict (per GitHub repository)

`EXPOSED`, `EXPLICITLY_ENABLED`, `MITIGATED_FLAG`, `UNVERIFIED_FLOATING`, `UNVERIFIED_NO_PIN`, `PATCHED`,
`NOT_JAVA`, `ERROR`. Ordered worst-first in that sequence. Blocking set: `EXPOSED`, `EXPLICITLY_ENABLED`. Strict
set adds the two `UNVERIFIED_*` values. Semantics in SPEC-04-08.

### 5.5 Input provenance kind (per decode call site)

`DYNAMIC_UNTRUSTED` > `DYNAMIC_INTERNAL` > `UNKNOWN` > `CONSTANT` (severity order). Definitions in SPEC-01-09.

### 5.6 Reachability verdict (per bytecode finding, runbook `j4s_analyzer`)

`REACHABLE_HIGH` (blocks the gate), `REACHABLE_CODE_ONLY`, `CONDITIONAL_LOW`, `UNREACHABLE_OR_N_A`. Matrix in
SPEC-01-10.

### 5.7 Pattern severity on match

`INFO`, `REVIEW`, `MITIGATE`, `BLOCK`. `BLOCK` means a CI gate must fail.

### 5.8 Crash triage verdict

`LIKELY` (score ≥ 6), `POSSIBLE` (score ≥ 3), `UNLIKELY`. Scoring in SPEC-03-14.

### 5.9 Report status

`RED`, `AMBER`, `GREEN` (and `NONE` for a host with no JVMs). Rules in SPEC-06-07.

### 5.10 Version pin kind and scope (repository scan)

Kind: `EXACT`, `FLOATING`, `LANGUAGE_LEVEL`, `UNKNOWN`. Per-pin status adds `FLOATING_PATCHABLE` (major-only pin on a
patchable line) and `LANGUAGE_LEVEL` (compiler level, evidence only) to the values of §5.1. Flag-finding state adds
`MENTION` (flag name present without a decidable value). Scope: `runtime`, `build`, `dev`, `docs`. Only `runtime`
findings decide a repository verdict (SPEC-04-07).

### 5.11 Scope words in prose

*exposed* = exploitable now; *unverified* = vulnerable build but not exploitable on this CPU or undeterminable;
*mitigated* = flag confirmed live; *patched* = baseline met. Documents and templates MUST NOT write "safe" for a
flag-only state.

## 6. Actors and their entry points

| Actor | Primary entry points | Reports read |
| :--- | :--- | :--- |
| Security engineer | `scripts/`, `github/`, `patterns/`, plans 01, 02, 10 | R1, R7 |
| Platform / SRE | `scripts/verify_java4shell_runtime.sh`, `scripts/audit_java4shell.py`, `helpers/j4s_proc.sh`, `helpers/j4s_k8s.sh`, `helpers/j4s_flag.sh`, plans 04, 05 | R6 |
| Developer / reviewer | `scripts/scan_java4shell_source.py`, `scripts/scan_java4shell_jars.py`, plan 03, 06 | R4 |
| Release / DevOps | `scripts/gate_cve_2026_114938.py`, `github/gh_j4s_actions.sh`, plan 06 | R5 |
| SOC / IR | `helpers/j4s_hs_err.py`, `helpers/j4s_b64check.py`, plans 08, 09 | R8 |
| Edge / WAF engineer | runbook §4 rules, `helpers/j4s_b64check.py`, plan 07 | R10 |
| Programme manager / CISO | `report-template/`, plans 00, 11, 12, `planning/levels/` | R0, R1, R2, R9 |

## 7. Lifecycle the toolkit supports (runbook §8)

1. Inventory runtimes and containers.
2. Verify hardware and intrinsic state.
3. Scan source, bytecode and dependencies.
4. Trace input provenance and touchpoints.
5. Apply the immediate mitigation flag.
6. Verify safely and monitor side effects.
7. Patch the JDK and enforce CI/CD gates.

Each step maps to pattern IDs (SPEC-05-06), to a planning document (document 07) and to one or more reports
(document 06).
