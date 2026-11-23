# 01 — Shared Decision Rules

These rules are implemented in more than one component. Every implementation MUST produce the same answer for
the same input. Divergence between two components is a defect in whichever one disagrees with this document.

## 1. Single-source rule

**SPEC-01-01.** Version classification, mitigation-flag detection, exposure verdicts and hardware-scope detection
MUST follow this document. Reference implementations: `helpers/j4s_version.py` (versions), `helpers/j4s_flag.sh`
and `helpers/j4s_proc.sh` (flags), `scripts/audit_java4shell.py` (exposure), `github/gh_j4s_scan.py`
(repository verdicts). A new component MUST import or copy these rules, not re-derive them from the runbook text.

## 2. Version parsing and classification

**SPEC-01-02 Parsing.** A version string is normalised as follows:

1. If it matches `8u511b33-perf` (case-insensitive) it is Oracle Java SE perf build → `VULN_RANGE` immediately.
2. Otherwise extract the leading numeric tuple `\d+(\.\d+){0,4}`: up to **five** components. Trailing qualifiers
   `_N` (Temurin build), `+N` (OpenJDK build) and `-suffix` (`-jre`, `-tem`, `-LTS`) are ignored.
3. Fewer than two components (a bare major such as `21`) is a **floating** pin (SPEC-04-06); it is classified by
   major only.
4. If nothing numeric is found the status is `UNKNOWN`.

Vendor numbering caveat: Corretto and Zulu tags carry extra vendor components (`21.0.4.7.1`, `21.0.4-21.36`). The
comparison uses the leading OpenJDK version and consults a fifth component only when the baseline has one
(`17.0.21.0.3`).

**SPEC-01-03 Decision table.** With `major`, `minor`, `patch`, `build`, `fifth` (missing components are 0) and
lexicographic comparison of the padded tuple:

| Major | Rule | Status |
| :--- | :--- | :--- |
| ≤ 16 (not perf) | always | `PATCHED_OR_UNAFFECTED` |
| 17, minor 0 | tuple < `17.0.6` | `PATCHED_OR_UNAFFECTED` |
| 17, minor 0 | `17.0.6` ≤ tuple < `17.0.21.0.3` | `VULN_RANGE` |
| 17, minor 0 | tuple ≥ `17.0.21.0.3` | `PATCHED_OR_UNAFFECTED` |
| 18, 19, 20, 22, 23, 24, 26 | always (EOL, no patch exists; floating tags included) | `VULN_RANGE` |
| 21, minor 0 | tuple < `21.0.13.1` | `VULN_RANGE`, else `PATCHED_OR_UNAFFECTED` |
| 25, minor 0 | tuple < `25.0.5.1` | `VULN_RANGE`, else `PATCHED_OR_UNAFFECTED` |
| 27, minor 0 | tuple < `27.0.1.1` | `VULN_RANGE`, else `PATCHED_OR_UNAFFECTED` |
| any other shape (e.g. 28+, or 17.1.x) | default | `VULN_RANGE` (requires manual verification) |

The runbook's bash audit treats `17.x` with `minor != 0` as unaffected; the stricter gate behaviour above is the
requirement. When two tools disagree, the stricter result wins.

**SPEC-01-04 Baselines API.** `baseline_for(major)` returns `17.0.21.0.3`, `21.0.13.1`, `25.0.5.1`, `27.0.1.1` for
17/21/25/27 and `None` otherwise. The CLI form `j4s_version.py baseline MAJOR` prints the baseline, `EOL: migrate to
21 (21.0.13.1)` for 18–20/22–24/26, `unaffected` for ≤ 16, and `unknown` for any other major.

**SPEC-01-05 Superseded runbook behaviour.** The runbook's `JDK_VER_RE` (4-component capture, `\b` before `_`)
and `parse_semver4` are superseded. Known consequences, which conformant components MUST NOT reproduce:

| Input | Runbook result | Required result |
| :--- | :--- | :--- |
| `17.0.21.0.3` | `VULN_RANGE` (read as `17.0.21.0`) | `PATCHED_OR_UNAFFECTED` |
| `17.0.21.0.2` | `VULN_RANGE` | `VULN_RANGE` |
| `21.0.12_7` | not matched | `VULN_RANGE` |
| `21.0.13.1_9` | `VULN_RANGE` (read as `21.0.13`) | `PATCHED_OR_UNAFFECTED` |

Pattern references: `J4S-VER-01` (gap record), `J4S-VER-01b` (corrected extractor), `J4S-VER-02`, `J4S-VER-04`,
`J4S-VER-05`.

**SPEC-01-06 `java -version` output.** When classifying tool output rather than a tag, take the quoted string on
the first line (`openjdk version "21.0.12" 2024-07-16`), falling back to the first `\d+(\.\d+){1,3}` or `8u…`
token. Mark output beginning `no-shell`, `exec-unavailable`, `unknown` or `error:` as `UNKNOWN`.

## 3. Mitigation-flag detection

**SPEC-01-07 Token-bounded match.** A mitigation is **present** when either token appears bounded by start of
string, whitespace, a double quote **or `=`** on the left, and end of string, whitespace or a double quote on the
right:

```
(^|[[:space:]"=])-XX:-UseBASE64Intrinsics([[:space:]"]|$)      -> ACTIVE
(^|[[:space:]"=])-XX:UseAVX=[0-2]([[:space:]"]|$)              -> CAPPED
(^|[[:space:]"=])-XX:\+UseBASE64Intrinsics([[:space:]"]|$)     -> EXPLICITLY_ENABLED
```

Precedence: `ACTIVE` > `CAPPED` > `EXPLICITLY_ENABLED` > `NOT_SET_ON_CMDLINE_OR_ENV`. The `=` in the leading
class is required because `/proc/<pid>/environ`, `docker inspect` and Kubernetes `env` render the variable as
`JAVA_TOOL_OPTIONS=-XX:-UseBASE64Intrinsics`; the runbook's `classify_flag_text` lacked it and is superseded
(`J4S-FLAG-02`, `J4S-FLAG-03`, `J4S-FLAG-04`).

Loose variants (`J4S-FLAG-05`, `-06`, `-07`) that match the token anywhere are acceptable for fleet audit and
CI gate text scanning, where the surface is free text rather than an option string.

**SPEC-01-08 Surfaces to inspect, in order of authority.**

1. Live JVM: `jcmd <pid> VM.flags -all` (or `jinfo -flag UseBASE64Intrinsics <pid>`), run as the process owner or
   root. This is the only proof that the flag is active (`J4S-FLAG-09`).
2. Process command line `/proc/<pid>/cmdline` and environment `/proc/<pid>/environ` restricted to
   `JAVA_TOOL_OPTIONS`, `JDK_JAVA_OPTIONS`, `_JAVA_OPTIONS` (`J4S-FLAG-08`).
3. Container spec: `docker inspect .Config.Env`, Kubernetes `spec.containers[].env/args/command`.
4. Declared runtime files in repositories (Dockerfile `ENV`, manifests, systemd units, start scripts).

A result from a lower level MUST be labelled as such (`Cmd/Env Flag`, `Manifest Flag`) and MUST NOT be reported as
"live".

## 4. Hardware scope

**SPEC-01-09 CPU detection.** On `x86_64` with readable `/proc/cpuinfo`, `avx512_vbmi` present in the `flags`
line means in hardware scope (`J4S-RT-03`). Also record `avx512f` and `avx512_vbmi2`. On any other architecture
the result is "not applicable"; when `/proc/cpuinfo` is unreadable the result is "unknown", never "false".
Kubernetes node checks report arch and CPU model and state that VBMI needs a per-node check.

## 5. Exposure verdict (runtime)

**SPEC-01-10 Per-process verdict.**

```
if version_status == PATCHED_OR_UNAFFECTED:  PATCHED_OR_SAFE_VERSION
elif flag_status == MITIGATED_FLAG:          MITIGATED_BY_FLAG
elif cpu_vbmi is True:                       EXPOSED_ON_VBMI_HOST
else:                                        UNVERIFIED_ON_HOST
```

`UNKNOWN` version status is treated as not patched. Verdict rank for trend comparison:
`EXPOSED_ON_VBMI_HOST` < `UNVERIFIED_ON_HOST` < `MITIGATED_BY_FLAG` < `PATCHED_OR_SAFE_VERSION`; a lower rank
after a higher one is a **regression**.

## 6. Input provenance (source)

**SPEC-01-11 Classification of a decode argument.** Given the argument expression of a
`Base64.get{,Url,Mime}Decoder().decode|wrap(...)` call and its enclosing method context:

| Condition | Kind |
| :--- | :--- |
| Expression is a string literal or a `SCREAMING_CASE` identifier (`[A-Z][A-Z0-9_]{2,}`) | `CONSTANT` (even when the method also reads headers; supersedes the runbook promotion) |
| Context matches an untrusted-source signature (`J4S-SRC-03`: HTTP headers/Authorization/Basic, request parameters/body/streams, JWT/SAML/bearer tokens, file or stream I/O, messaging/sockets/HTTP clients) | `DYNAMIC_UNTRUSTED` |
| Non-empty expression without a source signature | `DYNAMIC_INTERNAL` |
| Empty or unparsable | `UNKNOWN` |

`preauth_context` is true when an auth term (`Authorization`, `Proxy-Authorization`, `Basic …`, `jwt`, `jws`,
`saml`, `bearer`) occurs within 120 characters before a decode token on the same line (`J4S-SRC-04`).

## 7. Reachability verdict (runbook `j4s_analyzer`)

**SPEC-01-12 Matrix.** Given `is_test`, `input_kind`, and a runtime context (`jdk_patched`,
`mitigation_flag_present`, `avx512_vbmi`, `arch`):

| Condition | Verdict | Confidence |
| :--- | :--- | :--- |
| `is_test` | `CONDITIONAL_LOW` | MEDIUM |
| runtime safe (patched or flag) **or** CPU non-VBMI / non-x86-64, and `DYNAMIC_UNTRUSTED` | `REACHABLE_CODE_ONLY` | HIGH |
| runtime safe or non-VBMI, other kinds | `UNREACHABLE_OR_N_A` | HIGH |
| unmitigated and `DYNAMIC_UNTRUSTED` | `REACHABLE_HIGH` (BLOCK) | HIGH |
| unmitigated and `DYNAMIC_INTERNAL` / `UNKNOWN` / `CONSTANT` | `CONDITIONAL_LOW` | MEDIUM |

## 8. Unknowns and honesty

**SPEC-01-13.** When a check cannot run, the output MUST carry a distinct label and the summary MUST count it
separately: `jcmd-not-found`, `jcmd-unavailable-or-restricted`, `different-owner (user); run as user or root`,
`version-not-directly-resolved`, `exec-unavailable`, `no-shell-or-java`, `UNVERIFIED_FLOATING`,
`UNVERIFIED_NO_PIN`, `n/a`, `unknown`. No component may map an unknown to a safe state.

## 9. Exit-code convention

**SPEC-01-14.** Every executable in `scripts/`, `helpers/` and `github/` MUST use:

| Code | Meaning |
| :--- | :--- |
| `0` | ran; nothing needs attention (or, for pure reporters such as the audits, "ran, read the verdicts") |
| `1` | execution error (unreadable input, API failure, missing tool) — **except** `gate_cve_2026_114938.py`, where `1` means *gate failed* |
| `2` | ran and found something that needs attention (vulnerable version, exposed JVM, suspicious token, LIKELY/POSSIBLE crash, regression, RED report, blocking repository); for `verify_java4shell_runtime.sh`, usage error |

Per-component tables in documents 02–04 and 06 are the authoritative detail; this table is the convention they
instantiate.

## 10. Timing conventions

**SPEC-01-15.** Timings are expressed relative to disclosure, `T0 = 2026-11-17`, as `T+<n> h` / `T+<n> d`. SLA
dates are `T0 + sla_mitigate_days` (default 2) and `T0 + sla_patch_days` (default 30). A breach is reported only
while exposure remains.
