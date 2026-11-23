# 03 — Helpers and the `j4s` CLI (`helpers/`)

Small building blocks that wrap, feed and consume the detection scripts. Every helper is both a CLI and a
library.

## 1. Common requirements

**SPEC-03-01 Dependencies.** Bash 3.2+ (macOS default) for shell helpers; Python 3.10+ standard library for
Python helpers. `j4s_k8s.sh` and `j4s_flag.sh k8s-*` need `kubectl`. Python invoked from shell helpers MUST use
`python3 -I`.

**SPEC-03-02 Dual use.** Shell helpers expose `j4s_*` functions and MUST be safe to `source` (no side effects at
load, CLI dispatch guarded). Python helpers expose the functions named in `helpers/README.md` ("Library use")
and run `main()` only under `__main__`.

**SPEC-03-03 Exit codes.** `0` nothing needs attention; `2` found something that does; `1` execution error
(SPEC-01-14). `j4s_flag.sh has` returns `0` present / `1` missing as a predicate.

**SPEC-03-04 Shared logic.** Version and flag rules follow document 01; `j4s_version.py` is the reference
implementation for versions, `j4s_flag.sh`/`j4s_proc.sh` for flag state.

## 2. `j4s` — single entry point

**SPEC-03-05.** `helpers/j4s <command> [args]` dispatches by `exec` to the component listed below, so exit codes
and arguments pass through unchanged. `help`, `-h`, `--help` or no command prints usage grouped by phase; an
unknown command prints usage to stderr and exits 2.

| Group | Command | Target |
| :--- | :--- | :--- |
| Detection | `verify`, `audit`, `audit-sh`, `scan-src`, `scan-jars`, `gate` | `scripts/verify_java4shell_runtime.sh`, `audit_java4shell.py`, `audit_java4shell.sh`, `scan_java4shell_source.py`, `scan_java4shell_jars.py`, `gate_cve_2026_114938.py` |
| Investigation | `version`, `b64`, `hs-err`, `proc`, `k8s` | `j4s_version.py`, `j4s_b64check.py`, `j4s_hs_err.py`, `j4s_proc.sh`, `j4s_k8s.sh` |
| Remediation | `flag` | `j4s_flag.sh` |
| Reporting | `inventory`, `report` | `j4s_inventory.py`, `j4s_report.py` |
| GitHub | `gh-repos`, `gh-scan`, `gh-search`, `gh-actions` | `github/gh_j4s_repos.sh`, `gh_j4s_scan.py`, `gh_j4s_code_search.py`, `gh_j4s_actions.sh` |
| Report templates | `facts`, `render` | `report-template/tools/j4s_facts.py`, `render.py` |

Paths are resolved relative to the script's own location so `j4s` works from any working directory.

## 3. `j4s_flag.sh` — mitigation flag management

**SPEC-03-06 Functions.** `j4s_flag_has OPTS` (predicate per SPEC-01-07, accepts `ACTIVE` or `CAPPED`),
`j4s_flag_enabled_explicitly OPTS`, `j4s_flag_add OPTS` (idempotent: strips any `-XX:+UseBASE64Intrinsics`,
appends `-XX:-UseBASE64Intrinsics` once, normalises whitespace), `j4s_flag_remove OPTS` (post-patch cleanup),
`j4s_flag_snippet KIND`, `j4s_flag_k8s_apply`, `j4s_flag_k8s_verify`.

**SPEC-03-07 CLI.**

```
j4s_flag.sh has|add|remove "<opts>"
j4s_flag.sh snippet dockerfile|compose|k8s-env|k8s-patch|systemd|helm|tomcat|gradle|maven|bash
j4s_flag.sh k8s-apply <workload> [-n NS] [-c CONTAINER] [--kind Deployment|StatefulSet|DaemonSet] [--yes]
j4s_flag.sh k8s-verify <workload> [-n NS]
```

**SPEC-03-08 Safety.** `k8s-apply` prints the `kubectl patch` it would run and exits without applying unless
`--yes` is given. Snippets merge into existing `JAVA_TOOL_OPTIONS` rather than overwrite, and every snippet that
sets a host-wide variable carries a comment pointing to side effect 07.

## 4. `j4s_version.py` — version classifier

**SPEC-03-09 CLI.**

```
j4s_version.py classify VER... [--json]
j4s_version.py parse-output [FILE] [--json]      # java -version text from file or stdin
j4s_version.py baseline MAJOR                      # e.g. 21 -> 21.0.13.1
j4s_version.py table [--json]
```

**SPEC-03-10 Library.** `classify(ver)` returns a record with `input`, `normalized`, `major`, `status`, `reason`,
`baseline`, `action`; `from_java_version_output(text)`; `baseline_for(major)`. Exit 2 when any classified input is
`VULN_RANGE`.

## 5. `j4s_proc.sh` — per-process investigation (Linux)

**SPEC-03-11 Functions and CLI.**

| Function | CLI | Output |
| :--- | :--- | :--- |
| `j4s_cpu_vbmi`, `j4s_cpu_summary` | `cpu` | arch, VBMI state with `n/a` (non-x86) / `unknown` (unreadable) |
| `j4s_list_jvm_pids` | `list` | PIDs mapping `libjvm.so` |
| `j4s_pid_is_jvm`, `j4s_pid_cmdline`, `j4s_pid_jvm_env`, `j4s_pid_java_home` | `env PID`, `home PID` | facts |
| `j4s_pid_version PID` | `version PID` | version read from `$JAVA_HOME/release` (`JAVA_VERSION=`) when readable, **without spawning a JVM**; else `java -version` |
| `j4s_pid_flag_state PID` | `flags PID` (cmd/env line) | `ACTIVE | CAPPED | EXPLICITLY_ENABLED | NOT_SET_ON_CMDLINE_OR_ENV` |
| `j4s_pid_live_flags PID` | `flags PID` (live line) | `jcmd VM.flags -all` extract or the unknown labels of SPEC-01-13 |
| `j4s_pid_report PID` | `report [PID...]` (all JVMs when none given) | one block per PID incl. container cgroup |
| `j4s_container_pids CID` | `container CID` | host PIDs of a Docker container |
| `j4s_classify_flag_text TEXT` | `classify TEXT` | flag state of arbitrary text |

## 6. `j4s_k8s.sh` — Kubernetes read-only inventory

**SPEC-03-12.**

```
j4s_k8s.sh pods    [-n NS | -A] [-l SELECTOR] [--json]   # JVM-like containers: image, JVM env, flag status, image version classification
j4s_k8s.sh images  [-n NS | -A] [--json]                 # distinct JVM-like images with VULN_RANGE / PATCHED / FLOATING classification
j4s_k8s.sh missing [-n NS | -A] [--json]                 # Deployments/StatefulSets/DaemonSets lacking the flag
j4s_k8s.sh nodes                                         # node arch + CPU model; states that VBMI needs a per-node check
```

JVM-likeness uses the extended image/command heuristic (`J4S-RT-04` plus vendor and product names such as
`keycloak`, `kafka`, `elasticsearch`, `jenkins`, `solr`, `cassandra`, `flink`, `nexus`). Only `kubectl get` is
used; the helper never mutates cluster state.

## 7. `j4s_b64check.py` — Base64 token analysis

**SPEC-03-13 CLI and library.**

```
j4s_b64check.py token TOKEN... [--json]               # '-' reads one token from stdin
j4s_b64check.py scan FILE [--min-len N] [--all] [--json]   # logs, HAR, request dumps; '-' = stdin
j4s_b64check.py headers [FILE] [--json]               # Authorization header lines
```

Library: `analyze(token) -> Analysis`, `is_strictly_valid(token) -> bool` (RFC 4648 strict, intended as an
application-side guard before `decode()`), `find_tokens`, `scan_text`, `scan_headers`.

`Analysis` fields: `token` (truncated on output), `length`, `alphabet` (`std|url|mixed|invalid`), `pad_count`,
`strict_valid`, `anomalies[]`, `edge_rules_hit[]`, `suspicious`, `looks_like_jwt`. Anomaly labels:
`excess_padding`, `padding_inside_body`, `mixed_std_and_url_alphabet`, `non_base64_characters`,
`length_not_multiple_of_4_with_padding`, `impossible_body_length_mod4_eq_1`,
`padding_mismatch_expected_<n>_got_<m>`; JWT segments are analysed individually and prefixed `seg<i>:`.
`edge_rules_hit` maps to `J4S-EDGE-01..03`. A token is `suspicious` when it has any anomaly, or hits EDGE-01/02
while not strictly valid; EDGE-03 alone on a valid token is the documented false positive and is not suspicious.
Exit 2 when any analysed token is suspicious.

## 8. `j4s_hs_err.py` — crash-log triage

**SPEC-03-14 Scoring.** For each `hs_err_pid*.log` (or `-`), extract signal, problematic frame, JRE version,
`jvm_args`, CPU features, Base64 stub/decoder frames, heap-corruption markers, then score:

| Evidence | Score |
| :--- | :--- |
| Base64 decoder/stub frames on the stack | +4 |
| Problematic frame is the Base64 intrinsic/decoder | +3 |
| Memory-access signal (`SIGSEGV`, `SIGBUS`, `EXCEPTION_ACCESS_VIOLATION`) | +1 |
| Heap-corruption markers | +2 |
| JRE in `VULN_RANGE` | +2 |
| JRE `PATCHED_OR_UNAFFECTED` | −4 |
| CPU exposes `avx512_vbmi` | +1 |
| CPU lacks `avx512_vbmi` | −3 |
| Mitigation flag present in `jvm_args` | −4 |
| `-XX:+UseBASE64Intrinsics` present | +1 |

Verdict: `LIKELY` ≥ 6, `POSSIBLE` ≥ 3, else `UNLIKELY`. Output fields (`--json`): `file`, `signal`,
`problematic_frame`, `jre_version`, `version_status`, `mitigation_present`, `explicitly_enabled`,
`cpu_avx512_vbmi`, `base64_frames[]`, `heap_corruption_markers[]`, `verdict`, `score`, `reasons[]`. Exit 2 when
any file is `LIKELY` or `POSSIBLE`.

## 9. `j4s_inventory.py` — fleet inventory

**SPEC-03-15.**

```
j4s_inventory.py merge FILES... [--csv OUT] [--json OUT]
j4s_inventory.py rank FILES... [--top N]            # worst first (default 50)
j4s_inventory.py summary FILES... [--json]          # per-host counts
j4s_inventory.py diff BEFORE... --split AFTER...    # improved / regressed / unchanged / new / gone
```

Input: audit JSON files (SPEC-02-15); host from `host` field or `audit-<host>.json` file name. Processes are
matched across runs by `(host, workload id)` where the workload id is derived from the first 60 characters of
the command line. Rank order follows SPEC-01-10. Exit 2 when any `EXPOSED_ON_VBMI_HOST` row remains
(`merge`/`rank`/`summary`) or any regression exists (`diff`). Library: `load_audits`, `rows_from_audits`,
`rank_rows`, `diff_rows`.

## 10. `j4s_report.py` — consolidated status report

**SPEC-03-16.**

```
j4s_report.py [--audit JSON...] [--jars JSONL] [--source JSON] [--gate LOG] [--crashes JSON] [--b64 JSON] [--format md|json|html] [-o FILE]
```

Produces a single report with a `RED` / `AMBER` / `GREEN` status and a concrete action list. `RED` when any
exposed JVM or an untrusted decode on an unmitigated host; `AMBER` for flag-only, unverified, untrusted sites,
gate failures, POSSIBLE crashes or suspicious traffic; otherwise `GREEN`. Exit 2 on `RED`. This is the
lightweight alternative to the full template pipeline (document 06); both MUST agree on RAG for the same inputs.

## 11. Documentation duties

**SPEC-03-17.** `helpers/README.md` MUST keep: the helper table by phase, "Typical flows", "Library use", the
exit-code rule, the version-logic paragraph, and the pointer to side effect 09 for attach and spawn footprint.
