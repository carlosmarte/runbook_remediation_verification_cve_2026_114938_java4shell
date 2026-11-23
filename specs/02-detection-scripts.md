# 02 — Detection Scripts (`scripts/`)

Six runnable scripts extracted from the runbook (§2, §3, §5, §6, §7). They are the evidence producers for the
runtime, code and policy layers.

## 1. Common requirements

**SPEC-02-01 Dependencies.** Bash 4+ (Linux) for the shell scripts; Python 3.10+ standard library for the Python
scripts. Optional tools (`docker`, `kubectl`, `jcmd`, `curl`) are detected at run time; absence degrades output
with a labelled note, never a crash.

**SPEC-02-02 Non-intrusive.** No script sends a request body or header crafted to trigger the vulnerability.
Health checks are plain `GET` with a 5 s timeout.

**SPEC-02-03 Rule conformance.** All version, flag and verdict logic follows document 01. Each script's README
section lists every deliberate deviation from the runbook text (currently: five-component version comparison,
`=` delimiter for flags, gate fails on explicit re-enable and recognises vendor image names, source scan keeps
literal arguments `CONSTANT`, audit tolerates a missing `/proc`).

**SPEC-02-04 Exit codes.**

| Script | 0 | 1 | 2 |
| :--- | :--- | :--- | :--- |
| `verify_java4shell_runtime.sh` | ran | — | usage error |
| `audit_java4shell.sh` / `.py` | ran (read the verdicts) | error | — |
| `scan_java4shell_source.py` | no `DYNAMIC_UNTRUSTED` | error | `DYNAMIC_UNTRUSTED` findings present |
| `scan_java4shell_jars.py` | no findings | error | findings present |
| `gate_cve_2026_114938.py` | gate passed | gate failed | — |

## 2. `verify_java4shell_runtime.sh` (runbook §2)

**SPEC-02-05 Purpose.** Live, read-only verification of one Linux host: CPU flags, running Docker containers,
host JVM processes, optional Kubernetes pods, live JVM flags via `jcmd`, optional health GETs.

**SPEC-02-06 CLI.**

```
verify_java4shell_runtime.sh [--health-url URL]... [--no-docker] [--k8s] [--k8s-namespace NS] [--k8s-selector LABEL]
```

Unknown options print usage and exit 2. `--k8s-namespace` / `--k8s-selector` imply `--k8s`.

**SPEC-02-07 Behaviour.**

1. Print header with arch and `avx512f` / `avx512_vbmi` / `avx512_vbmi2` booleans (SPEC-01-09).
2. Section 1, Docker (unless `--no-docker` or no CLI): for each running container print name, id, image, JVM env
   variables from `.Config.Env`, then for each container PID (via `docker top -eo pid`) that maps `libjvm.so`
   (`J4S-RT-01`) print the JVM block; record the PID as container-owned.
3. Section 2, host: every remaining `/proc/<pid>` mapping `libjvm.so` prints the JVM block with scope `host`.
4. Section 3, Kubernetes (with `--k8s`): `kubectl get pods -o json` (all namespaces unless `-n`), optional
   `-l selector`; for every container or init container that looks JVM-like (`J4S-RT-04`), carries a JVM env var or
   matches the flag regex, print pod, container, image, resolved `imageID`, JVM env, and `Manifest Flag:
   PRESENT|MISSING_OR_NOT_IN_SPEC`. Missing `kubectl` prints a skip note.
5. Section 4, health: `curl -sS -m 5` each `--health-url`, print HTTP status (`000` on failure).

**SPEC-02-08 JVM block.** For each JVM PID: `libjvm.so` path, command line (truncated to 150 chars), JVM env
variables (if any), Java version (`java -version` from `$JAVA_HOME/bin/java` derived from the `libjvm.so` path,
`J4S-RT-02`, else argv[0] when it contains `java`; otherwise `version-not-directly-resolved`), `Cmd/Env Flag`
state (SPEC-01-07 on cmdline + env), and `Live VM Flag` from `jcmd <pid> VM.flags -all` showing the
`UseBASE64Intrinsics` and `UseAVX` values (`J4S-FLAG-09`).

**SPEC-02-09 `jcmd` privilege handling.** Use `$JAVA_HOME/bin/jcmd` next to the resolved java binary, else
`jcmd` on `PATH`. If the current user is neither root nor the process owner, print `different-owner (<owner>);
run as <owner> or root`. As root for a non-root process, run via `runuser -u <owner>` when available. Empty
output prints `jcmd-unavailable-or-restricted`.

## 3. `audit_java4shell.sh` (runbook §3.1)

**SPEC-02-10 Purpose.** Fleet audit in human-readable text: one line per JVM process and one per Docker
container.

**SPEC-02-11 Output line (processes).**

```
PID=<pid> | RISK=<HIGH_EXPOSURE|CHECK_CPU_AND_PATCH|LOW> | VER_STATUS=<VULN_RANGE|PATCHED_OR_UNAFFECTED|UNKNOWN> | FLAG=<MITIGATED_FLAG|MISSING_FLAG> | CMD=<120 chars> | VER=<java -version, 2 lines joined>
```

`RISK` is `HIGH_EXPOSURE` when CPU has VBMI, version not `PATCHED_OR_UNAFFECTED` and flag missing;
`CHECK_CPU_AND_PATCH` when version `VULN_RANGE` and flag missing on a non-VBMI host; else `LOW`.

**SPEC-02-12 Output line (containers).**

```
Container=<name> (<id>) | Image=<image> | HasJVM=<true|false> | MissingFlagProcs=<n> | JavaCheck=<java -version first line | no-shell-or-java | exec-unavailable>
```

The container `JavaCheck` runs `docker exec <id> sh -c 'java -version'`; this spawns a JVM inside the container
and MUST be documented as a footprint (side effect 09).

## 4. `audit_java4shell.py` (runbook §3.2)

**SPEC-02-13 Purpose.** The same audit as structured JSON. This is the canonical per-host evidence consumed by
`helpers/j4s_inventory.py`, `helpers/j4s_report.py` and `report-template/tools/j4s_facts.py`.

**SPEC-02-14 CLI.** `audit_java4shell.py [--pretty]`. Run as root or the JVM owner. Typically shipped over SSH:
`ssh host 'sudo python3 -' < scripts/audit_java4shell.py > audits/audit-host.json`.

**SPEC-02-15 Output contract (stable).**

```json
{
  "cve": "CVE-2026-114938", "alias": "Java4Shell",
  "cpu": {"arch": "x86_64", "avx512_vbmi": true, "avx512_vbmi2": true, "avx512_flags_sample": ["avx512f", "..."]},
  "summary": {"total_jvms_found": 3, "exposed_on_vbmi_host": 1, "missing_mitigation_flag": 2},
  "jvm_processes": [{
    "pid": 1234, "source": "host | container:<name>", "jvm_lib_path": "...", "java_binary": "... | null",
    "version_output": "openjdk version \"21.0.12\" ... | unknown (no java binary resolved) | error:...",
    "parsed_version": "21.0.12 | null", "version_status": "VULN_RANGE | PATCHED_OR_UNAFFECTED | UNKNOWN",
    "flag_status": "MITIGATED_FLAG | MISSING_FLAG", "cmdline": "...",
    "exposure_verdict": "EXPOSED_ON_VBMI_HOST | UNVERIFIED_ON_HOST | MITIGATED_BY_FLAG | PATCHED_OR_SAFE_VERSION"
  }],
  "containers": [{"id": "...", "name": "...", "image": "...", "pids": [1234]}]
}
```

Consumers key on `cpu.avx512_vbmi`, `jvm_processes[].exposure_verdict`, `version_status`, `flag_status`,
`parsed_version`, `cmdline`, `source`, `pid`. Fields MAY be added; these MUST NOT be renamed or removed. An
optional top-level `host` string MAY be present; otherwise consumers derive the host from the file name
(`audit-<host>.json`).

**SPEC-02-16 Portability.** When `/proc` is absent (macOS, Windows) the script prints a note and a report with
zero processes rather than raising.

**SPEC-02-17 Footprint.** `java -version` is executed once per distinct resolved binary with a 3 s timeout. The
script MUST NOT attach to the JVM (`jcmd`) — that is the verification script's job.

## 5. `scan_java4shell_source.py` (runbook §6 `ast_taint.py`, §7.3)

**SPEC-02-18 Purpose.** Find every `java.util.Base64` decode call site in a Java source tree, classify the
argument's provenance (SPEC-01-11), flag pre-auth context, and emit text, JSON or SARIF.

**SPEC-02-19 CLI.**

```
scan_java4shell_source.py [ROOT] [--json] [--sarif FILE] [--include-tests] [--min-kind CONSTANT|UNKNOWN|DYNAMIC_INTERNAL|DYNAMIC_UNTRUSTED]
```

Default root `.`. Test code is excluded unless `--include-tests`; the heuristic (`J4S-BC-04` extended) is a path
segment `test`, `tests`, `androidTest` or `it`, the token `test-classes`, or a file name ending `Test.java|kt|scala|groovy`
(case-insensitive). Findings are sorted worst-first (`DYNAMIC_UNTRUSTED` → `CONSTANT`), then by file and line.

**SPEC-02-20 Detection.** Files are pre-filtered on the tokens `Base64` or `Decoder` (`J4S-SRC-05`). Call
sites match `J4S-SRC-02` (`Base64.get{,Url,Mime}Decoder().decode|wrap(`); the argument is captured with
**balanced parentheses**, so `dec.wrap(in).read()` yields `in`. The classification context is the enclosing
method, approximated as up to 40 lines back to the nearest method declaration and 5 lines forward (supersedes
the runbook's fixed 15/5 window).

**SPEC-02-21 JSON contract.**

```json
{"cve": "CVE-2026-114938", "root": "./src", "total": 7, "dynamic_untrusted": 1,
 "findings": [{"file": "...", "line": 42, "column": 17, "call": "Base64.getDecoder().decode", "argument": "token",
               "input_kind": "DYNAMIC_UNTRUSTED", "sources": ["http_auth_header"], "preauth_context": true,
               "is_test": false, "reason": "...", "remediation": "..."}]}
```

**SPEC-02-22 SARIF.** SARIF 2.1.0 with one rule; `level` is `error` for `DYNAMIC_UNTRUSTED`, `warning` for
`DYNAMIC_INTERNAL`/`UNKNOWN`, `note` for `CONSTANT`; `properties` carry `sources`, `preauth_context`, `is_test`.

## 6. `scan_java4shell_jars.py` (runbook §5 `j4s-extract`)

**SPEC-02-23 Purpose.** Pure-Python replacement for the Rust extractor: parse class files inside `.class`,
`.jar`, `.war`, `.ear`, `.zip` (nested archives to depth 3, `J4S-BC-01`), and emit one JSONL record per class
whose constant pool references a Base64 decoding entry point.

**SPEC-02-24 CLI.** `scan_java4shell_jars.py PATH... [--jsonl FILE] [--quiet]`. Paths may be files or
directories. Summary (records, artifacts, shaded, test) goes to stderr unless `--quiet`.

**SPEC-02-25 Matching.** Owner class is `java/util/Base64` or `java/util/Base64$…`, including relocated copies
whose owner **ends with** `/java/util/Base64` or contains `/java/util/Base64$` (`J4S-BC-02`). Method names:
`getDecoder`, `getUrlDecoder`, `getMimeDecoder`, `decode`, `wrap` (`J4S-BC-03`). Class magic `0xCAFEBABE`
(`J4S-BC-06`). `is_test_artifact` by `J4S-BC-04`; `is_shaded` when class name or entry path contains `shaded`,
`shadow`, `repack`, `reloc` (`J4S-BC-05`).

**SPEC-02-26 JSONL contract (compatible with the Rust `Finding`).**

```json
{"artifact_path": "build/libs/app.jar", "entry_path": "BOOT-INF/lib/x.jar!com/acme/Foo.class",
 "is_test_artifact": false, "is_shaded": false, "class_name": "com.acme.Foo", "method_name": "<init>",
 "method_descriptor": "()V", "invoked_targets": ["java/util/Base64.getDecoder:()Ljava/util/Base64$Decoder;"],
 "constant_strings_sample": ["..."], "evidence_refs": ["bytecode:com.acme.Foo:<init>"]}
```

Nested entries are joined with `!`. The runbook's `j4s_analyzer` MUST accept this file unchanged.

## 7. `gate_cve_2026_114938.py` (runbook §7.1)

**SPEC-02-27 Purpose.** CI/CD policy gate: fail a build or deployment when a vulnerable JDK is pinned, the
mitigation flag is absent from a Java workload, the intrinsic is explicitly re-enabled, or a reachability report
contains `REACHABLE_HIGH`.

**SPEC-02-28 CLI.**

```
gate_cve_2026_114938.py [--jdk-version VER] [--jvm-opts "OPTS"] [--scan-dir DIR] [--reachability-json FILE] [--require-flag]
```

Defaults: `--jdk-version` from `$JDK_VERSION`, `--jvm-opts` from `$JAVA_TOOL_OPTIONS`, `--scan-dir .`. Because
the option value begins with `-`, callers MUST use `--jvm-opts="$JAVA_TOOL_OPTIONS"`.

**SPEC-02-29 Checks.**

| Check | Trigger | Violation prefix |
| :--- | :--- | :--- |
| Explicit version | `--jdk-version` classifies `VULN_RANGE` | `[JDK_VERSION]` |
| JVM options | `--require-flag` and no mitigation in `--jvm-opts`; or `-XX:+UseBASE64Intrinsics` present (`J4S-FLAG-04`) | `[JVM_OPTS]` |
| Dockerfile (`dockerfile`, `dockerfile.*`) | any pinned version `VULN_RANGE`; Java workload without flag | `[Dockerfile:<path>]` |
| Manifest (`*.yaml`, `*.yml` containing `kind:`) | same, when the file mentions a Java workload | `[Manifest:<path>]` |
| Reachability JSON | any finding with `verdict == REACHABLE_HIGH` | `[Reachability:<path>]` |

"Java workload" evidence (`J4S-RT-05`, extended): the words `java`, `jdk`, `jvm`, `JAVA_TOOL_OPTIONS`,
`JDK_JAVA_OPTIONS`, **or** a vendor image name (`corretto`, `temurin`, `zulu`, `liberica`, `sapmachine`,
`graalvm`), **or** any `-XX:` flag. Skipped directories: `.git`, `target`, `node_modules`, `.venv`, `venv`.

**SPEC-02-30 Output.** On failure print `POLICY GATE FAILED (CVE-2026-114938 / Java4Shell):` followed by
`  - <violation>` lines to stderr and exit 1. On success print `POLICY GATE PASSED (CVE-2026-114938 / Java4Shell).`
and exit 0. `report-template/tools/j4s_facts.py` parses exactly this shape (SPEC-06-04).

## 8. Interpreting results (documentation requirement)

**SPEC-02-31.** `scripts/README.md` MUST keep a results-interpretation table mapping every verdict and unknown
label to an action, and MUST point to side effect 09 for the audit footprint and side effect 05 for the cost
of `CAPPED`.
