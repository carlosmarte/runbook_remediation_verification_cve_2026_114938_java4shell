# Detection Scripts — CVE-2026-114938 ("Java4Shell")

Self-contained, runnable detection and verification scripts extracted from
`../cve_2026_114938_java4shell_remediation_verification_runbook.md`. No third-party
dependencies: Bash 4+ and Python 3.10+ standard library only. None of them send exploit
payloads.

| Script | Purpose | Runbook § | Platform | Needs |
| :--- | :--- | :--- | :--- | :--- |
| `verify_java4shell_runtime.sh` | Non-intrusive live check: CPU VBMI flags, Docker containers, host JVMs, optional Kubernetes pods, live JVM flags via `jcmd`, optional GET health checks | §2 | Linux | bash, coreutils; optional docker, kubectl+python3, jcmd, curl |
| `audit_java4shell.sh` | Fleet audit, text output: JVM processes with version status, flag status, and risk verdict; Docker containers | §3.1 | Linux | bash, coreutils; optional docker |
| `audit_java4shell.py` | Same audit as structured JSON (`--pretty`) | §3.2 | Linux | python3; optional docker |
| `scan_java4shell_source.py` | Source scan: finds `java.util.Base64` decode call sites, classifies input provenance (`CONSTANT` / `DYNAMIC_INTERNAL` / `DYNAMIC_UNTRUSTED`), flags pre-auth context; JSON and SARIF output | §6, §7.3 | any | python3 |
| `scan_java4shell_jars.py` | Bytecode scan of `.class/.jar/.war/.ear/.zip` (nested to depth 3): constant-pool references to Base64 decoding, shaded copies, test artifacts; JSONL compatible with the runbook's Rust `j4s-extract` | §5 | any | python3 |
| `gate_cve_2026_114938.py` | CI/CD policy gate: JDK version ranges in Dockerfiles and manifests, mitigation flag presence, optional reachability JSON | §7.1 | any | python3 |

## Quick start

```bash
chmod +x scripts/*.sh scripts/*.py

# 1. Is this host exposed right now?  (run as root or the JVM owner for live flags)
sudo scripts/verify_java4shell_runtime.sh --k8s --health-url https://svc.internal/health

# 2. Fleet audit, machine-readable
sudo scripts/audit_java4shell.py --pretty > java4shell-audit.json

# 3. Where does our code decode Base64, and from what?
scripts/scan_java4shell_source.py ./src --sarif java4shell-source.sarif
scripts/scan_java4shell_source.py ./src --min-kind DYNAMIC_UNTRUSTED     # only the ones that matter

# 4. What about built artifacts and third-party jars?
scripts/scan_java4shell_jars.py build/libs ~/.m2/repository --jsonl findings.jsonl

# 5. Gate a repo before deploy
scripts/gate_cve_2026_114938.py --scan-dir . --require-flag --jvm-opts="$JAVA_TOOL_OPTIONS"   # note '=': the value starts with '-'
scripts/gate_cve_2026_114938.py --scan-dir . --reachability-json reachability-findings.json
scripts/gate_cve_2026_114938.py --jdk-version 21.0.12_7      # single version check
```

## Exit codes

| Script | 0 | 1 | 2 |
| :--- | :--- | :--- | :--- |
| `verify_java4shell_runtime.sh` | ran | — | usage error |
| `audit_java4shell.sh` / `.py` | ran (read the verdicts) | error | — |
| `scan_java4shell_source.py` | no `DYNAMIC_UNTRUSTED` | error | `DYNAMIC_UNTRUSTED` findings |
| `scan_java4shell_jars.py` | no findings | error | findings |
| `gate_cve_2026_114938.py` | gate passed | gate failed | — |

## Deviations from the runbook text

The runbook's version regex and 4-field comparison mis-handle two real-world tag shapes
(verified 2026-11-20, see `../patterns/J4S-VER-01.md`). All three version-aware scripts here
use a lexicographic comparison over up to five components instead, with a trailing `_N` or
`+N` qualifier ignored:

| Input | Runbook result | These scripts |
| :--- | :--- | :--- |
| `17.0.21.0.3` (patched baseline) | `VULN_RANGE` (read as `17.0.21.0`) | `PATCHED_OR_UNAFFECTED` |
| `17.0.21.0.2` | `VULN_RANGE` | `VULN_RANGE` |
| `21.0.12_7` (Temurin tag) | not matched | `VULN_RANGE` |
| `21.0.13.1_9` | `21.0.13` → `VULN_RANGE` | `PATCHED_OR_UNAFFECTED` |

`verify_java4shell_runtime.sh` also accepts `=` as the delimiter before the flag. The runbook's
`classify_flag_text` only accepted whitespace or a quote, so a mitigation delivered through an
unquoted `JAVA_TOOL_OPTIONS=-XX:-UseBASE64Intrinsics` in the process environment was reported as
`NOT_SET_ON_CMDLINE_OR_ENV` (see `../patterns/J4S-FLAG-02.md`).

Three further deliberate deviations:

- `gate_cve_2026_114938.py` also fails on `-XX:+UseBASE64Intrinsics` (explicit re-enable, pattern
  `J4S-FLAG-04`), and treats vendor image names (`corretto`, `temurin`, `zulu`, `liberica`,
  `sapmachine`, `graalvm`) and any `-XX:` flag as evidence of a Java workload. The runbook's
  manifest check only looked for the words `java`/`jdk`/`jvm` and so skipped a bare
  `image: amazoncorretto:17.0.9`.
- `scan_java4shell_source.py` classifies a string literal or `SCREAMING_CASE` constant argument as
  `CONSTANT` even when the enclosing method also reads headers; the runbook promoted it to
  `DYNAMIC_UNTRUSTED`. Its context window is the enclosing method (approximated by the nearest
  method declaration) rather than a fixed 15 lines back and 5 forward, and the decode argument is
  captured with balanced parentheses so `dec.wrap(in).read()` yields `in`, not `in).read(`.
- `audit_java4shell.py` reports a note instead of crashing when `/proc` is absent (macOS, Windows).

Everything else is the runbook's logic. The Rust extractor and the multi-module Python
analyzer are not copied; `scan_java4shell_jars.py` and `scan_java4shell_source.py` cover
their detection roles in single files. For full reachability verdicts with dependency
chains and runtime context, use the runbook's `j4s_analyzer` on the JSONL these produce.

## Interpreting results

- `HIGH_EXPOSURE` / `EXPOSED_ON_VBMI_HOST`: unpatched JDK, no mitigation flag, CPU has `avx512_vbmi`. Fix now.
- `CHECK_CPU_AND_PATCH` / `UNVERIFIED_ON_HOST`: vulnerable version, flag missing, but this CPU is not VBMI. Patch before the workload moves.
- `MITIGATED_BY_FLAG` / `ACTIVE` / `CAPPED`: `-XX:-UseBASE64Intrinsics` or `-XX:UseAVX=0..2` is live. Note `CAPPED` has a broad performance cost (`../docs/side-efforts/05-*.md`).
- `EXPLICITLY_ENABLED`: someone set `-XX:+UseBASE64Intrinsics`. Remove it.
- `jcmd-unavailable-or-restricted` / `different-owner`: live flags unknown; rerun as the process owner or root.

Side effects of running these on production hosts are documented in
`../docs/side-efforts/09-audit-script-footprint.md`.
