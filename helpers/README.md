# Helpers — CVE-2026-114938 ("Java4Shell")

Small, self-contained, callable building blocks for remediation, detection, investigation, and
reporting. Every helper is both a CLI and a library: Bash files can be `source`d for their
functions, Python files can be imported. No dependencies beyond Bash 3.2+ and Python 3.10+
standard library (`j4s_k8s.sh` and the flag helper's `k8s-*` commands need `kubectl`).

The detection scripts live in `../scripts/`; these helpers wrap, feed, and consume them.
`j4s` is the single entry point for both.

| Helper | Phase | What it gives you |
| :--- | :--- | :--- |
| `j4s` | all | One CLI: `j4s verify`, `j4s scan-src`, `j4s flag add`, `j4s report` … (`j4s help`) |
| `j4s_flag.sh` | remediation | `has` / `add` / `remove` the mitigation flag idempotently; ready-to-paste `snippet`s for Dockerfile, Compose, Kubernetes env or patch, systemd, Helm, Tomcat, Gradle, Maven, shell; `k8s-apply` (dry-run by default) and `k8s-verify` |
| `j4s_version.py` | remediation / detection | Classify any JDK version string or `java -version` output against the patched baselines; print the baseline table; `baseline 21` → `21.0.13.1` |
| `j4s_proc.sh` | investigation | Per-PID facts on a Linux host: is it a JVM, cmdline, JVM env vars, resolved `JAVA_HOME`, exact version (from `$JAVA_HOME/release`, no JVM spawn), command-line vs live `jcmd` flag state, container cgroup |
| `j4s_k8s.sh` | investigation | Read-only cluster inventory: JVM-like containers with flag status and image version classification, distinct images, workloads missing the flag, node arch |
| `j4s_b64check.py` | investigation / detection | Explain why a Base64 token is malformed (excess padding, padding inside body, mixed alphabet …), strict RFC 4648 validation for application filters, scan logs/HAR/headers for the trigger shape, map hits to edge rule IDs |
| `j4s_hs_err.py` | investigation | Triage `hs_err_pid*.log`: signal, problematic frame, Base64 stub frames, heap-corruption markers, JRE version status, CPU VBMI, flag in `jvm_args` → LIKELY / POSSIBLE / UNLIKELY with reasons |
| `j4s_inventory.py` | reporting | Merge per-host audit JSON into one CSV/JSON, rank worst-first, per-host summary, and `diff` before/after runs to show progress and regressions |
| `j4s_report.py` | reporting | One Markdown / JSON / HTML status report from audits, jar scan, source scan, gate output, crash triage, and traffic probes, with a RED / AMBER / GREEN status and concrete action list |

## Typical flows

```bash
export PATH="$PWD/helpers:$PATH"

# Investigate one host
j4s proc cpu
j4s proc report                          # every JVM on the box
j4s proc flags 12345                     # one PID: cmdline/env vs live jcmd state

# Is this crash Java4Shell?
j4s hs-err /var/log/app/hs_err_pid*.log

# Did someone probe us? (WAF samples, access logs, request dumps)
j4s b64 scan /var/log/nginx/access.log --min-len 64
j4s b64 token 'QUJD====' 'eyJhbGciOi...'
j4s b64 headers < captured-headers.txt

# Remediate
j4s flag add "$JAVA_TOOL_OPTIONS"                        # -> new value to export
j4s flag snippet k8s-patch
j4s flag k8s-apply payments-api -n prod -c app           # prints the kubectl patch; add --yes to run
j4s flag k8s-verify payments-api -n prod

# Which versions do we need?
j4s version classify 17.0.9 21.0.12_7 25.0.5.1 8u511b33-perf
j4s version table

# Report across the fleet
for h in $(cat hosts.txt); do ssh "$h" 'sudo python3 -' < scripts/audit_java4shell.py > "audits/audit-$h.json"; done
j4s inventory summary audits/*.json
j4s inventory rank audits/*.json --top 20
j4s inventory diff audits-before/*.json --split audits/*.json
j4s report --audit audits/*.json --jars findings.jsonl --source src.json --gate gate.log -o status.md
```

## Library use

```bash
source helpers/j4s_flag.sh
JAVA_TOOL_OPTIONS="$(j4s_flag_add "${JAVA_TOOL_OPTIONS:-}")"; export JAVA_TOOL_OPTIONS

source helpers/j4s_proc.sh
for pid in $(j4s_list_jvm_pids); do echo "$pid $(j4s_pid_flag_state "$pid")"; done
```

```python
import sys; sys.path.insert(0, "helpers")
from j4s_version import classify, from_java_version_output
from j4s_b64check import analyze, is_strictly_valid
from j4s_hs_err import triage
from j4s_inventory import load_audits, rows_from_audits, diff_rows
from j4s_report import build_report, render_markdown

if not is_strictly_valid(token):        # application-side guard before Base64.getDecoder().decode()
    reject()
```

## Exit codes

All helpers return `0` when nothing needs attention and `2` when they found something that does
(a vulnerable version, a suspicious token, a LIKELY/POSSIBLE crash, exposed JVMs, a regression,
a RED report). `1` is an execution error. This makes them usable directly in CI and cron checks.

## Version logic

Every helper that reasons about versions uses the same rule: compare up to five numeric
components lexicographically against `17.0.21.0.3`, `21.0.13.1`, `25.0.5.1`, `27.0.1.1`;
treat 18–20, 22–24, 26 as EOL with no patch; treat Oracle `8u511b33-perf` as vulnerable;
treat anything ≤ 16 as unaffected; ignore `_N`, `+N`, and `-suffix` qualifiers. This fixes the
two parser gaps documented in `../patterns/J4S-VER-01.md`.

Side effects of running the investigation helpers on production hosts (attach safepoints,
spawned JVMs) are described in `../docs/side-efforts/09-audit-script-footprint.md`;
`j4s_proc.sh` avoids spawning a JVM when `$JAVA_HOME/release` is readable.
