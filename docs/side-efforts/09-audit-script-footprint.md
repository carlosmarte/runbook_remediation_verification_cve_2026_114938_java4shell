# 09 — Audit and Verification Script Footprint on Production Hosts

**Origin:** verification tooling (runbook §2 `verify_java4shell_runtime.sh`, §3 `audit_java4shell.sh` / `.py`)
**Impact:** Low. **Likelihood:** High; the scripts are meant to be run everywhere.

## What happens

The scripts are described as non-intrusive because they send no exploit payloads, but they do
touch running systems in ways that have small, real costs:

- **`jcmd <pid> VM.flags -all` / `jinfo`** use the dynamic attach mechanism. The target JVM pauses briefly at a safepoint to service the request, and the attach listener creates a `.java_pid<pid>` socket in the JVM's temp directory. On JVMs started with `-XX:+DisableAttachMechanism` the call fails; on JVMs under a different user the runbook correctly refuses unless running as that user or root (`runuser`).
- **`java -version` on every discovered `JAVA_HOME/bin/java`** spawns a short-lived JVM per inspected process. On a host with many JVMs this is a CPU and memory blip, and each one prints the `JAVA_TOOL_OPTIONS` banner (effect 07).
- **`docker exec <cid> sh -c 'java -version'`** executes a new process inside every running container, including ones that are CPU-throttled or scratch-based (where `sh` does not exist and the step returns `no-shell-or-java`). It also shows up in container audit logs as exec activity.
- **`/proc/<pid>/environ` reads** expose the full environment of every JVM to the script's output, which can include secrets passed as env vars. The script filters to the three JVM option variables before printing, but the raw read requires the same user or root, so it is typically run privileged.
- **`kubectl get pods -A -o json`** pulls the entire pod inventory from the API server, which is heavy on large clusters.
- **Health checks** (`--health-url`) are GET-only and bounded by a 5 second timeout, but they count against rate limits and can be mistaken for synthetic traffic.

## Who feels it

- SRE / platform teams running the audit fleet-wide during the incident.
- Security and audit teams reviewing `docker exec` and attach events.
- Latency-sensitive JVMs that experience the attach safepoint.

## How to detect it

- Brief GC-log safepoint entries with `AttachListener` reason at the audit timestamp.
- Short-lived `java -version` processes and `.java_pid*` files in `/tmp` (or the JVM's `-Djava.io.tmpdir`).
- Container runtime exec events correlated with the audit window.

## How to limit it

- Run off-peak and as the process owner where possible, so `runuser` and privilege escalation are not needed.
- Prefer reading the version from the `libjvm.so` path's `release` file (`$JAVA_HOME/release`) before spawning `java -version`; fall back only when the file is missing.
- Skip `docker exec` when the process-level inspection already resolved a version (the bash audit runs both).
- Scope `kubectl` with `--k8s-namespace` / `--k8s-selector` rather than `-A` on large clusters.
- Store output with the same sensitivity as process environments; redact before sharing.
- Treat `jcmd-unavailable-or-restricted` as "unknown", not "mitigated"; re-check via command line and env (`J4S-FLAG-02`, `J4S-FLAG-08`).

## Runbook and pattern references

- Runbook §2 (`query_live_jcmd`, `inspect_proc_jvm`, Docker/K8s/health sections), §3.
- Patterns: `J4S-RT-01`, `J4S-RT-02`, `J4S-RT-06`, `J4S-FLAG-08`, `J4S-FLAG-09`, `J4S-VER-03`.
