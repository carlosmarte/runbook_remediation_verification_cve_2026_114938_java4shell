# 04 — Mitigation Rollout Plan (`-XX:-UseBASE64Intrinsics`)

**Objective.** Make the mitigation flag live on every exposed JVM within the mitigation SLA, remove every explicit
re-enable, measure the cost, and prove it from the running process.
**Runbook basis.** §2 (flag, `JAVA_TOOL_OPTIONS`, `jinfo`/`jcmd`), §8 steps 5–6; side effects 04, 05, 07.
**Owner.** Platform / SRE with service teams. **Timing.** T+4 h to T+2 d.

## 1. Choose the flag

| Option | Effect | Cost | Use |
| :--- | :--- | :--- | :--- |
| `-XX:-UseBASE64Intrinsics` | disables only the Base64 intrinsic | higher CPU on Base64-heavy paths (side effect 04) | default |
| `-XX:UseAVX=0..2` | disables AVX-512 for the whole JVM | broad throughput loss on vector-heavy code (side effect 05) | only when the first flag is unavailable on an exotic build |
| `-XX:+UseBASE64Intrinsics` | **re-enables** the vulnerable path | — | never; remove wherever found (J4S-FLAG-04) |

## 2. Delivery mechanisms (pick per platform; `helpers/j4s_flag.sh snippet <kind>` prints each)

| Platform | Mechanism | Notes |
| :--- | :--- | :--- |
| Docker image | `ENV JAVA_TOOL_OPTIONS="-XX:-UseBASE64Intrinsics"` | survives any entrypoint; the JVM prints `Picked up JAVA_TOOL_OPTIONS` to stderr |
| Kubernetes | `env: - name: JAVA_TOOL_OPTIONS` in the container spec, or `kubectl patch` (`helpers/j4s_flag.sh k8s-apply`, dry-run by default) | per container, not per node |
| Helm | `values.yaml` env block; rendered manifest must show the flag | gate the rendered output |
| systemd | `Environment=JAVA_TOOL_OPTIONS=-XX:-UseBASE64Intrinsics` in a drop-in | `systemctl daemon-reload && restart` |
| Tomcat / app servers | `setenv.sh` `CATALINA_OPTS`, `jvm.options` (Elasticsearch), `*.vmoptions` | prefer the launch option over the global env on shared hosts |
| Build tools | `.mvn/jvm.config`, `org.gradle.jvmargs`, surefire `argLine` | protects build/test JVMs on VBMI runners |
| Fleet-wide host env | `/etc/environment`, profile.d | **last resort**: hits every JVM on the host including unrelated tools (side effect 07) |

Merge, do not overwrite: `JAVA_TOOL_OPTIONS="$(helpers/j4s_flag.sh add "${JAVA_TOOL_OPTIONS:-}")"` keeps existing
options and is idempotent.

## 3. Steps

1. **Order the queue** from plan 01: EXPOSED + internet-facing pre-auth first, then EXPOSED internal, then
   UNVERIFIED on hosts scheduled for hardware moves, then MITIGATED-but-build/test JVMs on VBMI CI runners.
2. **Baseline performance** on each Base64-heavy service before the flag: CPU, p50/p99 latency, error rate on
   auth/token/upload endpoints for ≥ 1 traffic cycle (side effect 04). Store the numbers for R1 §9.
3. **Canary.** Apply the flag to one instance / 5 % of pods; watch the baseline metrics for one cycle; confirm the
   live flag (step 6). Roll back by removing the env and restarting if p99 or CPU exceeds the agreed budget (R0
   decision 2).
4. **Roll out** per service with the platform's normal progressive delivery; for emergency restarts use the
   pre-approved change window.
5. **Remove explicit re-enables.** Every `-XX:+UseBASE64Intrinsics` found by the estate scan, code search, posture
   check (Actions variables) or host audit is deleted first; it overrides any mitigation set elsewhere depending on
   order and defeats the gate.
6. **Verify live, not on paper.** `jcmd <pid> VM.flags -all | grep -i base64` must show `-UseBASE64Intrinsics`;
   `helpers/j4s_proc.sh flags <pid>` shows cmdline/env vs live state; `helpers/j4s_flag.sh k8s-verify` for workloads.
   Run as the process owner or root (plan 10).
7. **Handle shared hosts.** Where several JVMs share a host and only some need the flag, use per-service launch
   options instead of `JAVA_TOOL_OPTIONS`; otherwise accept and document the propagation (side effect 07),
   checking that build agents and CLIs still start.
8. **Handle immutable or vendor runtimes.** Appliances and SaaS-like black boxes: ask the vendor for the flag or
   patch; until then isolate behind edge rules (plan 07) and note the exception (plan 10 §5).
9. **Record** each change: service, mechanism, time, who verified, before/after metrics. These rows become R6 and
   the exceptions register.
10. **Re-audit** the fleet daily until `fleet.exposed_vbmi = 0`; diff against the previous run
    (`helpers/j4s_inventory.py diff`) and treat any regression as a redeploy that lost the flag (plan 08 alert).

## 4. Benchmark protocol (side effect 04/05)

- Same traffic shape before/after (replay or shadow); measure at the JVM (CPU, GC) and at the edge (p99).
- Base64-heavy indicators: JWT validation per request, Basic auth, image/data-URL handling, large JSON with binary
  fields, SAML.
- Budget decided in R0 (e.g., +10 % p99 acceptable for 30 days). Exceeding it is not a reason to skip the flag on an
  exposed service; it is a reason to scale out and to accelerate the patch.
- `-XX:UseAVX` caps cost far more and are reversed as soon as the real flag or the patch is available.

## 5. Rollback

Remove the env/option and restart; the JVM returns to the intrinsic path. Rollback re-exposes the service, so it
is only acceptable with an edge rule in block mode in front and a new attempt scheduled.

## 6. Exit criteria

- `fleet.exposed_vbmi = 0` on the latest full audit; every `MITIGATED_BY_FLAG` row has a live `jcmd` confirmation.
- No `EXPLICITLY_ENABLED` anywhere (hosts, manifests, repos, Actions variables).
- Before/after performance recorded for every Base64-heavy service; budgets respected or escalated.
- Every exception (vendor, immutable) registered with compensating control and expiry.

## 7. Pitfalls

- `JAVA_TOOL_OPTIONS` set in the Dockerfile but overridden by an empty value in the manifest: the live check catches it.
- Flags added after `-jar` are program arguments, not JVM options.
- Quoting: `JAVA_TOOL_OPTIONS=-XX:-UseBASE64Intrinsics` without quotes is fine; the runbook's original detector
  missed the `=` delimiter (J4S-FLAG-02 note), the toolkit does not.
- Sidecars and init containers are separate JVMs; patch their specs too.
