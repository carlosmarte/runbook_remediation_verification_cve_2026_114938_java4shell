# 08 — Observability & Monitoring Plan

**Objective.** See, continuously, four things: whether exposure is drifting back (flag lost, old image redeployed),
whether anyone is probing or exploiting (edge hits, JVM crashes), what the mitigation costs (CPU, latency), and
whether the programme is progressing (coverage metrics). Alert on the first two, dashboard the rest.
**Runbook basis.** §2 (`jcmd`/`jinfo`, health GETs), §4 (WAF metrics), side effects 01, 02, 04, 05, 07.
**Owner.** SRE for metrics and dashboards, SOC for security alerts. **Timing.** basic alerts by T+2 d, full by T+7 d.

## 1. Signals

| Area | Signal | Source | Alert / dashboard |
| :--- | :--- | :--- | :--- |
| Exposure drift | JVM without live flag on a VBMI host where it was mitigated | scheduled `audit_java4shell.py` → `helpers/j4s_inventory.py diff` `regressed` | **alert** (page platform on-call) |
| Exposure drift | new JVM on vulnerable version appears (`new` + `EXPOSED_ON_VBMI_HOST`) | same | alert |
| Exposure drift | Kubernetes workload spec loses the flag | `helpers/j4s_k8s.sh missing` scheduled; admission policy (optional) | alert |
| Exposure drift | repo verdict regresses to `EXPOSED`/`EXPLICITLY_ENABLED` | weekly `gh_j4s_scan.py` diff; gate failures on main | alert to repo owner + security |
| Probing | edge rule hits (count or block) on pre-auth routes | WAF metrics `CVE2026114938AuthHeaderMalformedB64`, `…Body…`; nginx/Envoy logs | **alert** on block-mode hits; dashboard on count |
| Probing | Base64 decode failures per endpoint spike | application metric from the validator (plan 03 §3) | alert when > N× baseline |
| Exploitation | `hs_err_pid*.log` created by a Java service | file watch / log shipper → `helpers/j4s_hs_err.py --json` | **alert** on LIKELY/POSSIBLE (page SOC) |
| Exploitation | JVM restart loops, SIGSEGV in `base64_decode` stub frames | container restarts, kernel logs, APM crash events | alert |
| Cost | CPU, p50/p99, error rate on Base64-heavy endpoints before vs after flag | APM / service metrics tagged with `jvm.flag.base64intrinsics=off` | dashboard + SLO burn alert |
| Cost | `JAVA_TOOL_OPTIONS` propagation: unexpected JVMs printing `Picked up JAVA_TOOL_OPTIONS` | stderr logs | dashboard |
| Programme | exposure rate, mitigation/patch coverage, blocking repos, gate adoption | `report-template/tools/j4s_facts.py` nightly | dashboard, R1 |

## 2. Steps

1. **Schedule the fleet audit** (cron/Ansible/SSM) daily during rollout, weekly after; store JSON by date; run
   `helpers/j4s_inventory.py diff BEFORE... --split AFTER...` and raise an alert when `regressed` or new exposed rows
   are non-empty. Exit code 2 from the helper is the alert trigger.
2. **Schedule the Kubernetes check** (`j4s_k8s.sh missing`) per cluster every few hours during rollout; consider an
   admission policy (OPA/Kyverno) requiring `JAVA_TOOL_OPTIONS` to contain the flag on JVM-like images until patched
   images are mandatory.
3. **Ship `hs_err` files.** Make sure JVMs write `-XX:ErrorFile=/var/log/<svc>/hs_err_pid%p.log` to a shipped path
   (containers: an emptyDir/hostPath that the log agent reads or a preStop hook that uploads). Trigger
   `j4s_hs_err.py` on new files; LIKELY/POSSIBLE opens plan 09.
4. **Instrument decode validation.** Counter `base64_reject_total{route, anomaly}` and histogram of input length;
   alert on rate spikes on pre-auth routes.
5. **Edge metrics and sampling.** Enable WAF sampled requests and metrics; forward nginx/Envoy warn logs to the SIEM;
   alert on block-mode hits, review count-mode hits daily (plan 07).
6. **Performance SLOs.** Tag deployments with the flag state; compare before/after per service (plan 04 §4); alert on
   SLO burn rather than on raw CPU.
7. **Dashboards.** One programme dashboard from nightly `facts.json` (exposure rate, coverage, blocking repos, gate
   adoption, open alerts) and one security dashboard (edge hits by route, crash verdicts, decode rejects).
8. **SIEM correlation rules.** Edge hit on route R → JVM crash on the service behind R within 10 minutes → SEV-1
   incident (plan 09). Decode-reject spike + crash → same.
9. **Test the alerts.** Replay a malformed token (`QUJD====`) against a staging route in count mode; copy a sample
   `hs_err` file into the watched path in staging; verify the pages arrive.
10. **Retention.** Keep audits, traffic analyses and crash triage for the attestation (R9) and for incident timelines.

## 3. Alert definitions (reference)

| Alert | Condition | Severity | Routes to |
| :--- | :--- | :--- | :--- |
| J4S-ExposureRegression | `inventory diff` has `regressed` > 0 or new `EXPOSED_ON_VBMI_HOST` | high | platform on-call, security |
| J4S-K8sFlagMissing | `j4s_k8s.sh missing` returns rows for VBMI node pools | high | platform |
| J4S-EdgeBlock | block-mode hit on pre-auth route | high | SOC |
| J4S-EdgeCountSpike | count-mode hits > 10/min on one route | medium | SOC daily review |
| J4S-CrashLikely | `j4s_hs_err.py` verdict LIKELY | critical | SOC page, incident |
| J4S-CrashPossible | verdict POSSIBLE | high | SOC |
| J4S-DecodeRejectSpike | `base64_reject_total` rate > 5× 7-day baseline on a route | medium | service on-call, SOC |
| J4S-FlagLatencyBurn | p99 SLO burn after flag rollout | medium | service on-call |

## 4. Outputs

| Output | Consumer |
| :--- | :--- |
| Nightly `facts.json` + dashboards | R1, R0 |
| Alert history | R8 timeline, R9 evidence |
| Before/after performance data | R1 §9, plan 04 |

## 5. Exit criteria

- Every alert above exists, has been test-fired, and routes to a named rota.
- Fleet audit and Kubernetes check run on schedule with results stored and diffed.
- `hs_err` files from every Java service reach the triage step.
- Programme dashboard shows the four coverage metrics from nightly facts.

## 6. Pitfalls

- Audits that run as a non-owner report `jcmd-unavailable-or-restricted`, which looks like drift; run as root/owner.
- Health GETs in `verify_java4shell_runtime.sh` confirm liveness, not the flag; do not treat 200 as mitigated.
- Crash files inside ephemeral containers vanish with the pod unless shipped or persisted.
- Count-mode WAF rules produce no blocks by design; a quiet dashboard means nothing until promotion.
