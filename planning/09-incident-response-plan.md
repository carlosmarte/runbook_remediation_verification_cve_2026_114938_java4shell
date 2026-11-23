# 09 — Incident Response Plan

**Objective.** When monitoring indicates probing or exploitation of CVE-2026-114938, contain within minutes, preserve
evidence, assume heap disclosure, eradicate by mitigation and patch, and recover with verified state.
**Runbook basis.** side effects 01 (DoS/crash) and 02 (JavaBleed), §4 (edge rules), §2 (verification); helpers
`j4s_hs_err.py`, `j4s_b64check.py`, `j4s_proc.sh`.
**Owner.** SOC / incident commander. **Trigger.** any J4S-CrashLikely, J4S-EdgeBlock on a pre-auth route, correlated
decode-reject spike + crash, or external report.

## 1. Severity

| Observation | Severity |
| :--- | :--- |
| LIKELY crash on an internet-facing service with unmitigated JVM on VBMI hardware | SEV-1 (assume RCE attempt; assume heap disclosure) |
| LIKELY crash on an internal service, or POSSIBLE on internet-facing | SEV-2 |
| Edge block hits with no crash, service mitigated | SEV-3 (probing) |
| Count-mode hits only | monitoring event, daily review |

## 2. Steps

### Detect and triage (minutes 0–15)
1. **Collect the crash file(s)** and run `helpers/j4s_hs_err.py /path/hs_err_pid*.log --json > crashes.json`. Read
   verdict, score and reasons: signal, problematic frame (`StubRoutines::base64_decode`), heap-corruption markers,
   JRE version status, flag presence, CPU VBMI.
2. **Pull the edge evidence** for the window: WAF sampled requests, access logs; run
   `helpers/j4s_b64check.py scan access.log --min-len 64 --json > traffic.json` and `headers` on captured headers.
   Note source IPs, routes, timing relative to the crash.
3. **State of the host**: `sudo scripts/audit_java4shell.py --pretty` and `helpers/j4s_proc.sh report` on the affected
   host; confirm whether the JVM was `EXPOSED_ON_VBMI_HOST` at the time.
4. **Declare** severity, open the incident record, start the timeline (R8 §5), inform the programme manager.

### Contain (minutes 15–60)
5. **Apply the flag** to every JVM on the affected hosts/workloads and restart (plan 04 §2); verify live with `jcmd`.
   If the service cannot restart immediately, block the route at the edge first.
6. **Switch edge rules to block** (EDGE-01/02 at least) on the affected routes and, if the attack shape is clear, on
   all pre-auth routes (plan 07 step 5).
7. **Rate-limit or block the source** IPs/ASNs at the edge for the investigation window; expect them to change.
8. **Preserve evidence** with chain of custody: `hs_err` files, heap dumps if any, GC and application logs, container
   images (digest), edge logs/samples, deploy history. Copy to the forensics store before pods are recycled.

### Assess impact (hours 1–8)
9. **Assume JavaBleed.** Out-of-bounds heap writes can corrupt adjacent array lengths and expose heap contents in later
   responses (side effect 02). Enumerate secrets resident in the crashed JVM's heap: JWT signing keys, session
   stores, DB credentials, API keys, cached PII. Decide rotation (step 11) on that list, not on proof of
   exfiltration.
10. **Hunt fleet-wide** for the same token shapes and source IPs across all edge logs for ±72 h; check other services
    behind the same entry points for crashes or restarts in the window; look for follow-on indicators (new
    processes, outbound connections, unexpected child processes of the JVM).

### Eradicate and recover (hours 8–72)
11. **Rotate** the secrets enumerated in step 9; invalidate sessions issued by the affected service during the window
    if session material was in heap.
12. **Patch** the affected services to the baseline (plan 05) ahead of schedule; keep the flag.
13. **Verify** with plan 10: live flag, version, edge rules blocking, alerts quiet; re-run the host audit.
14. **Restore service levels**; remove temporary IP blocks when the attacker activity stops.

### Close
15. **Report**: R8 during the incident, an entry in R1, R0 if SEV-1; R9 at closure.
16. **Lessons learned**: why was the JVM still exposed (flag missing, drift, late inventory); feed fixes into plans
    04, 06 and 08.

## 3. Indicators (reference)

- Requests with Base64 payloads ≥ 64 chars containing `===`, `=` followed by alphabet characters, or a long run
  with a single trailing `=`, on `Authorization`, cookies, SAML/JWT fields or bodies (J4S-EDGE-01..03).
- `SIGSEGV`/`SIGBUS` with problematic frame in `StubRoutines::base64_decode` or `java.util.Base64$Decoder.decode0`;
  `guarantee(...) failed`, `Internal Error (oop.inline.hpp)` and similar heap-corruption markers.
- JVM restart loops on Base64-handling services coinciding with the requests above.
- Decode-reject metric spikes on pre-auth routes.

## 4. Roles

| Role | Does |
| :--- | :--- |
| Incident commander (SOC lead) | severity, timeline, decisions, communications to R0 audience |
| Platform on-call | flag, restarts, host audits, evidence capture |
| Edge on-call | rule promotion, IP blocks, log exports |
| Service owner | secret inventory, rotation, patch PR |
| Security engineering | triage tooling, fleet hunt, attestation evidence |

## 5. Exit criteria

- Affected JVMs `MITIGATED_BY_FLAG` or `PATCHED_OR_SAFE_VERSION` with live confirmation; edge rules blocking on the
  routes involved.
- Secrets from step 9 rotated; sessions invalidated where applicable.
- Fleet hunt complete; no further LIKELY/POSSIBLE crashes for 72 h.
- R8 finalised; timeline and evidence archived.

## 6. Pitfalls

- A `POSSIBLE` verdict on an already-mitigated JVM is usually an unrelated crash; check `mitigation_present` before
  escalating, but still preserve the file.
- Restarting the pod destroys the crash file unless shipped (plan 08 step 3).
- Blocking only the observed IP is not containment; the flag is.
- Declaring "no exploitation" because no shell was seen ignores the heap-disclosure path; rotate anyway.
