# 10 — Verification & Validation Plan

**Objective.** Define what counts as proof at every step: that a JVM is mitigated, that a version is patched, that a
repository is safe, that a gate is enforced, that an edge rule works, and that the programme can close. Evidence is
machine-produced, dated, diffable and traceable to a host, PID, repo, file or token.
**Runbook basis.** §2 (non-intrusive verification, `jinfo`/`jcmd`), §3 (fleet audit), §8 step 6; side effect 09
(audit footprint).
**Owner.** Security engineering; internal audit as witness at closure.

## 1. Evidence standards

| Claim | Acceptable proof | Not acceptable |
| :--- | :--- | :--- |
| Flag is live on a JVM | `jcmd <pid> VM.flags -all` shows `-XX:-UseBASE64Intrinsics` (or `UseAVX ≤ 2`), run as owner/root; recorded in audit JSON or `j4s_proc.sh flags` output | manifest/Dockerfile text; `ps` output alone; health GET 200 |
| JDK is patched | `java -version` from the mapped `libjvm.so`'s `$JAVA_HOME` (or `$JAVA_HOME/release`) classified `PATCHED_OR_UNAFFECTED`; image digest recorded | tag name alone (`:21-jre`); package manager says "latest" |
| Host not in hardware scope | `/proc/cpuinfo` lacks `avx512_vbmi` or arch is not x86-64, captured in audit `cpu` block | instance type guesswork |
| Repository is safe | `gh_j4s_scan.py` verdict `PATCHED` with the pin and file:line; gate workflow present and required | README statement; a closed ticket |
| Code is hardened | `scan_java4shell_source.py` shows validation call before every `DYNAMIC_UNTRUSTED` decode, or a justification per site; negative tests present | "we reviewed it" |
| Gate is enforced | `gh_j4s_actions.sh` shows `GATE_WORKFLOW` present, `GATE_REQUIRED = yes`, last run `success` | workflow file exists but `continue-on-error` |
| Edge rule works | staged replay of `QUJD====` returns 403 (block) or appears in samples (count); metric increments | config diff |
| No exploitation | crash triage over the window shows no LIKELY/POSSIBLE; edge samples reviewed | absence of complaints |
| Programme closed | R9 with evidence register; `facts.json` showing coverage 100 % or exceptions with expiry | verbal sign-off |

## 2. Steps

1. **Establish the baseline run** at T+0: full fleet audit and estate scan stored under `evidence/T0/`. Everything
   later is diffed against it.
2. **Verify each mitigation change** (plan 04) the same day: re-audit the host (`audit_java4shell.py`) or the workload
   (`j4s_flag.sh k8s-verify`, `j4s_proc.sh flags <pid>`); attach the output to the change record.
3. **Non-intrusive service check** after each change: `scripts/verify_java4shell_runtime.sh --health-url …`
   (GET only; no exploit payloads) plus the service's own smoke tests; compare p99/CPU with the baseline (plan 04 §4).
4. **Before/after diff** weekly: `helpers/j4s_inventory.py diff evidence/<prev>/*.json --split evidence/<now>/*.json`;
   `improved` is progress, `regressed` is an alert (plan 08), `new` needs classification.
5. **Verify each upgrade** (plan 05): audit shows `PATCHED_OR_SAFE_VERSION`; estate scan shows `PATCHED`; image digest
   recorded in the repo; flag removal, if done, re-verified by audit and re-benchmarked.
6. **Verify the gate** (plan 06): intentionally open a PR with `FROM eclipse-temurin:21.0.12_7-jre` in a sandbox repo
   and confirm the required check blocks the merge; record the run URL.
7. **Verify edge rules** (plan 07): staged replay in count then block mode; confirm metrics/samples; confirm a valid
   JWT and a SAML POST still pass.
8. **Verify monitoring** (plan 08): fire each alert with a synthetic condition in staging; record delivery.
9. **Verify code hardening** (plan 03): source scan on the merged branch; negative tests in CI; SARIF shows no open
   `J4S-SRC-04` on pre-auth paths without validation.
10. **Independent spot checks**: a second person re-runs the audit on a random 10 % sample of hosts and 10 % of repos
    with their own credentials; discrepancies are findings.
11. **Closure package**: final `facts.json`, R6, R7, R5, R10, R8 (if any), exceptions register with expiry, side-effect
    measurements, and R9 signed by the risk owner with audit as witness.

## 3. Acceptance criteria per phase (ties to 00-master-plan)

| Phase | Accept when |
| :--- | :--- |
| P1 Assess | ≥ 95 % hosts audited; estate scan complete; unknowns listed with owner |
| P2 Mitigate | `exposed_vbmi = 0`; every `MITIGATED_BY_FLAG` has live `jcmd` proof; no `EXPLICITLY_ENABLED` |
| P3 Protect | edge EDGE-01/02 blocking with 0 FPs over a cycle; alerts test-fired |
| P4 Trace | no `REACHABLE_HIGH`; all untrusted sites validated or justified |
| P5 Patch | `patch_coverage = 100 %` or exceptions; `UNVERIFIED_FLOATING = 0` |
| P6 Gate | `gate_adoption = 100 %`, required and passing |
| P7 Close | R9 signed; retention set; lessons learned recorded |

## 4. Audit footprint and safety (side effect 09)

- The audit spawns `java -version` once per distinct JDK and attaches `jcmd` briefly; run off-peak on
  latency-critical hosts; never on a crash-looping JVM; prefer `j4s_proc.sh` (reads `release` file) on fragile hosts.
- Never send exploit payloads to verify; the staged replay token is sent only to the edge in staging.
- Credentials: read-only tokens for GitHub; root or process owner for `/proc` and `jcmd`; log who ran what.

## 5. Outputs

| Output | Location | Consumer |
| :--- | :--- | :--- |
| Dated evidence directories (`audits`, `estate.json`, `posture.tsv`, `gate.log`, `traffic.json`, `crashes.json`) | evidence store | facts, all reports |
| Change records with verification output | change system | R6, R9 |
| Gate and edge test run URLs | evidence register | R5, R10, R9 |
| Spot-check results | R1 blockers / R9 | audit |

## 6. Exit criteria

- Every claim in the closure package maps to a row in the evidence standards table with a file or run URL.
- Independent spot checks found no discrepancy, or discrepancies were fixed and re-verified.
- R9 signed.
