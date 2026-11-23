# Team / service-owner plan (one service, end to end)

**You own:** one or more services: where they run, how they are built, what they decode, and the proof that they
are mitigated and then patched.
**You receive:** an R3 ticket per service with the verdicts for your hosts, repository and code; the patched base image
from platform; the performance budget from your product owner.
**You deliver:** flag live and verified, untrusted decode sites validated, JDK upgraded and pinned, gate required,
closed ticket with evidence.

## Steps (mirrors R3 §7 and checklist C)

1. **Day 0: know your exposure.** Read R3 §1–§3: which hosts/pods run your service, their CPU class, the JDK version
   status, the flag state, the repository verdict. If the runtime is not in your repo (`UNVERIFIED_NO_PIN`), name
   where it is (platform image, Helm values repo, host JDK) and tell the programme manager.
2. **Day 0: apply the flag** in the runtime definition — Dockerfile `ENV JAVA_TOOL_OPTIONS="-XX:-UseBASE64Intrinsics"`,
   manifest `env`, Helm values, unit file (`helpers/j4s_flag.sh snippet <kind>`). Merge, deploy via canary, then
   fully. For an exposed internet-facing service this happens today, inside the pre-approved window.
3. **Day 0: verify live.** `helpers/j4s_proc.sh flags <pid>` on a host or `helpers/j4s_flag.sh k8s-verify <deploy> -n <ns>`;
   the live state must read `ACTIVE`. Attach the output to the ticket.
4. **Day 0–1: remove re-enables.** Delete any `-XX:+UseBASE64Intrinsics` from manifests, scripts, `JAVA_OPTS`, Actions variables.
5. **Day 1: measure the cost.** Compare CPU and p99 on your Base64-heavy endpoints with the pre-flag baseline (plan 04 §4);
   report against the budget; scale out if needed.
6. **Day 2–5: trace your decoding.** `scripts/scan_java4shell_source.py src --json > src.json`; map every
   `DYNAMIC_UNTRUSTED` site to its touchpoint (plan 03 §1); add validation before decode (length `% 4`, no `===`,
   no `=` inside the body, single alphabet, length cap) with negative tests. Review `DYNAMIC_INTERNAL` sites whose
   producers accept external data.
7. **Day 2–5: scan the artifact.** `scripts/scan_java4shell_jars.py build/libs --jsonl findings.jsonl`; note shaded
   Base64 copies in dependencies (they are reachable too) and plan dependency upgrades.
8. **Week 1–2: upgrade the JDK.** Move to the patched base image or vendor tag (plan 05 §1 table); pin exact tag or
   digest; run the test suite on the new JDK; canary; deploy. Update `.sdkmanrc` / `setup-java` pins in the same PR.
9. **Week 1–2: make it stick.** Add `.github/workflows/cve-2026-114938-gate.yml` (plan 06 §3), ask for it to be a
   required check, upload the source-scan SARIF.
10. **Prove it.** Re-run the host audit (or ask platform) → `PATCHED_OR_SAFE_VERSION`; estate scan → `PATCHED`; gate run
    green. Put the three links in the ticket and close it.
11. **Optionally remove the flag** once every instance of the service can only land on a patched runtime; re-benchmark.
12. **If something crashes or probes appear:** follow plan 09 with the SOC; preserve `hs_err` files; be ready to list
    the secrets your JVM holds in memory for rotation.

## Evidence you attach to the ticket

| Claim | Evidence |
| :--- | :--- |
| Flag live | `j4s_proc.sh flags` / `k8s-verify` output with timestamp |
| Cost measured | before/after CPU and p99 numbers |
| Code hardened | `src.json` after the change; test names |
| Patched | audit JSON row with `PATCHED_OR_SAFE_VERSION`; image digest |
| Durable | gate run URL; branch protection screenshot or `gh_j4s_actions.sh` row |

## Pitfalls specific to teams

- Setting the flag in the Dockerfile and overriding `JAVA_TOOL_OPTIONS` in the manifest with another value.
- Upgrading the build stage but not the runtime stage of a multi-stage Dockerfile.
- Treating the sidecar or init container as "not my JVM".
- Declaring done from the manifest; only the live JVM counts.
