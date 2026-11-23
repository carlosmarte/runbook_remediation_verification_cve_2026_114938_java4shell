# 07 — Edge Compensating Controls Plan

**Objective.** Put a temporary detection/blocking layer in front of Java services for malformed-padding Base64
payloads while the fleet is being mitigated and patched; tune it so it does not block legitimate logins; retire
it deliberately.
**Runbook basis.** §4.1 nginx, §4.2 Envoy, §4.3 AWS WAFv2; patterns J4S-EDGE-01..05; side effect 06.
**Owner.** Edge / network security with API owners and SOC. **Timing.** count mode T+8 h, block mode T+2–7 d, retire at
closure.

## 1. What the rules detect

| Pattern | Regex idea | Legitimate occurrence? |
| :--- | :--- | :--- |
| J4S-EDGE-01 | three or more `=` | never in valid Base64 |
| J4S-EDGE-02 | `=` followed by alphabet characters (padding inside the body) | never in a single valid token; can occur when two tokens are concatenated (`a==b…`) |
| J4S-EDGE-03 | run of 64+ chars ending in a single `=` | yes: valid tokens with one pad; MIME-wrapped SAML; legacy URL-safe clients |
| J4S-EDGE-04 | selector: `Authorization: Basic|Bearer` ≥ 64 chars | selector only |
| J4S-EDGE-05 | body size window ≥ 64 B, ≤ 1 MiB | bodies above the window pass through |

EDGE-01/02 are safe to block early; EDGE-03 is the false-positive source.

## 2. Steps

1. **Map entry points** that terminate traffic for Java services: public load balancers/WAF, API gateways,
   ingress controllers, service mesh. Use the pre-auth touchpoint list from plan 03 (or architecture knowledge at
   T+8 h) to know which routes carry Basic/JWT/SAML/upload traffic.
2. **Deploy in count/log mode** on every public entry point: nginx `cve-2026-114938.conf` with
   `set $block_cve_2026_114938 0`, Envoy Lua filter with `logWarn` only, AWS WAFv2 rules with `Action: Count`.
   Enable sampled requests and metrics (`CVE2026114938AuthHeaderMalformedB64`, `…BodyMalformedB64`).
3. **Collect one full traffic cycle** (24 h incl. batch windows). Export sampled requests / access logs and analyse
   with `helpers/j4s_b64check.py scan FILE --min-len 64 --json > traffic.json` and `headers` for captured headers.
4. **Review hits** (R10 §4): classify each as attack-shaped (EDGE-01/02, anomalies) or legitimate (SAML POST with
   line wraps, multipart with data URLs, legacy clients). Record route, client, rule.
5. **Promote EDGE-01/02 to block** on all routes once a cycle shows zero legitimate hits. Keep metrics and sampling.
6. **Promote EDGE-03 per route** only where the owner confirms no MIME-wrapped or single-pad legitimate traffic;
   otherwise scope it: exclude SAML ACS routes, exempt `multipart/form-data`, use the body size window (EDGE-05),
   allow the URL-safe alphabet before a single pad.
7. **Keep header and body rules independently switchable**; bodies over 1 MiB stay `CONTINUE`/pass-through.
8. **Wire alerts** (plan 08): block-mode hits on pre-auth routes page the SOC; count-mode hits feed the daily review.
9. **Re-check after each tuning change** with another cycle; document the rule state per deployment in R10 §3.
10. **Retire** when R6 shows patch coverage 100 % and R7 shows no `EXPOSED`/`MITIGATED_FLAG` repositories, or when the
    residual risk is accepted in R9. Until then the rules stay even with the flag live everywhere, because a redeploy
    can drop the flag.

## 3. Reference configurations (runbook §4)

- nginx: `map $http_authorization` selectors + `access_by_lua_block` body check; `return 403` behind the
  `$block_cve_2026_114938` switch.
- Envoy: `envoy.filters.http.lua` with `has_malformed_b64()` over `authorization` / `proxy-authorization` and the
  buffered body (64 B – 1 MiB); uncomment `respond({[":status"]="403"})` to block.
- AWS WAFv2: regex pattern set `Java4ShellMalformedBase64PatternSet`; rules on `SingleHeader authorization` and `Body`
  with `OversizeHandling: CONTINUE`; switch `Action` from `Count` to `Block`.

## 4. Outputs

| Output | Consumer |
| :--- | :--- |
| Rule state per deployment (mode, hits, blocked, false positives, decision) | R10 §3 |
| `traffic.json` per cycle | facts, R8, R10 |
| False-positive register with fixes | R10 §4 |
| Alert definitions | plan 08 |

## 5. Exit criteria

- EDGE-01/02 blocking on every public entry point with 0 confirmed false positives over a cycle.
- EDGE-03 blocking or consciously left in count mode per route, with the reason recorded.
- Metrics and sampled requests retained for the incident plan.
- Retirement decision recorded with the evidence that justified it.

## 6. Pitfalls

- Blocking SAML or legacy JWT traffic locks users out; count mode first is not optional (side effect 06).
- Rules protect only traffic that passes the edge; internal queues, files and client tools are not covered (side
  effect 03) and still need the flag and patch.
- Base64 inside JSON strings in large bodies is not seen when the body exceeds the size window; that is a conscious
  trade-off, not a bug.
