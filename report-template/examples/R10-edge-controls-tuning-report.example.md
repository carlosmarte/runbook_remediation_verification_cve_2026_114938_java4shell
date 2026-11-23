# CVE-2026-114938 (Java4Shell) — Edge Controls Tuning Report

Acme Corp (fictional example) · Payments, Identity and Finance Ops production · 2026-11-24 · period 2026-11-17 to 2026-11-24 · mode **count (block on /authorize only)**

## 1. Purpose

The nginx / Envoy / AWS WAF rules from runbook §4 detect **malformed trailing padding** in Base64-looking payloads of 64+ characters on `Authorization` headers and request bodies. They are a temporary control that buys time for the flag and the patch; they must start in count/log mode because legitimate JWTs, SAML assertions and form posts can trip them (`docs/side-efforts/06`).

## 2. What the traffic shows

| Measure | Value |
| :--- | ---: |
| Tokens analysed (≥ 64 chars) | 5 |
| Suspicious (anomaly or EDGE-01/02 without strict validity) | **3** |
| J4S-EDGE-01 — three or more `=` | 1 |
| J4S-EDGE-02 — `=` followed by alphabet characters | 1 |
| J4S-EDGE-03 — long run with a single terminal `=` | 1 |
| JWT-like tokens among hits | 1 |

EDGE-01 and EDGE-02 have no legitimate reading: a valid Base64 string never contains `===` or padding inside the body. EDGE-03 is a heuristic and the main source of false positives; keep it in count mode until the samples below are reviewed.

### Sample of suspicious tokens

| Log line | Token (truncated) | Length | Pads | Rules | Anomalies | JWT-like |
| :--- | :--- | ---: | ---: | :--- | :--- | :--- |
| 48213 | `QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIz…` | 76 | 4 | J4S-EDGE-01 | excess_padding | no |
| 48214 | `QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIz…` | 75 | 1 | J4S-EDGE-02 | padding_inside_body | no |
| 48219 | `QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIz…` | 89 | 1 | J4S-EDGE-03 | length_not_multiple_of_4 | no |

## 3. Rule status per deployment

| Deployment | Rule | Mode | Hits (period) | Blocked | Confirmed false positives | Decision |
| :--- | :--- | :--- | ---: | ---: | ---: | :--- |
| nginx api.acme.example | map $http_authorization (EDGE-01/02/03) | block on /authorize, count elsewhere | 3 | 2 | 0 | promote EDGE-01/02 to block on all routes 2026-11-26 |
| Envoy internal mesh | Lua filter auth + body | log | 0 | 0 | 0 | keep log mode |
| AWS WAFv2 public ALB | Java4ShellMalformedBase64PatternSet | COUNT | 11 | 0 | 8 | EDGE-03 body rule too noisy on SAML POST; scope to non-SAML routes |

## 4. False-positive review

| Route / client | What tripped | Rule | Legitimate? | Fix |
| :--- | :--- | :--- | :--- | :--- |
| /saml/acs | `SAMLResponse=PHNhbWxwOlJlc3Bvbn...Pg== (MIME line-wrapped)` | J4S-EDGE-03 | yes | exclude /saml/acs from the body rule; SAML is validated by the IdP signature |
| /api/v1/files | `multipart body containing base64 image with trailing =` | J4S-EDGE-03 | yes | size window: skip bodies > 64 KiB (EDGE-05) |

## 5. Promotion criteria (count → block)

- EDGE-01 and EDGE-02: promote to block when zero legitimate hits over one full traffic cycle (24 h incl. batch windows).
- EDGE-03: promote only per route, after the route owner confirms no MIME-wrapped or legacy-padded clients.
- Keep `Authorization` header rules and body rules independently switchable; bodies > 1 MiB stay in `CONTINUE`/pass-through (EDGE-05).
- Every block in production must emit a metric (`CVE2026114938AuthHeaderMalformedB64`, `…BodyMalformedB64`) and a sampled request for review.

## 6. Retirement criteria

Retire the rules when the fleet report (R6) shows patch coverage 100% **and** the GitHub estate (R7) shows no `EXPOSED`/`MITIGATED_FLAG` repositories, or when the business accepts the residual risk in R9. Until then the rules stay, even after the flag is live everywhere, because the flag can be lost on redeploy.

## 7. Actions

1. Apply -XX:-UseBASE64Intrinsics to 1 exposed JVM(s) on VBMI hosts now (JAVA_TOOL_OPTIONS or launch args) and confirm with jcmd VM.flags.
2. Set JAVA_TOOL_OPTIONS=-XX:-UseBASE64Intrinsics in the runtime definition of 1 repositor(ies) and open upgrade PRs to 17.0.21.0.3+ / 21.0.13.1+ / 25.0.5.1+ / 27.0.1.1+.
3. Remove every -XX:+UseBASE64Intrinsics (J4S-FLAG-04) from manifests, start scripts and Actions variables.
4. Patch 1 JVM(s) on vulnerable versions that sit on non-VBMI CPUs before workloads move to Ice Lake / Zen 4 class hardware.
5. Schedule JDK upgrades for the 1 JVM(s) and 1 repositor(ies) that rely on the flag; keep the flag until java -version shows the baseline.
6. Resolve 1 floating image/package pin(s) to exact versions (docker run IMAGE java -version) and pin digests.
7. Locate the runtime for 1 Java repositor(ies) without a pin (platform image, host JDK, Helm values repo) and audit it with verify_java4shell_runtime.sh.
8. Add strict Base64 validation (length multiple of 4, no mid-string '=', at most two pads) before the 2 untrusted decode call site(s).
9. Add gate_cve_2026_114938.py to the pipelines of 3 Java repositor(ies) and make the check required on the default branch.
10. Resolve 4 CI gate violation(s) before the next release.
11. Treat LIKELY/POSSIBLE crash files as exploitation attempts: preserve hs_err and heap dumps, rotate secrets resident in those JVMs, correlate with edge hits.
12. Move edge rules J4S-EDGE-01/02 from count to block for routes that received suspicious tokens; keep EDGE-03 in count mode until false positives are tuned.
