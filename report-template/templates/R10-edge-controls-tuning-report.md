{{! ============================================================================
R10 - Edge / WAF Compensating Controls Tuning Report
Audience : Edge/network security engineers, API platform owners, SOC
SDLC     : operate (compensating control lifecycle: count -> block -> retire)
Cadence  : after each traffic cycle in count mode; weekly in block mode; at retirement
Inputs   : --b64 traffic.json (helpers/j4s_b64check.py scan --json over edge logs / WAF samples); --extra edge{} with rules[], routes[], fp_samples[]
============================================================================ }}
# {{meta.cve}} ({{meta.alias}}) — Edge Controls Tuning Report

{{meta.org}} · {{meta.scope}} · {{meta.report_date}} · period {{meta.period}} · mode **{{extra.edge.mode|default:count}}**

## 1. Purpose

The nginx / Envoy / AWS WAF rules from runbook §4 detect **malformed trailing padding** in Base64-looking payloads of 64+ characters on `Authorization` headers and request bodies. They are a temporary control that buys time for the flag and the patch; they must start in count/log mode because legitimate JWTs, SAML assertions and form posts can trip them (`docs/side-efforts/06`).

## 2. What the traffic shows

{{#if traffic.available}}
| Measure | Value |
| :--- | ---: |
| Tokens analysed (≥ 64 chars) | {{traffic.tokens}} |
| Suspicious (anomaly or EDGE-01/02 without strict validity) | **{{traffic.suspicious}}** |
| J4S-EDGE-01 — three or more `=` | {{traffic.edge01}} |
| J4S-EDGE-02 — `=` followed by alphabet characters | {{traffic.edge02}} |
| J4S-EDGE-03 — long run with a single terminal `=` | {{traffic.edge03}} |
| JWT-like tokens among hits | {{traffic.jwt_like}} |

EDGE-01 and EDGE-02 have no legitimate reading: a valid Base64 string never contains `===` or padding inside the body. EDGE-03 is a heuristic and the main source of false positives; keep it in count mode until the samples below are reviewed.

### Sample of suspicious tokens

| Log line | Token (truncated) | Length | Pads | Rules | Anomalies | JWT-like |
| :--- | :--- | ---: | ---: | :--- | :--- | :--- |
{{#each traffic.rows}}
| {{.line}} | `{{.token|md}}` | {{.length}} | {{.pad_count}} | {{.edge_rules}} | {{.anomalies|md}} | {{.jwt|yesno}} |
{{/each}}
{{else}}
_No traffic analysis supplied. Export WAF sampled requests or access logs for the period and run `helpers/j4s_b64check.py scan FILE --min-len 64 --json`._
{{/if}}

## 3. Rule status per deployment

| Deployment | Rule | Mode | Hits (period) | Blocked | Confirmed false positives | Decision |
| :--- | :--- | :--- | ---: | ---: | ---: | :--- |
{{#each extra.edge.rules}}
| {{.deployment}} | {{.rule}} | {{.mode}} | {{.hits}} | {{.blocked}} | {{.false_positives}} | {{.decision}} |
{{/each}}
{{#if extra.edge.rules}}{{else}}| nginx api.example.com | `cve-2026-114938.conf` map (EDGE-01/02/03) | count | | | | |
| Envoy ingress | Lua filter auth + body | log | | | | |
| AWS WAFv2 | `Java4ShellMalformedBase64PatternSet` header + body | COUNT | | | | |{{/if}}

## 4. False-positive review

| Route / client | What tripped | Rule | Legitimate? | Fix |
| :--- | :--- | :--- | :--- | :--- |
{{#each extra.edge.fp_samples}}
| {{.route}} | `{{.sample|md}}` | {{.rule}} | {{.legit|yesno}} | {{.fix}} |
{{/each}}
{{#if extra.edge.fp_samples}}{{else}}| | _e.g. SAML POST with line-wrapped Base64 (MIME) → EDGE-03_ | | | scope the body rule to routes that never carry SAML, or exempt `Content-Type: application/x-www-form-urlencoded` with `SAMLResponse` |
| | _e.g. URL-safe JWT with trailing `=` from a legacy client_ | | | allow `[A-Za-z0-9_-]` alphabet before the single pad |{{/if}}

## 5. Promotion criteria (count → block)

- EDGE-01 and EDGE-02: promote to block when zero legitimate hits over one full traffic cycle (24 h incl. batch windows).
- EDGE-03: promote only per route, after the route owner confirms no MIME-wrapped or legacy-padded clients.
- Keep `Authorization` header rules and body rules independently switchable; bodies > 1 MiB stay in `CONTINUE`/pass-through (EDGE-05).
- Every block in production must emit a metric (`CVE2026114938AuthHeaderMalformedB64`, `…BodyMalformedB64`) and a sampled request for review.

## 6. Retirement criteria

Retire the rules when the fleet report (R6) shows patch coverage 100% **and** the GitHub estate (R7) shows no `EXPOSED`/`MITIGATED_FLAG` repositories, or when the business accepts the residual risk in R9. Until then the rules stay, even after the flag is live everywhere, because the flag can be lost on redeploy.

## 7. Actions

{{#each actions}}
{{@index}}. {{.}}
{{/each}}
