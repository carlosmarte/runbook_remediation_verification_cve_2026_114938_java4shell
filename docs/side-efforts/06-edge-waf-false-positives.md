# 06 — Legitimate Requests Blocked by Edge / WAF Rules

**Origin:** compensating controls (runbook §4: nginx, Envoy, AWS WAFv2)
**Impact:** High when enforced (authentication and API failures). **Likelihood:** High until tuned; the runbook requires a count / log-only phase for this reason.

## What happens

The edge rules look for Base64-like runs of 64+ characters with suspicious padding:

| Pattern | Intent | Common legitimate match |
| :--- | :--- | :--- |
| `J4S-EDGE-01` `={3,}` | three or more `=` | Query strings and form bodies (`a==b===c`), Markdown/table content, some encrypted blobs |
| `J4S-EDGE-02` `=[A-Za-z0-9+/_-]{1,64}` | `=` followed by alphabet | **Any `key=value` pair** in a form post or query string; URL-encoded JSON; cookies |
| `J4S-EDGE-03` long run + single `=` | one trailing pad | Perfectly valid Base64 that happens to need one `=` pad, inside a longer token or body |
| `J4S-EDGE-04` `(Basic\|Bearer)\s+[...]{64,}` | header selector | All long Bearer tokens, which then flow into the rules above |

Because `J4S-EDGE-02` matches the `=` in ordinary form fields, enforcing the body rules on
`application/x-www-form-urlencoded` endpoints will block logins and form submissions. JWTs use the
URL-safe alphabet without padding, but a JWT embedded in a larger body alongside `=`-bearing fields
will still trip the rules. SAML responses are long Base64 with padding and will match
`J4S-EDGE-03` routinely.

Additional costs of the body checks:

- nginx `access_by_lua_block` and Envoy `request_handle:body()` **buffer the whole body** up to 1 MiB, adding memory and latency and disabling streaming for those routes.
- The AWS WAF rule uses `OversizeHandling: CONTINUE`, so bodies over the inspection limit pass unchecked; attackers can pad a payload to bypass it.

## Who feels it

- End users: failed logins, rejected form posts, broken SSO (SAML) flows.
- API consumers with long Bearer tokens or Base64 fields in JSON.
- Edge operators who must triage 403 spikes.

## How to detect it

- 403 rate per route and per rule name (`CVE2026114938AuthHeaderMalformedB64`, `CVE2026114938BodyMalformedB64` metrics in WAF; `logWarn` lines in Envoy; the `$suspect_java4shell` variable in nginx logs).
- Matches whose payload decodes cleanly with a strict Base64 decoder are false positives.
- Support tickets clustered on login, SSO callback, and upload endpoints after the rule change.

## How to limit it

- Deploy in **count / log-only mode first** (nginx `set $block_cve_2026_114938 0;`, Envoy `respond` commented out, WAF `Action: Count`). Review hits for at least one full traffic cycle.
- Scope the body rules to routes and content types that actually carry Base64 (`application/json` fields, upload endpoints), and exclude form-encoded routes.
- Scope header rules to `Authorization: Basic`; leave `Bearer` to the application unless Basic-only traffic is confirmed.
- Add an allow-list for SAML ACS endpoints or validate SAML padding with a stricter, dedicated check.
- Treat the rules as temporary. Remove them once every upstream JVM is patched or carries the flag; they are not a substitute (runbook §4).

## Runbook and pattern references

- Runbook §4.1–4.3, §8 step 6.
- Patterns: `J4S-EDGE-01..05`.
