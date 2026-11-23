# J4S-SRC-04 — Auth / JWT / SAML / Basic decoding context (runbook §7.3)

**Area:** 2. Java source patterns (reachability of `java.util.Base64` decoding)  
**Source:** `../cve_2026_114938_java4shell_remediation_verification_runbook.md`  
**Index:** [SPEC.md](SPEC.md)

- **Surface:** Java source, config, templates
- **Flavor:** PCRE (`rg -P`), single line
- **Severity on match:** MITIGATE
```regex
\b(Authorization|Proxy-Authorization|Basic\s+[A-Za-z0-9+/=_-]+|jwt|jws|saml|bearer)\b.{0,120}\b(Base64|decode|getDecoder)\b
```
- **Action:** treat as a pre-authentication touchpoint. Prioritize for `-XX:-UseBASE64Intrinsics` rollout and input validation.
- **Notes:** run case-insensitively (`rg -i`): the alternation is lower-case but code uses `Bearer`, `Basic`, `JWT`. Single-line only; when the header read and the decode are on different lines, rely on J4S-SRC-03 context analysis instead.
