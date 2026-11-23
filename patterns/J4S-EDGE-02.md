# J4S-EDGE-02 — Padding followed by Base64 alphabet (mid-string `=`)

**Area:** 8. Edge / WAF compensating-control patterns (runbook §4)  
**Source:** `../cve_2026_114938_java4shell_remediation_verification_runbook.md`  
**Index:** [SPEC.md](SPEC.md)

- **Flavor:** PCRE / WAF
```regex
=[A-Za-z0-9+/_-]{1,64}
```
nginx map form: `~*=[A-Za-z0-9+/_-]{1,}` ; Lua form: `=[A-Za-z0-9+/_-]`
