# J4S-EDGE-04 — Auth header candidate selector (nginx)

**Area:** 8. Edge / WAF compensating-control patterns (runbook §4)  
**Source:** `../cve_2026_114938_java4shell_remediation_verification_runbook.md`  
**Index:** [SPEC.md](SPEC.md)

- **Surface:** `$http_authorization`, `proxy-authorization`
- **Flavor:** nginx PCRE, case-insensitive
```regex
~*(?:Basic|Bearer)\s+[A-Za-z0-9+/=_-]{64,}
```
