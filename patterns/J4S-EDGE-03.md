# J4S-EDGE-03 — Long run with single terminal `=`

**Area:** 8. Edge / WAF compensating-control patterns (runbook §4)  
**Source:** `../cve_2026_114938_java4shell_remediation_verification_runbook.md`  
**Index:** [SPEC.md](SPEC.md)

- **Flavor:** varies by engine

| Engine | Pattern |
| :--- | :--- |
| nginx `map` | `~*[A-Za-z0-9+/_-]{64,}[^=]={1}(?:\s\|$\|;)` |
| OpenResty `ngx.re.find` | `[A-Za-z0-9+/_-]{64,}[^=]={1}(?:[^=A-Za-z0-9+/_-]\|$)` |
| AWS WAFv2 | `[A-Za-z0-9+/_-]{64,}[^=A-Za-z0-9+/_-]?={1}(?:[^=A-Za-z0-9+/_-]\|$)` |
| Envoy Lua `gmatch` | `[A-Za-z0-9+/_-]{64,}[^=]=([^=]\|$)` |

(`\|` is a table escape for `|`.)
