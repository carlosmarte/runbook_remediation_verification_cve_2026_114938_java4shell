# J4S-EDGE-05 — Body size window

**Area:** 8. Edge / WAF compensating-control patterns (runbook §4)  
**Source:** `../cve_2026_114938_java4shell_remediation_verification_runbook.md`  
**Index:** [SPEC.md](SPEC.md)

- Inspect bodies only when `64 ≤ len ≤ 1048576` (Envoy); nginx checks `#body >= 64`.
