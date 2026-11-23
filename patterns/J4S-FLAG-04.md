# J4S-FLAG-04 — Intrinsic explicitly re-enabled (anti-pattern)

**Area:** 4. JVM flag / option patterns (mitigation state)  
**Source:** `../cve_2026_114938_java4shell_remediation_verification_runbook.md`  
**Index:** [SPEC.md](SPEC.md)

- **Surface:** same as FLAG-02
- **Flavor:** ERE
- **Severity on match:** BLOCK on unpatched JDK
- **Result label:** `EXPLICITLY_ENABLED`
```regex
(^|[[:space:]"])-XX:\+UseBASE64Intrinsics([[:space:]"]|$)
```
