# J4S-VER-04 — Numeric tuple parser

**Area:** 5. JDK version patterns  
**Source:** `../cve_2026_114938_java4shell_remediation_verification_runbook.md`  
**Index:** [SPEC.md](SPEC.md)

- **Flavor:** Python / ERE
```regex
^(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:\.(\d+))?
```
Missing components default to `0`.
