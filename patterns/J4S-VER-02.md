# J4S-VER-02 — Vulnerable Oracle Java 8 perf build (`JAVA8_PERF_RE`)

**Area:** 5. JDK version patterns  
**Source:** `../cve_2026_114938_java4shell_remediation_verification_runbook.md`  
**Index:** [SPEC.md](SPEC.md)

- **Surface:** any version string
- **Flavor:** ERE / Python, case-insensitive
- **Severity on match:** BLOCK
```regex
8u511b33-perf
```
