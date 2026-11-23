# J4S-FLAG-03 — Mitigation present via AVX cap — `classify_flag_text`

**Area:** 4. JVM flag / option patterns (mitigation state)  
**Source:** `../cve_2026_114938_java4shell_remediation_verification_runbook.md`  
**Index:** [SPEC.md](SPEC.md)

- **Surface:** same as FLAG-02
- **Flavor:** ERE
- **Result label:** `CAPPED`
```regex
(^|[[:space:]"])-XX:UseAVX=[0-2]([[:space:]"]|$)
```
