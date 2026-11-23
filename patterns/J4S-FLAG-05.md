# J4S-FLAG-05 — Mitigation present (loose, fleet audit) — `check_cmdline_mitigation` / `check_cmdline_flags`

**Area:** 4. JVM flag / option patterns (mitigation state)  
**Source:** `../cve_2026_114938_java4shell_remediation_verification_runbook.md`  
**Index:** [SPEC.md](SPEC.md)

- **Surface:** process cmdline
- **Flavor:** ERE (bash) / Python
- **Result label:** `MITIGATED_FLAG` else `MISSING_FLAG`
```regex
(-XX:-UseBASE64Intrinsics|-XX:UseAVX=[0-2])
```
Python variant with trailing boundary:
```regex
(?:-XX:-UseBASE64Intrinsics|-XX:UseAVX=[0-2])(?:\s|$)
```
