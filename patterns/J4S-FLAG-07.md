# J4S-FLAG-07 — Mitigation present (Kubernetes manifest scan) — `flag_re`, runbook §2

**Area:** 4. JVM flag / option patterns (mitigation state)  
**Source:** `../cve_2026_114938_java4shell_remediation_verification_runbook.md`  
**Index:** [SPEC.md](SPEC.md)

- **Surface:** joined `args + command + JVM env values` per container
- **Flavor:** Python
```regex
(?:-XX:-UseBASE64Intrinsics|-XX:UseAVX=[0-2])
```
