# J4S-FLAG-06 — Mitigation present (CI gate) — `MITIGATION_FLAG_RE`, runbook §7.1

**Area:** 4. JVM flag / option patterns (mitigation state)  
**Source:** `../cve_2026_114938_java4shell_remediation_verification_runbook.md`  
**Index:** [SPEC.md](SPEC.md)

- **Surface:** Dockerfile, K8s YAML, `JAVA_TOOL_OPTIONS` string
- **Flavor:** Python
- **Severity on non-match (Java workload):** BLOCK when `--require-flag`
```regex
(?:-XX:-UseBASE64Intrinsics|-XX:UseAVX=[0-2])(?:\s|"|'|\\|$)
```
