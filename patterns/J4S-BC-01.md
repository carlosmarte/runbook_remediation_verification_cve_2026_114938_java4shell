# J4S-BC-01 — Scannable artifact extensions

**Area:** 3. Bytecode / archive patterns (`j4s-extract`, runbook §5)  
**Source:** `../cve_2026_114938_java4shell_remediation_verification_runbook.md`  
**Index:** [SPEC.md](SPEC.md)

- **Surface:** filesystem walk
- **Flavor:** bash-glob / extension match (case-insensitive)
```text
*.class  *.jar  *.war  *.ear  *.zip
```
- **Nested archive depth limit:** 3
