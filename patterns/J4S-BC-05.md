# J4S-BC-05 — Shaded / relocated heuristic (`looks_like_shaded`)

**Area:** 3. Bytecode / archive patterns (`j4s-extract`, runbook §5)  
**Source:** `../cve_2026_114938_java4shell_remediation_verification_runbook.md`  
**Index:** [SPEC.md](SPEC.md)

- **Surface:** `"<class_name> <entry_path>"` lower-cased
- **Flavor:** substring
- **Effect:** sets `is_shaded=true`; dependency-chain resolution should search by class simple name, not Maven coordinate.
```text
shaded | shadow | repack | reloc
```
