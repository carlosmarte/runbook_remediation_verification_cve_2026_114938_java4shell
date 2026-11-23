# J4S-BC-04 — Test artifact heuristic (`looks_like_test_path`)

**Area:** 3. Bytecode / archive patterns (`j4s-extract`, runbook §5)  
**Source:** `../cve_2026_114938_java4shell_remediation_verification_runbook.md`  
**Index:** [SPEC.md](SPEC.md)

- **Surface:** artifact path and archive entry path, lower-cased
- **Flavor:** substring / suffix
- **Effect:** downgrades verdict to `CONDITIONAL_LOW`
```text
contains "/test/"  OR  contains "\test\"  OR  contains "test-classes"
OR ends with "test.jar"  OR ends with "tests.jar"
```
