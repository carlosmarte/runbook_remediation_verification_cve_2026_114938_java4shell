# J4S-DEP-01 — Maven/Gradle dependency tree line

**Area:** 7. Dependency / SBOM patterns (`dep_graph.py`, runbook §6)  
**Source:** `../cve_2026_114938_java4shell_remediation_verification_runbook.md`  
**Index:** [SPEC.md](SPEC.md)

- **Surface:** `mvn dependency:tree` / `gradle dependencies` text
- **Flavor:** Python
- **Capture:** group 1 = tree prefix (depth = `len(prefix)//2` after replacing `+`, `\`, `-` with spaces); group 2 = `group:artifact:...` coordinate
```regex
^([|\s+\-\\]*?)([A-Za-z0-9_.-]+:[A-Za-z0-9_.-]+:[^\s]+)
```
Strip `^\[INFO\]\s*` first.
