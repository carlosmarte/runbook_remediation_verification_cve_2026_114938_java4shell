# J4S-DEP-02 — CycloneDX JSON fields

**Area:** 7. Dependency / SBOM patterns (`dep_graph.py`, runbook §6)  
**Source:** `../cve_2026_114938_java4shell_remediation_verification_runbook.md`  
**Index:** [SPEC.md](SPEC.md)

- **Surface:** CycloneDX SBOM
```text
metadata.component.bom-ref   (root)
dependencies[].ref  →  dependencies[].dependsOn[]   (edges)
```
