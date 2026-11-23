# J4S-FLAG-08 — JVM option environment variables

**Area:** 4. JVM flag / option patterns (mitigation state)  
**Source:** `../cve_2026_114938_java4shell_remediation_verification_runbook.md`  
**Index:** [SPEC.md](SPEC.md)

- **Surface:** `/proc/<pid>/environ`, `docker inspect .Config.Env`, K8s `env[].name`
- **Flavor:** ERE (line-anchored)
```regex
^(JAVA_TOOL_OPTIONS|JDK_JAVA_OPTIONS|_JAVA_OPTIONS)=
```
