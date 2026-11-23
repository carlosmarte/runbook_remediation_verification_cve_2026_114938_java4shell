# J4S-RT-04 — JVM-like Kubernetes container heuristic

**Area:** 6. Runtime / process discovery patterns  
**Source:** `../cve_2026_114938_java4shell_remediation_verification_runbook.md`  
**Index:** [SPEC.md](SPEC.md)

- **Surface:** `"<image> <args> <command> <JVM env>"` per container
- **Flavor:** Python, `re.I`
```regex
(?:java|jdk|jvm|spring|tomcat|kafka|elasticsearch|keycloak|jenkins)
```
