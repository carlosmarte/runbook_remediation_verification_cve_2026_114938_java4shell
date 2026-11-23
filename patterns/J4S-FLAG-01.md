# J4S-FLAG-01 — Broad flag/option locator (runbook §7.3)

**Area:** 4. JVM flag / option patterns (mitigation state)  
**Source:** `../cve_2026_114938_java4shell_remediation_verification_runbook.md`  
**Index:** [SPEC.md](SPEC.md)

- **Surface:** any text (Dockerfile, manifest, systemd unit, shell wrapper, Helm values, CI YAML)
- **Flavor:** ERE
- **Severity on match:** INFO (locates where JVM options are set)
```regex
(-XX:[+-]?UseBASE64Intrinsics|-XX:UseAVX=[0-9]|JAVA_TOOL_OPTIONS|JDK_JAVA_OPTIONS)
```
