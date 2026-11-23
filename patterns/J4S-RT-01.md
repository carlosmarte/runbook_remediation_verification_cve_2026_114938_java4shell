# J4S-RT-01 — JVM process detection via memory maps

**Area:** 6. Runtime / process discovery patterns  
**Source:** `../cve_2026_114938_java4shell_remediation_verification_runbook.md`  
**Index:** [SPEC.md](SPEC.md)

- **Surface:** `/proc/<pid>/maps`
- **Flavor:** ERE / fixed
```regex
libjvm\.so
```
- **Path extraction:** last whitespace-separated field of the first matching line (`awk '/libjvm\.so/{print $NF; exit}'`). Python: `(\S*libjvm\.so\S*)`.
