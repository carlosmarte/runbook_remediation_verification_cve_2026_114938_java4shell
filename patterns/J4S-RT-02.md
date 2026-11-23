# J4S-RT-02 — Derive `JAVA_HOME/bin/java` from `libjvm.so` path

**Area:** 6. Runtime / process discovery patterns  
**Source:** `../cve_2026_114938_java4shell_remediation_verification_runbook.md`  
**Index:** [SPEC.md](SPEC.md)

- **Flavor:** Python / bash parameter expansion
```regex
^(.+?)/lib/[^/]+/libjvm\.so$
```
Bash: `${jvm_path%/lib/*/libjvm.so}/bin/java` (also accept `*/lib/server/libjvm.so`). Fallback: `argv0` if it contains `java` and is executable.
