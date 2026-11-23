# J4S-RT-03 — AVX-512 CPU feature flags

**Area:** 6. Runtime / process discovery patterns  
**Source:** `../cve_2026_114938_java4shell_remediation_verification_runbook.md`  
**Index:** [SPEC.md](SPEC.md)

- **Surface:** `/proc/cpuinfo` (x86_64 only)
- **Flavor:** ERE
- **Exposure gate:** `avx512_vbmi` present ⇒ host is in hardware scope
```regex
\bavx512f\b
\bavx512_vbmi\b
\bavx512_vbmi2\b
```
Enumerate all: `grep -oE '\bavx512[a-z0-9_]*\b' /proc/cpuinfo | sort -u`
