# J4S-VER-01b — Supplementary version extractor (underscore and 5-component aware)

**Area:** 5. JDK version patterns  
**Source:** `../cve_2026_114938_java4shell_remediation_verification_runbook.md`  
**Index:** [SPEC.md](SPEC.md)

- **Surface:** same as VER-01
- **Flavor:** PCRE (`rg -P`) / Python
- **Capture group 1:** `major.minor.patch[.build[.extra]]`; trailing `_N` build qualifier is consumed but not captured
```regex
(?<![\d.])(\d+(?:\.\d+){2,4})(?:_\d+)?(?![\d.])
```
- **Notes:** no vendor prefix required, so it also catches bare `ARG JDK_VERSION=21.0.12` lines. Vendor-prefixed hits from VER-01 remain authoritative when both match.
