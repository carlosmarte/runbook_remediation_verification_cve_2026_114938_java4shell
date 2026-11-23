# J4S-SRC-05 — File pre-filter (cheap gate before AST/regex)

**Area:** 2. Java source patterns (reachability of `java.util.Base64` decoding)  
**Source:** `../cve_2026_114938_java4shell_remediation_verification_runbook.md`  
**Index:** [SPEC.md](SPEC.md)

- **Surface:** file content
- **Flavor:** fixed-string
```text
Base64   OR   Decoder
```
- **Notes:** `ast_taint.py` skips any `.java` file containing neither token.
