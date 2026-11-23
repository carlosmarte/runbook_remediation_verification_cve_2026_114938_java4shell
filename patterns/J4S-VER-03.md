# J4S-VER-03 — Version token from `java -version` output (fleet audit)

**Area:** 5. JDK version patterns  
**Source:** `../cve_2026_114938_java4shell_remediation_verification_runbook.md`  
**Index:** [SPEC.md](SPEC.md)

- **Surface:** first two lines of `java -version` stderr
- **Flavor:** ERE (`grep -oE`, take first)
```regex
[0-9]+(\.[0-9]+){1,3}|8u[0-9a-zA-Z_-]+
```
Python equivalent (`classify_java_version`): prefer the quoted token `"([^"]+)"`, fall back to `\b(\d+(?:\.\d+){1,3})\b`.
