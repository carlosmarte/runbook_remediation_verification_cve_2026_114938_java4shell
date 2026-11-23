# J4S-SRC-02 — Precise decoder invocation with argument capture (`BASE64_CALL_RE`, runbook §6 `ast_taint.py`)

**Area:** 2. Java source patterns (reachability of `java.util.Base64` decoding)  
**Source:** `../cve_2026_114938_java4shell_remediation_verification_runbook.md`  
**Index:** [SPEC.md](SPEC.md)

- **Surface:** single Java source line
- **Flavor:** Python (`re`)
- **Severity on match:** REVIEW
- **Capture groups:** group 1 or group 2 = argument expression passed to `decode(...)` / `wrap(...)`
```regex
\bBase64\s*\.\s*(?:getDecoder|getUrlDecoder|getMimeDecoder)\s*\(\s*\)\s*\.\s*(?:decode|wrap)\s*\(([^;]+)\)|\b(?:getDecoder|getUrlDecoder|getMimeDecoder)\s*\(\s*\)\s*\.\s*(?:decode|wrap)\s*\(([^;]+)\)
```
- **Action:** pass captured argument plus 15 lines of preceding context and 5 lines following to J4S-SRC-03.
