# J4S-SRC-01 — Quick Base64 decoder call grep (runbook §7.3)

**Area:** 2. Java source patterns (reachability of `java.util.Base64` decoding)  
**Source:** `../cve_2026_114938_java4shell_remediation_verification_runbook.md`  
**Index:** [SPEC.md](SPEC.md)

- **Surface:** `*.java`, `*.kt`, `*.scala`, `*.groovy`
- **Flavor:** ERE
- **Severity on match:** REVIEW
```regex
\b(Base64\.(getDecoder|getUrlDecoder|getMimeDecoder)|getDecoder\(\)|getUrlDecoder\(\)|getMimeDecoder\(\)|\.decode\(|\.wrap\()
```
- **Action:** feed each hit into J4S-SRC-02/03 to classify the argument's provenance.
- **Notes:** `.decode(` / `.wrap(` alone are noisy (URLDecoder, charset decoders). Pre-filter files with `Base64|Decoder` (see J4S-SRC-05).
