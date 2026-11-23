# J4S-BC-03 — Base64 method names of interest

**Area:** 3. Bytecode / archive patterns (`j4s-extract`, runbook §5)  
**Source:** `../cve_2026_114938_java4shell_remediation_verification_runbook.md`  
**Index:** [SPEC.md](SPEC.md)

- **Surface:** `CONSTANT_NameAndType` name resolved from J4S-BC-02 owner
- **Flavor:** exact match set
```text
getDecoder | getUrlDecoder | getMimeDecoder | decode | wrap
```
- **Emitted target format:** `owner.method:descriptor` (e.g. `java/util/Base64$Decoder.decode:([B)[B`)
