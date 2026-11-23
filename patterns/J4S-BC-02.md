# J4S-BC-02 — Base64 owner class in constant pool (`is_base64_target`)

**Area:** 3. Bytecode / archive patterns (`j4s-extract`, runbook §5)  
**Source:** `../cve_2026_114938_java4shell_remediation_verification_runbook.md`  
**Index:** [SPEC.md](SPEC.md)

- **Surface:** `CONSTANT_Methodref` / `CONSTANT_InterfaceMethodref` owner (JVM internal name)
- **Flavor:** string predicates (equivalent ERE shown)
- **Severity on match:** REVIEW
```regex
(^java/util/Base64$|^java/util/Base64\$|/java/util/Base64$|/java/util/Base64\$)
```
- **Notes:** the `/java/util/Base64` suffix forms catch **shaded / relocated** copies (e.g. `com/vendor/shaded/java/util/Base64$Decoder`).
