# J4S-FLAG-09 — Live JVM flag extraction from `jcmd <pid> VM.flags -all`

**Area:** 4. JVM flag / option patterns (mitigation state)  
**Source:** `../cve_2026_114938_java4shell_remediation_verification_runbook.md`  
**Index:** [SPEC.md](SPEC.md)

- **Surface:** `jcmd` stdout
- **Flavor:** ERE (`grep -oE`)
```regex
(\+|-)?UseBASE64Intrinsics[^[:space:]]*
```
```regex
UseAVX[[:space:]]*=[[:space:]]*[0-9]+
```
- **Alternative one-liners:**
```bash
jinfo -flag UseBASE64Intrinsics <PID>
jcmd <PID> VM.flags -all | grep -i base64
```
