# J4S-FLAG-02 — Mitigation present (strict, token-bounded) — `classify_flag_text`, runbook §2

**Area:** 4. JVM flag / option patterns (mitigation state)  
**Source:** `../cve_2026_114938_java4shell_remediation_verification_runbook.md`  
**Index:** [SPEC.md](SPEC.md)

- **Surface:** process cmdline + JVM env vars (`/proc/<pid>/cmdline`, `/proc/<pid>/environ`)
- **Flavor:** ERE
- **Result label:** `ACTIVE`
```regex
(^|[[:space:]"])-XX:-UseBASE64Intrinsics([[:space:]"]|$)
```

- **Known gap (verified 2026-11-20):** the leading delimiter class `[[:space:]"]` does not include `=`, so an
  unquoted environment value such as `JAVA_TOOL_OPTIONS=-XX:-UseBASE64Intrinsics` (exactly how it appears in
  `/proc/<pid>/environ`, `docker inspect`, and Kubernetes `env`) is classified `NOT_SET_ON_CMDLINE_OR_ENV`.
  Use `(^|[[:space:]"=])` as the leading class. The same applies to J4S-FLAG-03 and J4S-FLAG-04.
  `scripts/verify_java4shell_runtime.sh` and the helpers carry the corrected class.
