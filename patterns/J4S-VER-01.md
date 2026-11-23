# J4S-VER-01 — Vendor-prefixed JDK version in text (`JDK_VER_RE`, runbook §7.1)

**Area:** 5. JDK version patterns  
**Source:** `../cve_2026_114938_java4shell_remediation_verification_runbook.md`  
**Index:** [SPEC.md](SPEC.md)

- **Surface:** Dockerfile (`FROM`, `ARG`, `ENV`), K8s manifest image tags, SBOM
- **Flavor:** Python, `re.I`
- **Capture group 1:** `major.minor.patch[.build]`
```regex
\b(?:jdk|openjdk|temurin|corretto|zulu|liberica|sapmachine)?[-:_]?(\d+\.\d+\.\d+(?:\.\d+)?)\b
```

- **Known gaps (verified 2026-11-20):**
  - Misses tags whose build uses an underscore, e.g. Temurin `21.0.12_7` (the `\b` fails before `_`). Use J4S-VER-01b.
  - Captures only 4 components, so the patched Liberica/Temurin baseline `17.0.21.0.3` is read as `17.0.21.0` and `parse_semver4` then reports it `VULN_RANGE`. Treat 17-line gate failures on `17.0.21.0.x` as false positives pending a runbook fix.
