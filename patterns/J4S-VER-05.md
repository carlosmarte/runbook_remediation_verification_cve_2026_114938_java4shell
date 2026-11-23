# J4S-VER-05 — Vulnerable range decision table

**Area:** 5. JDK version patterns  
**Source:** `../cve_2026_114938_java4shell_remediation_verification_runbook.md`  
**Index:** [SPEC.md](SPEC.md)

Apply to the `(major, minor, patch, build)` tuple from J4S-VER-04.

| Major | Rule | Status |
| :--- | :--- | :--- |
| ≤ 16 (non-perf) | always | `PATCHED_OR_UNAFFECTED` |
| 17, minor 0 | `patch < 6` | `PATCHED_OR_UNAFFECTED` |
| 17, minor 0 | `6 ≤ patch < 21`, or `patch == 21 && build < 3` | `VULN_RANGE` |
| 17, minor 0 | `patch > 21`, or `patch == 21 && build ≥ 3` | `PATCHED_OR_UNAFFECTED` (baseline `17.0.21.0.3`) |
| 18, 19, 20, 22, 23, 24, 26 | always (EOL lines) | `VULN_RANGE` |
| 21, minor 0 | `patch < 13`, or `patch == 13 && build < 1` | `VULN_RANGE` |
| 21, minor 0 | `patch > 13`, or `patch == 13 && build ≥ 1` | `PATCHED_OR_UNAFFECTED` (baseline `21.0.13.1`) |
| 25, minor 0 | `patch < 5`, or `patch == 5 && build < 1` | `VULN_RANGE` |
| 25, minor 0 | `patch > 5`, or `patch == 5 && build ≥ 1` | `PATCHED_OR_UNAFFECTED` (baseline `25.0.5.1`) |
| 27, minor 0 | `patch < 1`, or `patch == 1 && build < 1` | `VULN_RANGE` |
| 27, minor 0 | `patch > 1`, or `patch == 1 && build ≥ 1` | `PATCHED_OR_UNAFFECTED` (baseline `27.0.1.1`) |
| any other | default | `VULN_RANGE` (requires manual verification) |
| matches J4S-VER-02 | — | `VULN_RANGE` |

**Note:** the bash fleet audit treats `17.x` with `minor != 0` as unaffected; the Python gate treats any unlisted shape as vulnerable. When they disagree, prefer the stricter (gate) result.
