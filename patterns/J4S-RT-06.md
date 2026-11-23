# J4S-RT-06 — Container process ID list

**Area:** 6. Runtime / process discovery patterns  
**Source:** `../cve_2026_114938_java4shell_remediation_verification_runbook.md`  
**Index:** [SPEC.md](SPEC.md)

- **Command:** `docker top <cid> -eo pid | tail -n +2 | tr -d ' '`, keep tokens matching `^[0-9]+$`.
