{{! ============================================================================
R9 - Compliance / Audit Attestation
Audience : Internal audit, compliance, customers' security questionnaires, regulators
SDLC     : closure (after operate); also at any point a customer asks "are you affected?"
Cadence  : once at closure, re-issued if scope changes
Inputs   : final --audit audits/*.json, --gh-scan estate.json, --gate gate.log; --extra attestation{} with signatories[], exceptions[], evidence[]
============================================================================ }}
# {{meta.cve}} ({{meta.alias}}) — Remediation Attestation

| | |
| :--- | :--- |
| **Organisation / scope** | {{meta.org}} — {{meta.scope}} |
| **Attestation date** | {{meta.report_date}} · report {{meta.report_id}} |
| **Vulnerability** | {{meta.cve}} ({{meta.alias}}, upstream {{meta.upstream_id}}), {{meta.cwe}}, CVSS 3.1 {{meta.cvss31}} / CVSS 4.0 {{meta.cvss40}}, disclosed {{meta.disclosure_date}} |
| **Affected products** | OpenJDK HotSpot and downstream builds on x86-64 with AVX-512 VBMI: JDK 17.0.6–17.0.21.0.2, 21 < 21.0.13.1, 25 < 25.0.5.1, 27 < 27.0.1.1, EOL 18–20/22–24/26, Oracle 8u511b33-perf |
| **Current status** | **{{status.rag}}** |
| **Classification** | {{meta.classification}} |

## 1. Statement

{{#if status.green}}
{{meta.org}} attests that, within the scope above, every Java runtime identified is either upgraded to a patched build ({{meta.baselines}}) or not affected, every repository that defines a Java runtime pins a patched build or carries the documented mitigation, and no exploitation indicators were found in the evidence listed below.
{{else}}
{{meta.org}} attests that, within the scope above, remediation of {{meta.cve}} is **in progress** with status {{status.rag}}: {{#each status.reasons}}{{.}}; {{/each}}The compensating control `{{meta.mitigation_flag}}` is applied as stated in section 3 and the remaining items carry the exceptions and dates in section 5.
{{/if}}

## 2. Scope and coverage

| Population | Identified | Verified | Method |
| :--- | ---: | ---: | :--- |
| Hosts (physical/VM) | {{fleet.hosts|default:0}} | {{fleet.hosts|default:0}} | `scripts/audit_java4shell.py` per host (process maps, `java -version`, cmdline/env flags, live `jcmd`) |
| JVM processes | {{fleet.jvms|default:0}} | {{fleet.jvms|default:0}} | same |
| Container images / Kubernetes workloads | {{extra.attestation.images|default:see repositories}} | | `scripts/verify_java4shell_runtime.sh --k8s`, `helpers/j4s_k8s.sh` |
| Source repositories (Java) | {{repos.java|default:0}} | {{repos.java|default:0}} | `github/gh_j4s_scan.py` (default branch, runtime definitions, CI gate) |
| Source call sites decoding Base64 | {{source.total|default:n/a}} | {{source.total|default:n/a}} | `scripts/scan_java4shell_source.py` (provenance classification) |
| Compiled artifacts | {{jars.artifacts|default:n/a}} | {{jars.artifacts|default:n/a}} | `scripts/scan_java4shell_jars.py` (constant-pool references, shaded copies) |

## 3. Results

| Control | Result |
| :--- | :--- |
| JVMs exposed (vulnerable, unmitigated, VBMI hardware) | **{{fleet.exposed_vbmi|default:0}}** |
| JVMs mitigated by `{{meta.mitigation_flag}}` (upgrade pending) | {{fleet.mitigated_flag|default:0}} |
| JVMs patched or unaffected | {{fleet.patched|default:0}} ({{fleet.patch_coverage|pct|default:n/a}}) |
| JVMs on vulnerable builds on non-VBMI hardware | {{fleet.unverified|default:0}} |
| Repositories deploying a vulnerable JDK unmitigated | **{{repos.blocking|default:0}}** |
| Repositories mitigated / unverified / patched | {{repos.mitigated_flag|default:0}} / {{repos.unverified_floating|default:0}}+{{repos.unverified_no_pin|default:0}} / {{repos.patched|default:0}} |
| Release gate enforced | {{repos.with_gate|default:0}} of {{repos.java|default:0}} Java repositories; last gate run: {{gate.status|default:n/a}} |
| Untrusted Base64 decode sites in production code | {{source.untrusted_prod|default:n/a}} (validation added: {{extra.attestation.validation_added|default:TBD}}) |
| Exploitation indicators | crashes LIKELY {{crashes.likely|default:0}} / POSSIBLE {{crashes.possible|default:0}}; suspicious edge tokens {{traffic.suspicious|default:0}} |

## 4. Evidence register

| # | Evidence | Produced by | Location / hash | Date |
| ---: | :--- | :--- | :--- | :--- |
{{#each extra.attestation.evidence}}
| {{@index}} | {{.item}} | {{.tool}} | {{.location}} | {{.date}} |
{{/each}}
{{#each inputs}}
| | {{.key}} | scanner output | {{.value}} | {{meta.report_date}} |
{{/each}}

## 5. Exceptions and risk acceptances

{{#if extra.exceptions}}
| Asset | Reason | Compensating control | Risk owner | Approved | Expires |
| :--- | :--- | :--- | :--- | :--- | :--- |
{{#each extra.exceptions}}
| {{.service}} | {{.reason}} | {{.control}} | {{.approver}} | {{.approved|default:—}} | {{.expires}} |
{{/each}}
{{else}}
None recorded.
{{/if}}

## 6. Controls mapping

| Framework | Control | How this remediation satisfies it |
| :--- | :--- | :--- |
| ISO 27001:2022 | A.8.8 Management of technical vulnerabilities | inventory (§2), risk-based remediation with SLA {{meta.sla_mitigate_days}}/{{meta.sla_patch_days}} days, verification (§3) |
| NIST SP 800-53 | RA-5, SI-2, CM-6 | scanning, flaw remediation, configuration (`JAVA_TOOL_OPTIONS`) enforced by CI gate |
| SOC 2 | CC7.1, CC7.2 | detection of vulnerable components; monitoring for exploitation (crash triage, edge rules) |
| PCI DSS 4.0 | 6.3.1, 6.3.3, 11.3 | critical patch within policy window or documented compensating control |
| CIS Controls v8 | 7.4, 7.7, 16.13 | automated remediation process, remediation of detected vulnerabilities, application-level input validation |

## 7. Sign-off

| Role | Name | Date | Signature |
| :--- | :--- | :--- | :--- |
{{#each extra.attestation.signatories}}
| {{.role}} | {{.name}} | {{.date|default:}} | |
{{/each}}
{{#if extra.attestation.signatories}}{{else}}| CISO / risk owner | | | |
| Head of platform engineering | | | |
| Internal audit (witness) | | | |{{/if}}

_This attestation reflects the evidence listed in section 4 as of {{meta.report_date}}. It will be re-issued if new Java runtimes enter scope or hardware changes bring non-VBMI hosts into the affected class._
