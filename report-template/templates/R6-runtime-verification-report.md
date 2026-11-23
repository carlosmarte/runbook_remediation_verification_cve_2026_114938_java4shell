{{! ============================================================================
R6 - Runtime Verification Report (hosts, containers, Kubernetes)
Audience : Platform / SRE / infrastructure teams, security operations
SDLC     : deploy / operate
Cadence  : daily during rollout, then weekly; always before and after a flag or JDK change
Inputs   : --audit audits/*.json (scripts/audit_java4shell.py per host) [--audit-before ...]; narrative from
           scripts/verify_java4shell_runtime.sh and helpers/j4s_k8s.sh pasted into extra.k8s / extra.notes
============================================================================ }}
# {{meta.cve}} ({{meta.alias}}) — Runtime Verification Report

{{meta.org}} · {{meta.scope}} · {{meta.report_date}} · status **{{status.rag}}**

## 1. Fleet summary

| Measure | Value |
| :--- | ---: |
| Hosts audited | {{fleet.hosts|default:0}} |
| Hosts with AVX-512 VBMI (in hardware scope) | {{fleet.hosts_vbmi|default:0}} ({{fleet.vbmi_host_share|pct|default:0%}}) |
| JVM processes | {{fleet.jvms|default:0}} (on VBMI hosts: {{fleet.jvms_vbmi|default:0}}) |
| **EXPOSED_ON_VBMI_HOST** | **{{fleet.exposed_vbmi|default:0}}** |
| UNVERIFIED_ON_HOST (vulnerable version, no flag, non-VBMI CPU) | {{fleet.unverified|default:0}} |
| MITIGATED_BY_FLAG | {{fleet.mitigated_flag|default:0}} |
| PATCHED_OR_SAFE_VERSION | {{fleet.patched|default:0}} |
| JVMs with a vulnerable version (any CPU) | {{fleet.vulnerable_versions|default:0}} |
| JVMs without the flag on the command line / env | {{fleet.missing_flag|default:0}} |
| Exposure rate / mitigation coverage / patch coverage | {{fleet.exposure_rate|pct|default:n/a}} / {{fleet.mitigation_coverage|pct|default:n/a}} / {{fleet.patch_coverage|pct|default:n/a}} |

### Exposure matrix

| | Vulnerable version, no flag | Vulnerable version, flag active | Patched / unaffected |
| :--- | :--- | :--- | :--- |
| **VBMI host** | EXPOSED_ON_VBMI_HOST — fix now | MITIGATED_BY_FLAG — upgrade | safe |
| **non-VBMI host** | UNVERIFIED_ON_HOST — patch before hardware moves | MITIGATED_BY_FLAG | safe |

## 2. Hosts

| Host | Arch | VBMI | JVMs | Exposed | Unverified | Mitigated | Patched | Containers | Status |
| :--- | :--- | :--- | ---: | ---: | ---: | ---: | ---: | ---: | :--- |
{{#each fleet.hosts_rows}}
| {{.host}} | {{.arch}} | {{.vbmi|yesno}} | {{.jvms}} | {{.exposed}} | {{.unverified}} | {{.mitigated}} | {{.patched}} | {{.containers}} | **{{.status}}** |
{{/each}}

## 3. Exposed JVMs (act today)

{{#if fleet.exposed_rows}}
| Host | PID | Source | JDK | Flag | Command |
| :--- | ---: | :--- | :--- | :--- | :--- |
{{#each fleet.exposed_rows}}
| {{.host}} | {{.pid}} | {{.source}} | {{.version}} | {{.flag_status}} | `{{.cmd|md}}` |
{{/each}}

Per process: `helpers/j4s_proc.sh flags <pid>` shows command-line vs live state; apply with `JAVA_TOOL_OPTIONS=-XX:-UseBASE64Intrinsics` (or launch args) and restart; confirm with `jcmd <pid> VM.flags -all | grep UseBASE64Intrinsics`.
{{else}}
None.
{{/if}}

## 4. All JVM processes

| Host | PID | Source | JDK | Version status | Flag (cmdline/env) | Verdict | Command |
| :--- | ---: | :--- | :--- | :--- | :--- | :--- | :--- |
{{#each fleet.jvms_rows}}
| {{.host}} | {{.pid}} | {{.source}} | {{.version}} | {{.version_status}} | {{.flag_status}} | {{.verdict}} | `{{.cmd|md}}` |
{{/each}}

{{#if trend.available}}
## 5. Before / after

| | Before | After |
| :--- | ---: | ---: |
| Exposed JVMs | {{trend.exposed_before}} | {{trend.exposed_after}} |
| Mitigation coverage | {{trend.mitigation_before|pct}} | {{trend.mitigation_after|pct}} |
| Patch coverage | {{trend.patch_before|pct}} | {{trend.patch_after|pct}} |

Improved {{trend.improved}} · **Regressed {{trend.regressed}}** · New {{trend.new}} · Gone {{trend.gone}} · Unchanged {{trend.unchanged}}
{{#if trend.regressed_rows}}
| Host | PID | Command | Before | After |
| :--- | ---: | :--- | :--- | :--- |
{{#each trend.regressed_rows}}
| {{.host}} | {{.pid}} | `{{.cmd|md}}` | {{.before}} | **{{.verdict}}** |
{{/each}}
{{/if}}
{{/if}}

{{#if extra.k8s}}
## 6. Kubernetes (read-only inventory, `helpers/j4s_k8s.sh`)

| Namespace / workload | Container | Image | Image version status | Flag in spec | Node arch |
| :--- | :--- | :--- | :--- | :--- | :--- |
{{#each extra.k8s}}
| {{.workload}} | {{.container}} | `{{.image|md}}` | {{.version_status}} | {{.flag}} | {{.arch}} |
{{/each}}
{{/if}}

## 7. Verification method and limits

- JVMs are found by `libjvm.so` in `/proc/<pid>/maps` (J4S-RT-01); versions from `$JAVA_HOME/release` or `java -version` (J4S-VER-03); flags from cmdline/env (J4S-FLAG-02/03) and live `jcmd` (J4S-FLAG-09).
- `jcmd` attaches to the JVM (safepoint pause, milliseconds) and must run as the process owner or root; `jcmd-unavailable-or-restricted` means the live state is unknown, not safe (`docs/side-efforts/09`).
- A `MITIGATED_BY_FLAG` verdict from the command line is confirmed only when the live flag reads `-UseBASE64Intrinsics`.
- Non-x86-64 hosts (ARM64, Graviton, Apple Silicon) are out of hardware scope but still carry vulnerable binaries; they are reported as UNVERIFIED so a hardware migration cannot silently expose them.

## 8. Actions

{{#each actions}}
{{@index}}. {{.}}
{{/each}}

{{#if extra.notes}}
## 9. Notes

{{extra.notes}}
{{/if}}
