{{! ============================================================================
R8 - Incident / Exploitation Triage Report
Audience : Security operations, incident response, forensics; summary line for the CISO
SDLC     : operate / incident response
Cadence  : on every LIKELY/POSSIBLE crash, suspicious edge traffic, or WAF block spike
Inputs   : --crashes crashes.json (helpers/j4s_hs_err.py --json) --b64 traffic.json (helpers/j4s_b64check.py scan --json)
           --audit audits of the affected hosts; --extra incident{} with id, severity, timeline[], containment[], iocs[]
============================================================================ }}
# {{meta.cve}} ({{meta.alias}}) — Incident Triage Report {{extra.incident.id|default:}}

| | |
| :--- | :--- |
| **Incident** | {{extra.incident.id|default:—}} · severity {{extra.incident.severity|default:TBD}} · opened {{extra.incident.opened|default:—}} |
| **Commander / reporter** | {{extra.incident.commander|default:—}} / {{meta.prepared_by}} |
| **Status** | **{{status.rag}}** · {{extra.incident.state|default:investigating}} |
| **Affected** | {{extra.incident.affected|default:see hosts below}} |

## 1. Assessment

{{#if crashes.available}}
{{crashes.files}} crash file(s) triaged: **{{crashes.likely}} LIKELY**, {{crashes.possible}} POSSIBLE, {{crashes.unlikely}} UNLIKELY. {{crashes.hosts_unmitigated}} flagged crash(es) came from JVMs without the mitigation.
{{/if}}
{{#if traffic.available}}
{{traffic.tokens}} Base64 token(s) analysed from logs/headers: **{{traffic.suspicious}} suspicious** (J4S-EDGE-01 excess padding: {{traffic.edge01}}, EDGE-02 padding inside body: {{traffic.edge02}}, EDGE-03 long run + single pad: {{traffic.edge03}}); {{traffic.jwt_like}} JWT-like.
{{/if}}

Read as: a `LIKELY` crash (SIGSEGV/SIGBUS in a Base64 stub frame, heap-corruption markers, vulnerable JRE, no flag, VBMI CPU) on a host that also received malformed-padding tokens is an **exploitation attempt**; whether it succeeded cannot be decided from the crash alone (side effects 01–02: DoS and "JavaBleed" heap disclosure).

{{#if crashes.flagged_rows}}
## 2. Crash files

| File | Verdict | Score | Signal | Frame | JRE | Version status | Flag | Re-enabled | VBMI | Reasons |
| :--- | :--- | ---: | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
{{#each crashes.flagged_rows}}
| `{{.file|md}}` | **{{.verdict}}** | {{.score}} | {{.signal|default:-}} | `{{.problematic_frame|md|default:-}}` | {{.jre_version|default:-}} | {{.version_status}} | {{.mitigation_present|yesno}} | {{.explicitly_enabled|yesno}} | {{.cpu_avx512_vbmi|yesno}} | {{.reasons|join|md}} |
{{/each}}
{{/if}}

{{#if traffic.rows}}
## 3. Suspicious tokens (sample, first {{traffic.rows|count}})

| Log line | Token (truncated) | Length | Pads | Edge rules | Anomalies | JWT-like |
| :--- | :--- | ---: | ---: | :--- | :--- | :--- |
{{#each traffic.rows}}
| {{.line}} | `{{.token|md}}` | {{.length}} | {{.pad_count}} | {{.edge_rules}} | {{.anomalies|md}} | {{.jwt|yesno}} |
{{/each}}
{{/if}}

{{#if fleet.available}}
## 4. State of the affected hosts

| Host | VBMI | PID | JDK | Version status | Flag | Verdict |
| :--- | :--- | ---: | :--- | :--- | :--- | :--- |
{{#each fleet.jvms_rows}}
| {{.host}} | {{.vbmi|yesno}} | {{.pid}} | {{.version}} | {{.version_status}} | {{.flag_status}} | **{{.verdict}}** |
{{/each}}
{{/if}}

## 5. Timeline

| Time (UTC) | Event | Source |
| :--- | :--- | :--- |
{{#each extra.incident.timeline}}
| {{.time}} | {{.event}} | {{.source}} |
{{/each}}
{{#if extra.incident.timeline}}{{else}}| | _fill from edge logs, hs_err timestamps, deploy history_ | |{{/if}}

## 6. Containment and eradication

| Step | Status | Owner |
| :--- | :--- | :--- |
| Apply `-XX:-UseBASE64Intrinsics` to every JVM on the affected hosts and restart | {{extra.containment.flag|default:☐}} | |
| Switch edge rules J4S-EDGE-01/02 from count to block on the affected routes | {{extra.containment.edge|default:☐}} | |
| Preserve `hs_err_pid*.log`, heap dumps, GC logs, access logs (chain of custody) | {{extra.containment.preserve|default:☐}} | |
| Rotate secrets resident in the crashed JVMs' heaps (tokens, keys, DB credentials) — JavaBleed assumption | {{extra.containment.rotate|default:☐}} | |
| Hunt for the same token shapes across the fleet (`helpers/j4s_b64check.py scan` on all edge logs for the window) | {{extra.containment.hunt|default:☐}} | |
| Upgrade the affected services to {{meta.baselines}} | {{extra.containment.patch|default:☐}} | |

## 7. Indicators

{{#if extra.incident.iocs}}
{{#each extra.incident.iocs}}
- {{.}}
{{/each}}
{{else}}
- Base64 payloads ≥ 64 chars with `===`, `=` followed by alphabet characters, or a long run ending in a single `=` (J4S-EDGE-01..03)
- `SIGSEGV`/`SIGBUS` with problematic frame in `StubRoutines::base64_decode` / `java.util.Base64$Decoder.decode0`
- Unexpected JVM restarts of Base64-handling services within minutes of such requests
{{/if}}

## 8. Decisions and actions

{{#each actions}}
{{@index}}. {{.}}
{{/each}}

_Escalate to R0 if any crash is LIKELY on an internet-facing service. Close via R9 attestation once the hosts are PATCHED and secrets rotated._
