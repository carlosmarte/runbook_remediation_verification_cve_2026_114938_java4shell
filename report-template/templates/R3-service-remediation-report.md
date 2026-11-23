{{! ============================================================================
R3 - Service Remediation Report (one service / one team)
Audience : Service owner, team lead, on-call engineer
SDLC     : develop -> release -> operate (the full loop for one service)
Cadence  : once at triage, updated until the service is PATCHED
Inputs   : audits of the service's hosts (--audit), the service repository (--gh-scan with that repo), its source scan
           (--source), jar scan (--jars) and gate log (--gate); --extra service{} with name, owner, tier, runtime, endpoints
============================================================================ }}
# {{meta.cve}} ({{meta.alias}}) — Service Remediation Report: {{extra.service.name|default:SERVICE}}

| | |
| :--- | :--- |
| **Service / owner / tier** | {{extra.service.name|default:—}} / {{extra.service.owner|default:—}} / {{extra.service.tier|default:—}} |
| **Runtime** | {{extra.service.runtime|default:see pins below}} |
| **Internet-facing / pre-auth surface** | {{extra.service.internet_facing|default:unknown}} / {{extra.service.preauth_surface|default:unknown}} |
| **Status** | **{{status.rag}}** on {{meta.report_date}} |
| **Target** | flag live by {{meta.sla_mitigate_due}}; patched ({{meta.baselines}}) by {{meta.sla_patch_due}} |

## 1. Exposure summary

{{#each status.reasons}}
- {{.}}
{{/each}}

## 2. Where it runs (runtime evidence)

{{#if fleet.available}}
| Host | Arch | VBMI | PID | Source | JDK | Version status | Flag | Verdict |
| :--- | :--- | :--- | ---: | :--- | :--- | :--- | :--- | :--- |
{{#each fleet.jvms_rows}}
| {{.host}} | {{.arch|default:-}} | {{.vbmi|yesno}} | {{.pid}} | {{.source}} | {{.version}} | {{.version_status}} | {{.flag_status}} | **{{.verdict}}** |
{{/each}}

Flag confirmation must come from the live JVM, not the manifest: `jcmd <pid> VM.flags -all | grep UseBASE64Intrinsics` (pattern J4S-FLAG-09).
{{else}}
_No host audit supplied. Run `scripts/audit_java4shell.py --pretty` on each host (as the JVM owner or root) and attach the JSON._
{{/if}}

{{#if repos.available}}
## 3. How it is built and deployed (repository evidence)

| Repository | Verdict | Runtime JDK pins | Flag in runtime files | Gate | Reason |
| :--- | :--- | :--- | :--- | :--- | :--- |
{{#each repos.rows}}
| [{{.repo}}]({{.url}}) | `{{.verdict}}` | {{.pins|md}} | {{.flag}} | {{.gate|yesno}} | {{.reason|md}} |
{{/each}}
{{/if}}

{{#if source.available}}
## 4. Where the code decodes Base64 (source evidence)

{{source.total}} call sites in {{source.files}} files: **{{source.untrusted}} untrusted**, {{source.internal}} internal, {{source.constant}} constant, {{source.unknown}} unknown; {{source.preauth}} in pre-authentication context; {{source.test}} in tests.

| File:line | Call | Argument | Input kind | Pre-auth | Test | Why |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
{{#each source.rows}}
| `{{.file}}:{{.line}}` | `{{.call|md}}` | `{{.argument|md}}` | {{.input_kind}} | {{.preauth_context|yesno}} | {{.is_test|yesno}} | {{.reason|md}} |
{{/each}}
{{/if}}

{{#if jars.available}}
## 5. Compiled artifacts and dependencies (bytecode evidence)

{{jars.classes}} classes in {{jars.artifacts}} artifacts reference `java.util.Base64` decoding; {{jars.shaded}} are shaded/relocated copies, {{jars.test}} are test artifacts.

| Artifact | Classes | Shaded | Test |
| :--- | ---: | ---: | :--- |
{{#each jars.artifact_rows}}
| `{{.artifact|md}}` | {{.classes}} | {{.shaded}} | {{.test|yesno}} |
{{/each}}
{{/if}}

{{#if gate.available}}
## 6. Release gate

Gate result: **{{gate.status}}** ({{gate.count}} violation(s)).
{{#each gate.violations}}
- {{.}}
{{/each}}
{{/if}}

## 7. Remediation checklist

| # | Step | Command / change | Done | Evidence |
| ---: | :--- | :--- | :--- | :--- |
| 1 | Add the flag to the runtime | `ENV JAVA_TOOL_OPTIONS="-XX:-UseBASE64Intrinsics"` (Dockerfile) · `env: JAVA_TOOL_OPTIONS` (manifest) · `helpers/j4s_flag.sh snippet k8s-patch` | ☐ | |
| 2 | Verify live | `helpers/j4s_proc.sh flags <pid>` or `helpers/j4s_k8s.sh missing -n <ns>` → `ACTIVE` | ☐ | |
| 3 | Benchmark | p99 and CPU on Base64-heavy endpoints before/after (side effect 04) | ☐ | |
| 4 | Validate input before decode | reject length % 4 ≠ 0, `={3,}`, `=` inside the body (`helpers/j4s_b64check.py` `is_strictly_valid`) at each untrusted site | ☐ | |
| 5 | Upgrade the JDK | pin `{{meta.baselines}}` or vendor equivalent; run the test suite on the new JDK | ☐ | |
| 6 | Pin and gate | exact tag or digest; add `.github/workflows/cve-2026-114938-gate.yml`; make it a required check | ☐ | |
| 7 | Re-audit | rerun `audit_java4shell.py` and `gh_j4s_scan.py`; attach JSON; verdict `PATCHED` | ☐ | |
| 8 | Remove the flag (optional, after fleet is patched) | revert step 1; re-benchmark | ☐ | |

## 8. Actions assigned

{{#each actions}}
{{@index}}. {{.}}
{{/each}}

_Related: R4 developer findings for this repo, R6 runtime verification for its hosts, R8 if any crash or probe was seen._
