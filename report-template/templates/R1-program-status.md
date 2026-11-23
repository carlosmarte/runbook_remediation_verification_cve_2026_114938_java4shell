{{! ============================================================================
R1 - Remediation Programme Status
Audience : Security leadership, remediation programme manager, incident commander
SDLC     : operate / release (programme governance)
Cadence  : daily in the first week, weekly until closure
Inputs   : everything available -> tools/j4s_facts.py --audit ... --audit-before ... --gh-scan ... --actions ... --source ... --gate ... -o facts.json
           plus --extra narrative.json with business_units[], blockers[], exceptions[], milestones[]
============================================================================ }}
# {{meta.cve}} ({{meta.alias}}) — Remediation Programme Status

**Report {{meta.report_id}}** · {{meta.report_date}} · period {{meta.period}} · day {{meta.days_since_disclosure}} since disclosure
**Status: {{status.rag}}** · owner {{meta.owner}} · prepared by {{meta.prepared_by}} · next review {{meta.next_review}}

## 1. Headline

{{#each status.reasons}}
- {{.}}
{{/each}}

## 2. Scorecard

| Indicator | Now | Target | SLA |
| :--- | ---: | ---: | :--- |
| JVMs exposed on VBMI hosts | {{fleet.exposed_vbmi|default:n/a}} | 0 | by {{meta.sla_mitigate_due}} ({{meta.sla_mitigate_days}} d) |
| Mitigation coverage (flag or patch) | {{fleet.mitigation_coverage|pct|default:n/a}} | 100% | by {{meta.sla_mitigate_due}} |
| Patch coverage | {{fleet.patch_coverage|pct|default:n/a}} | 100% | by {{meta.sla_patch_due}} ({{meta.sla_patch_days}} d) |
| Repositories deploying a vulnerable JDK unmitigated | {{repos.blocking|default:n/a}} | 0 | by {{meta.sla_mitigate_due}} |
| Repositories unverified (floating / no pin) | {{repos.unverified_floating|default:0}} + {{repos.unverified_no_pin|default:0}} | 0 | by {{meta.sla_patch_due}} |
| Release gate adoption (Java repos) | {{repos.gate_adoption|pct|default:n/a}} | 100% | {{extra.gate_target_date|default:TBD}} |
| Untrusted Base64 decode sites in production code | {{source.untrusted_prod|default:n/a}} | validated | by {{meta.sla_patch_due}} |
| Crash files LIKELY / POSSIBLE | {{crashes.likely|default:0}} / {{crashes.possible|default:0}} | 0 | continuous |
| Suspicious edge tokens (period) | {{traffic.suspicious|default:0}} | monitored | continuous |

{{#if trend.available}}
## 3. Movement since last run

| | Before | Now |
| :--- | ---: | ---: |
| Exposed JVMs | {{trend.exposed_before}} | {{trend.exposed_after}} |
| Mitigation coverage | {{trend.mitigation_before|pct}} | {{trend.mitigation_after|pct}} |
| Patch coverage | {{trend.patch_before|pct}} | {{trend.patch_after|pct}} |

{{trend.improved}} JVM(s) improved, **{{trend.regressed}} regressed**, {{trend.new}} new, {{trend.gone}} no longer running.
{{#if trend.regressed_rows}}
Regressions (fix first — a regression usually means the flag was dropped by a redeploy):

| Host | PID | Command | Before | Now |
| :--- | ---: | :--- | :--- | :--- |
{{#each trend.regressed_rows}}
| {{.host}} | {{.pid}} | `{{.cmd|md}}` | {{.before}} | **{{.verdict}}** |
{{/each}}
{{/if}}
{{/if}}

## 4. Progress against the runbook plan (§8)

| Step | Activity | Evidence | State |
| :--- | :--- | :--- | :--- |
| 1 | Inventory runtimes & containers | {{fleet.hosts|default:0}} hosts, {{fleet.jvms|default:0}} JVMs; {{repos.total|default:0}} repositories scanned | {{extra.steps.1|default:in progress}} |
| 2 | Verify hardware & intrinsic state | {{fleet.hosts_vbmi|default:0}} VBMI hosts; live flag checks via jcmd | {{extra.steps.2|default:in progress}} |
| 3 | Scan source, AST & compiled JARs | {{source.total|default:0}} call sites, {{jars.classes|default:0}} classes in {{jars.artifacts|default:0}} artifacts | {{extra.steps.3|default:in progress}} |
| 4 | Trace input provenance & touchpoints | {{source.untrusted|default:0}} untrusted, {{source.internal|default:0}} internal, {{source.constant|default:0}} constant, {{source.preauth|default:0}} pre-auth | {{extra.steps.4|default:in progress}} |
| 5 | Apply immediate mitigation | {{fleet.mitigated_flag|default:0}} JVMs on flag; {{repos.mitigated_flag|default:0}} repos on flag | {{extra.steps.5|default:in progress}} |
| 6 | Verify safely & monitor side effects | crashes {{crashes.files|default:0}} triaged; edge tokens {{traffic.tokens|default:0}} analysed | {{extra.steps.6|default:in progress}} |
| 7 | Patch JDK & enforce CI gates | {{fleet.patched|default:0}} JVMs patched; gate in {{repos.with_gate|default:0}}/{{repos.java|default:0}} repos; gate {{gate.status|default:not run}} | {{extra.steps.7|default:in progress}} |

{{#if extra.business_units}}
## 5. By business unit / team

| Unit | Services | Exposed | Mitigated | Patched | Owner | Due | Status |
| :--- | ---: | ---: | ---: | ---: | :--- | :--- | :--- |
{{#each extra.business_units}}
| {{.name}} | {{.services}} | {{.exposed}} | {{.mitigated}} | {{.patched}} | {{.owner}} | {{.due}} | {{.status}} |
{{/each}}
{{/if}}

## 6. Open actions

{{#each actions}}
{{@index}}. {{.}}
{{/each}}

{{#if extra.blockers}}
## 7. Blockers and escalations

| Blocker | Impact | Owner | Needed |
| :--- | :--- | :--- | :--- |
{{#each extra.blockers}}
| {{.item}} | {{.impact}} | {{.owner}} | {{.needed}} |
{{/each}}
{{/if}}

{{#if extra.exceptions}}
## 8. Exceptions and risk acceptances

| Service | Reason | Compensating control | Approver | Expires |
| :--- | :--- | :--- | :--- | :--- |
{{#each extra.exceptions}}
| {{.service}} | {{.reason}} | {{.control}} | {{.approver}} | {{.expires}} |
{{/each}}
{{/if}}

## 9. Side effects being tracked

| Effect (docs/side-efforts) | Watch | Current reading |
| :--- | :--- | :--- |
| 04 CPU/latency from the flag | p99 latency, CPU on Base64-heavy endpoints | {{extra.side_effects.perf|default:not measured}} |
| 06 Edge rule false positives | blocked legitimate auth / API calls (count mode) | {{extra.side_effects.edge|default:count mode}} |
| 07 JAVA_TOOL_OPTIONS propagation | unintended JVMs picking up the flag (build agents, CLIs) | {{extra.side_effects.propagation|default:not observed}} |
| 08 Upgrade regressions / EOL migrations | failed canaries, services on 18–20/22–24/26 | {{extra.side_effects.upgrade|default:n/a}} |
| 10 Gate blocking releases on false positives | gate failures reclassified as noise | {{extra.side_effects.gate|default:n/a}} |

_Evidence files: {{#each inputs}}{{.key}}={{.value}}; {{/each}}_
