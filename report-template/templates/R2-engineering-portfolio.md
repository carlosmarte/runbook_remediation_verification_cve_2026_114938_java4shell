{{! ============================================================================
R2 - Engineering Portfolio View
Audience : VP Engineering, directors, engineering managers who own several services
SDLC     : plan / release (prioritisation and capacity)
Cadence  : weekly
Inputs   : --gh-scan estate.json --actions posture.tsv --audit audits/*.json; --extra with service_owners{} (repo -> owner/team/tier)
============================================================================ }}
# {{meta.cve}} ({{meta.alias}}) — Engineering Portfolio

{{meta.org}} · {{meta.scope}} · {{meta.report_date}} · status **{{status.rag}}**

## 1. Portfolio in one table

| Verdict | Repos | Meaning | What the team must do |
| :--- | ---: | :--- | :--- |
| `EXPOSED` | {{repos.exposed|default:0}} | Runtime pins a vulnerable JDK, no flag | Flag today, upgrade this sprint |
| `EXPLICITLY_ENABLED` | {{repos.explicitly_enabled|default:0}} | `-XX:+UseBASE64Intrinsics` present | Remove the flag today |
| `MITIGATED_FLAG` | {{repos.mitigated_flag|default:0}} | Flag present, JDK still vulnerable | Upgrade within SLA ({{meta.sla_patch_due}}) |
| `UNVERIFIED_FLOATING` | {{repos.unverified_floating|default:0}} | Floating tag (`:21-jre`, distro package) | Rebuild after the fix, pin exact tag or digest |
| `UNVERIFIED_NO_PIN` | {{repos.unverified_no_pin|default:0}} | Runtime defined outside the repo | Name the platform/host; audit it |
| `PATCHED` | {{repos.patched|default:0}} | Baseline met | Remove flag when fleet is patched |

Java repositories: **{{repos.java|default:0}}** (of {{repos.total|default:0}} scanned). Release gate adopted by {{repos.gate_adoption|pct|default:n/a}}. Pre-auth Base64 decoding found in {{repos.repos_with_preauth|count|default:0}} repositories.

## 2. Work queue, worst first

| # | Repository | Verdict | Runtime JDK pins | Flag | Gate | Pre-auth decode | Owner / team | Tier | Due |
| ---: | :--- | :--- | :--- | :--- | :--- | ---: | :--- | :--- | :--- |
{{#each repos.rows}}
| {{@index}} | [{{.repo}}]({{.url}}) | `{{.verdict}}` | {{.pins|md}} | {{.flag}} | {{.gate|yesno}} | {{.preauth}} | {{.owner|default:unassigned}} | {{.tier|default:-}} | {{.due|default:-}} |
{{/each}}

{{! Owners/tier/due come from --extra service_owners when the facts builder is extended, or are filled in by hand. }}

## 3. Capacity and sequencing

| Workstream | Items | Effort guide | Sequence |
| :--- | ---: | :--- | :--- |
| Flag rollout (`JAVA_TOOL_OPTIONS`, manifests, Helm values) | {{repos.exposed|default:0}} repos + {{fleet.exposed_vbmi|default:0}} running JVMs | hours per service; canary first on Base64-heavy endpoints | 1 |
| Remove explicit re-enable | {{repos.explicitly_enabled|default:0}} | minutes | 1 |
| JDK upgrade to {{meta.baselines}} | {{repos.exposed|default:0}} + {{repos.mitigated_flag|default:0}} repos | 0.5–2 days per service incl. regression tests | 2 |
| EOL migrations (18–20 → 21, 22–24 → 25, 26 → 27) | {{extra.eol_services|default:see pins containing 18–20/22–24/26}} | days to weeks | 3 (own plan) |
| Pin floating images / packages | {{repos.unverified_floating|default:0}} | hours | 2 |
| Identify runtime for no-pin repos | {{repos.unverified_no_pin|default:0}} | hours (platform team) | 2 |
| Add release gate workflow | {{repos.without_gate|count|default:0}} | 30 min per repo (copy `.github/workflows/cve-2026-114938-gate.yml`) | 2 |
| Input validation before decode | {{source.untrusted_prod|default:n/a}} call sites | hours per site + tests | 3 |

## 4. Repositories without a release gate

{{#if repos.without_gate}}
{{#each repos.without_gate}}
- {{.}}
{{/each}}
{{else}}
All Java repositories carry a gate workflow, or no repository scan was supplied.
{{/if}}

{{#if posture.available}}
## 5. Pipeline posture ({{posture.repos}} repositories)

| Gate workflow present | Gate required on default branch | Last run passing / failing | Flag in Actions variables | Re-enabled via variables | Open code-scanning J4S alerts | Dependabot alerts |
| ---: | ---: | :--- | ---: | ---: | ---: | ---: |
| {{posture.with_gate}} | {{posture.gate_required}} | {{posture.gate_passing}} / {{posture.gate_failing}} | {{posture.var_active}} | {{posture.var_reenabled}} | {{posture.cs_alerts}} | {{posture.dependabot}} |
{{/if}}

## 6. Risks to delivery

- Upgrade regressions: run the service test suite on the target JDK before switching the image (`docs/side-efforts/08`).
- Performance: measure CPU and p99 on Base64-heavy endpoints before and after the flag (`docs/side-efforts/04`).
- `JAVA_TOOL_OPTIONS` is host-global: prefer per-service launch args where several JVMs share a host (`docs/side-efforts/07`).
- Gate false positives on vendor tags are documented (`patterns/J4S-VER-01.md`); the shipped gate uses the corrected parser.

## 7. Recommended actions

{{#each actions}}
{{@index}}. {{.}}
{{/each}}
