{{! ============================================================================
R7 - GitHub Estate Scan Report (repositories of a user / organisation)
Audience : AppSec, platform engineering, engineering managers
SDLC     : plan / develop / build (what the code declares about its runtime)
Cadence  : weekly; immediately after an org-wide flag or image change
Inputs   : --gh-scan estate.json (github/gh_j4s_scan.py --format json [--source]) --actions posture.tsv (github/gh_j4s_actions.sh)
           optional code-search sweep summary pasted into extra.code_search
============================================================================ }}
# {{meta.cve}} ({{meta.alias}}) — GitHub Estate Scan

{{meta.org}} · scope `{{repos.scope|default:n/a}}` · scanned {{repos.generated_at|default:n/a}} · report {{meta.report_date}} · status **{{status.rag}}**

## 1. Verdict distribution

| Verdict | Repos | Share of Java repos |
| :--- | ---: | ---: |
| `EXPOSED` | {{repos.exposed|default:0}} | |
| `EXPLICITLY_ENABLED` | {{repos.explicitly_enabled|default:0}} | |
| `MITIGATED_FLAG` | {{repos.mitigated_flag|default:0}} | |
| `UNVERIFIED_FLOATING` | {{repos.unverified_floating|default:0}} | {{repos.floating_share|pct|default:0%}} |
| `UNVERIFIED_NO_PIN` | {{repos.unverified_no_pin|default:0}} | |
| `PATCHED` | {{repos.patched|default:0}} | |
| `NOT_JAVA` | {{repos.not_java|default:0}} | — |
| `ERROR` | {{repos.error|default:0}} | — |

**{{repos.java|default:0}} Java repositories** of {{repos.total|default:0}} scanned · blocking (EXPOSED + EXPLICITLY_ENABLED) **{{repos.blocking|default:0}}** ({{repos.exposed_share|pct|default:0%}}) · unverified {{repos.unverified_share|pct|default:0%}} · gate adoption {{repos.gate_adoption|pct|default:0%}} · Base64 decode sites found {{repos.source_hits|default:0}} ({{repos.preauth_hits|default:0}} pre-auth) in {{repos.repos_with_preauth|count|default:0}} repos.

## 2. Insights

- **Exposure is declared, not guessed.** `EXPOSED` means a runtime file (Dockerfile, manifest, service unit) pins a JDK in the vulnerable range and no runtime file sets the flag. Developer pins (`.sdkmanrc`), CI pins (`setup-java`) and docs do not count.
- **Floating tags are the largest unknown.** {{repos.unverified_floating|default:0}} repositories use `:21-jre`-style tags or distro packages; whether they are patched depends on the build date, so each needs an exact version from the image (`docker run IMAGE java -version`) or a digest pin.
- **Runtime defined elsewhere.** {{repos.unverified_no_pin|default:0}} Java repositories carry no runtime pin at all; their JDK is set by a platform image, Helm values repo or host. Those owners must be named.
- **Gate coverage.** {{repos.without_gate|count|default:0}} Java repositories have no workflow referencing the gate; a flag added today can be removed by the next PR unnoticed.

## 3. Blocking repositories (fix now)

{{#if repos.exposed_rows}}
| Repository | Verdict | Runtime JDK pins | Flag | Gate | Pre-auth decode | Reason |
| :--- | :--- | :--- | :--- | :--- | ---: | :--- |
{{#each repos.exposed_rows}}
| [{{.repo}}]({{.url}}) | `{{.verdict}}` | {{.pins|md}} | {{.flag}} | {{.gate|yesno}} | {{.preauth}} | {{.reason|md}} |
{{/each}}
{{else}}
None.
{{/if}}

## 4. Mitigated by flag (upgrade pending)

{{#if repos.mitigated_rows}}
| Repository | Runtime JDK pins | Flag | Gate |
| :--- | :--- | :--- | :--- |
{{#each repos.mitigated_rows}}
| [{{.repo}}]({{.url}}) | {{.pins|md}} | {{.flag}} | {{.gate|yesno}} |
{{/each}}
{{else}}
None.
{{/if}}

## 5. Unverified repositories

{{#if repos.unverified_rows}}
| Repository | Verdict | Pins seen | Language | Last push | Reason |
| :--- | :--- | :--- | :--- | :--- | :--- |
{{#each repos.unverified_rows}}
| [{{.repo}}]({{.url}}) | `{{.verdict}}` | {{.pins|md}} | {{.language}} | {{.pushed_at}} | {{.reason|md}} |
{{/each}}
{{else}}
None.
{{/if}}

## 6. Full table

| Repository | Verdict | Runtime JDK pins | Flag | Gate | Decode sites | Pre-auth |
| :--- | :--- | :--- | :--- | :--- | ---: | ---: |
{{#each repos.rows}}
| [{{.repo}}]({{.url}}) | `{{.verdict}}` | {{.pins|md}} | {{.flag}} | {{.gate|yesno}} | {{.hits}} | {{.preauth}} |
{{/each}}

{{#if posture.available}}
## 7. Pipeline posture

| Repos | Gate workflow | Gate required | Passing / failing | Flag via Actions vars | Re-enabled via vars | J4S code-scanning alerts | Dependabot |
| ---: | ---: | ---: | :--- | ---: | ---: | ---: | ---: |
| {{posture.repos}} | {{posture.with_gate}} | {{posture.gate_required}} | {{posture.gate_passing}} / {{posture.gate_failing}} | {{posture.var_active}} | {{posture.var_reenabled}} | {{posture.cs_alerts}} | {{posture.dependabot}} |
{{/if}}

{{#if extra.code_search}}
## 8. Code-search sweep

| Pattern set | Hits | Repositories | Severity ≥ MITIGATE |
| :--- | ---: | ---: | ---: |
{{#each extra.code_search}}
| {{.set}} | {{.hits}} | {{.repos}} | {{.blocking}} |
{{/each}}
{{/if}}

## 9. Method and limits

Default branch only; files read: Dockerfiles, compose/Kubernetes/Helm/Actions YAML, `.sdkmanrc`/`.java-version`/`.tool-versions`, `pom.xml`/Gradle, service units, start scripts, Terraform (cap {{extra.max_files|default:80}} files per repo). Versions compared with the five-component rule against {{meta.baselines}}; floating tags are not resolved. Source hits use single-line patterns (J4S-SRC-01/04); for provenance run `scripts/scan_java4shell_source.py` on a checkout. See `github/README.md`.

## 10. Actions

{{#each actions}}
{{@index}}. {{.}}
{{/each}}
