{{! ============================================================================
R0 - Executive Brief (one page)
Audience : Board risk committee, CISO, CIO, business unit executives
SDLC     : cross-phase (operate + remediation programme)
Cadence  : at disclosure (T+24h), then weekly until GREEN, then at closure
Inputs   : fleet audits, GitHub estate scan, optional crash/traffic evidence ->
           tools/j4s_facts.py --audit audits/*.json --gh-scan estate.json [--crashes ..] [--b64 ..] -o facts.json
Rule     : one page, no file paths, no PIDs. Numbers come from facts.json; judgement comes from the author.
============================================================================ }}
# {{meta.cve}} ("{{meta.alias}}") — Executive Brief

| | |
| :--- | :--- |
| **Organisation / scope** | {{meta.org}} — {{meta.scope}} |
| **Report date** | {{meta.report_date}} (day {{meta.days_since_disclosure}} after public disclosure on {{meta.disclosure_date}}) |
| **Overall status** | **{{status.rag}}** |
| **Prepared by / owner** | {{meta.prepared_by}} / {{meta.owner}} |
| **Classification** | {{meta.classification}} |

## 1. What this is

A critical, pre-authentication remote code execution flaw ({{meta.cvss31}} CVSS 3.1, {{meta.cvss40}} CVSS 4.0) in the Java
runtime's Base64 decoder on modern x86-64 servers with AVX-512 VBMI (Intel Ice Lake and newer, AMD Zen 4 and newer).
Any Java service that decodes attacker-controlled Base64 — HTTP Basic auth, JWT/SAML tokens, file uploads — can be
crashed or taken over. Patched Java builds are available ({{meta.baselines}}); a single JVM start-up flag
(`{{meta.mitigation_flag}}`) removes the exposure immediately at a small CPU cost.

## 2. Where we stand

{{#if fleet.available}}
| Runtime fleet | Value |
| :--- | ---: |
| Hosts audited / on affected hardware | {{fleet.hosts}} / {{fleet.hosts_vbmi}} |
| Java processes found | {{fleet.jvms}} |
| **Exposed now** (vulnerable version, no flag, affected CPU) | **{{fleet.exposed_vbmi}}** ({{fleet.exposure_rate|pct}}) |
| Protected by flag or patch | {{fleet.mitigation_coverage|pct}} |
| Fully patched | {{fleet.patch_coverage|pct}} |
| Vulnerable but on unaffected hardware | {{fleet.unverified}} |
{{else}}
_Runtime fleet audit not yet available for this scope._
{{/if}}

{{#if repos.available}}
| Source & deployment estate (GitHub) | Value |
| :--- | ---: |
| Java repositories scanned | {{repos.java}} of {{repos.total}} |
| **Deploy a vulnerable JDK without mitigation** | **{{repos.blocking}}** ({{repos.exposed_share|pct}}) |
| Mitigated by flag, upgrade still due | {{repos.mitigated_flag}} |
| Cannot be verified from the repository (floating tag / runtime defined elsewhere) | {{repos.unverified_floating}} + {{repos.unverified_no_pin}} ({{repos.unverified_share|pct}}) |
| Patched | {{repos.patched}} |
| Pipelines enforcing the release gate | {{repos.with_gate}} of {{repos.java}} ({{repos.gate_adoption|pct}}) |
{{/if}}

{{#if trend.available}}
**Trend since last report:** exposed JVMs {{trend.exposed_before}} → {{trend.exposed_after}}; protected {{trend.mitigation_before|pct}} → {{trend.mitigation_after|pct}}; patched {{trend.patch_before|pct}} → {{trend.patch_after|pct}}. {{trend.improved}} improved, {{trend.regressed}} regressed, {{trend.new}} new.
{{/if}}

{{#if crashes.available}}{{#if crashes.likely}}**Exploitation indicators:** {{crashes.likely}} JVM crash file(s) match the exploit signature and are being handled as a security incident (see R8).{{/if}}{{/if}}
{{#if traffic.available}}{{#if traffic.suspicious}}**Probing observed:** {{traffic.suspicious}} malformed Base64 token(s) matching the trigger shape were seen at the edge.{{/if}}{{/if}}

## 3. Why the status is {{status.rag}}

{{#each status.reasons}}
- {{.}}
{{/each}}

## 4. Decisions requested

{{#if extra.decisions}}
{{#each extra.decisions}}
{{@index}}. **{{.title}}** — {{.ask}} _(owner: {{.owner}}, needed by {{.by}})_
{{/each}}
{{else}}
1. **Approve emergency change window** for flag rollout to remaining exposed services. _(owner: {{meta.owner}})_
2. **Accept temporary CPU/latency increase** on Base64-heavy services while the flag is active.
3. **Fund EOL migrations** for services on Java 18–20 / 22–24 / 26, which have no patch.
{{/if}}

## 5. Plan and dates

| Milestone | Target | Status |
| :--- | :--- | :--- |
| Flag live on every exposed JVM (SLA {{meta.sla_mitigate_days}} days) | {{meta.sla_mitigate_due}} | {{#if meta.sla_mitigate_breached}}{{#if fleet.exposed_vbmi}}**BREACHED**{{else}}met{{/if}}{{else}}in progress{{/if}} |
| Patched JDK on every service (SLA {{meta.sla_patch_days}} days) | {{meta.sla_patch_due}} | {{#if meta.sla_patch_breached}}{{#if fleet.patch_coverage}}see patch coverage{{else}}**BREACHED**{{/if}}{{else}}in progress{{/if}} |
| Release gate enforced in every Java pipeline | {{extra.gate_target_date|default:TBD}} | {{repos.gate_adoption|pct|default:—}} |
{{#each extra.milestones}}
| {{.item}} | {{.date}} | {{.status}} |
{{/each}}

## 6. Residual risk and side effects to expect

- Services relying on the flag remain on vulnerable builds until upgraded; the flag is a stop-gap, not a fix.
- Base64-heavy services may show higher CPU and latency with the flag; benchmarks are part of each rollout.
- Edge/WAF blocking rules can reject legitimate logins and API calls until tuned; they run in count mode first.
- Hosts without AVX-512 VBMI are not exploitable today but become exposed on the next hardware migration.

_Next review: {{meta.next_review}}. Detail reports: R1 programme status, R6 runtime verification, R7 GitHub estate._
