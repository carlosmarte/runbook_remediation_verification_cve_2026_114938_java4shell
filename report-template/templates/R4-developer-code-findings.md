{{! ============================================================================
R4 - Developer Code Findings (pull request / code review level)
Audience : Developers, code reviewers, AppSec champions
SDLC     : develop / code review (also usable verbatim as a PR comment or issue body)
Cadence  : per scan of a repository or per PR
Inputs   : --source src.json (scan_java4shell_source.py --json) --jars findings.jsonl --gate gate.log [--gh-scan repo.json]
============================================================================ }}
## {{meta.cve}} ({{meta.alias}}) — Base64 decoding findings{{#if extra.repo}} for `{{extra.repo}}`{{/if}}

{{#if extra.pr}}_PR #{{extra.pr.number}} ({{extra.pr.branch}}) — scanned {{meta.report_date}}_{{else}}_Scanned {{meta.report_date}}_{{/if}}

{{#if source.available}}
**{{source.total}}** `java.util.Base64` decode call sites in {{source.files}} files
· **{{source.untrusted}} decode untrusted input** ({{source.untrusted_prod}} in production code)
· {{source.internal}} internal · {{source.constant}} constant · {{source.unknown}} unknown
· {{source.preauth}} sit in an authentication / token path.

### Must fix before merge (untrusted input)

{{#if source.untrusted_rows}}
| File:line | Call | Argument | Sources | Pre-auth | Fix |
| :--- | :--- | :--- | :--- | :--- | :--- |
{{#each source.untrusted_rows}}
| `{{.file}}:{{.line}}` | `{{.call|md}}` | `{{.argument|md}}` | {{.sources|join}} | {{.preauth_context|yesno}} | {{.remediation|md}} |
{{/each}}

Reference fix (validate before decode; keep it even after the JDK upgrade):

```java
static byte[] decodeStrict(String s) {
    if (s == null || s.length() % 4 != 0 || s.contains("===")) throw new IllegalArgumentException("bad base64");
    int pad = s.indexOf('=');
    if (pad >= 0 && pad < s.length() - 2) throw new IllegalArgumentException("padding inside body");
    if (!s.matches("[A-Za-z0-9+/]*={0,2}")) throw new IllegalArgumentException("alphabet");
    return java.util.Base64.getDecoder().decode(s);
}
```
{{else}}
None. 🎉
{{/if}}

### Review (internal / constant / unknown provenance, production code)

{{#if source.review_rows}}
| File:line | Call | Argument | Input kind | Why |
| :--- | :--- | :--- | :--- | :--- |
{{#each source.review_rows}}
| `{{.file}}:{{.line}}` | `{{.call|md}}` | `{{.argument|md}}` | {{.input_kind}} | {{.reason|md}} |
{{/each}}
{{else}}
None.
{{/if}}

{{#if source.test}}_{{source.test}} finding(s) in test code are listed in the JSON but not blocking (pattern J4S-BC-04 / side effect 11)._{{/if}}
{{else}}
_No source scan supplied. Run `scripts/scan_java4shell_source.py <root> --json > src.json`._
{{/if}}

{{#if jars.available}}
### Compiled artifacts

{{jars.classes}} class(es) in {{jars.artifacts}} artifact(s) reference Base64 decoding; **{{jars.shaded}} shaded copies** (a relocated `java.util.Base64` in a dependency still runs on the same vulnerable intrinsic). {{jars.test}} test artifacts excluded from the verdict.

| Artifact | Class | Targets | Shaded | Test |
| :--- | :--- | :--- | :--- | :--- |
{{#each jars.rows}}
| `{{.artifact_path|md}}` | `{{.class_name}}` | {{.invoked_targets|join|md}} | {{.is_shaded|yesno}} | {{.is_test_artifact|yesno}} |
{{/each}}
{{/if}}

{{#if gate.available}}
### Release gate: **{{gate.status}}**

{{#each gate.violations}}
- {{.}}
{{/each}}
{{#if gate.passed}}No violations.{{/if}}
{{/if}}

{{#if repos.available}}
### Runtime definition in this repository

| Verdict | Runtime JDK pins | Flag | Gate workflow |
| :--- | :--- | :--- | :--- |
{{#each repos.rows}}
| `{{.verdict}}` | {{.pins|md}} | {{.flag}} | {{.gate|yesno}} |
{{/each}}
{{/if}}

### What to do in this PR

1. Validate every untrusted Base64 input before `decode()` (see reference fix); add a negative test with `QUJD====` and `QU=JD`.
2. If this repo owns a Dockerfile or manifest: set `JAVA_TOOL_OPTIONS=-XX:-UseBASE64Intrinsics` and pin the JDK to {{meta.baselines}}.
3. Never add `-XX:+UseBASE64Intrinsics` (J4S-FLAG-04); the gate fails on it.
4. Keep `scripts/gate_cve_2026_114938.py --scan-dir . --require-flag` green.

<sub>Patterns: J4S-SRC-01..05, J4S-BC-01..06, J4S-FLAG-04/06, J4S-VER-05 · runbook §5–§7 · false positives: docs/side-efforts/11</sub>
