# 09 — Runbook Reference Components (defined in the runbook, not shipped as files)

The runbook contains complete reference implementations that the repository intentionally does not copy into
files. They remain normative for anyone who builds them, and the shipped scripts MUST stay interoperable with
them.

## 1. Edge and reverse-proxy compensating controls (runbook §4)

**SPEC-09-01 Status.** Temporary compensating controls; never a replacement for the flag or the patch. MUST be
deployed in count / log-only mode first and promoted per route after false-positive review (side effect 06,
plan 07, report R10).

**SPEC-09-02 Detection logic (shared by all three engines).** Apply to `Authorization` / `Proxy-Authorization`
headers whose value is `Basic|Bearer` followed by a Base64-looking run of ≥ 64 characters (`J4S-EDGE-04`), and to
request bodies between 64 bytes and 1 MiB (`J4S-EDGE-05`). Flag when any of:

| ID | Shape | Regex (reference) |
| :--- | :--- | :--- |
| `J4S-EDGE-01` | three or more padding characters | `={3,}` |
| `J4S-EDGE-02` | padding followed by alphabet (mid-string `=`) | `=[A-Za-z0-9+/_-]{1,64}` |
| `J4S-EDGE-03` | 64+ run with a single terminal `=` | `[A-Za-z0-9+/_-]{64,}[^=A-Za-z0-9+/_-]?={1}(?:[^=A-Za-z0-9+/_-]|$)` |

**SPEC-09-03 Reference configurations.** The runbook provides and the plan 07 §3 cites:

- **nginx**: `map $http_authorization` selector plus `$auth_b64_check` map, a `set $block_cve_2026_114938 1|0`
  switch (0 = audit mode), optional OpenResty `access_by_lua_block` body check, `return 403` when blocking.
- **Envoy**: `envoy.filters.http.lua` with `has_malformed_b64()` applied to `authorization`/`proxy-authorization`
  and to the buffered body (64 B – 1 MiB); `logWarn` by default, `respond 403` commented out for promotion.
- **AWS WAFv2**: regex pattern set `Java4ShellMalformedBase64PatternSet` with the three regexes; Web ACL rules
  `Block-CVE-2026-114938-AuthHeader-MalformedB64` (priority 10, `SingleHeader authorization`) and
  `Block-CVE-2026-114938-Body-MalformedB64` (priority 11, `Body` with `OversizeHandling: CONTINUE`), CloudWatch
  metrics `CVE2026114938AuthHeaderMalformedB64` / `CVE2026114938BodyMalformedB64`; start with `Count` action.

**SPEC-09-04 Verification.** A staged replay of `QUJD====` MUST return 403 in block mode or appear in sampled
requests in count mode (plan 10). `helpers/j4s_b64check.py` MUST classify the same token as `J4S-EDGE-01`
suspicious, so log analysis and edge rules agree.

## 2. Rust bytecode and archive extractor `j4s-extract` (runbook §5)

**SPEC-09-05.** Cargo package `j4s-extract` 0.1.0 (deps `anyhow`, `rayon`, `serde`, `serde_json`, `walkdir`,
`zip`). CLI: `j4s-extract [ROOT] [OUT.jsonl]`; walks `ROOT` for `.class/.jar/.war/.ear/.zip`, parses class
constant pools in parallel, recurses nested archives to depth 3, and writes one JSON line per class with Base64
invocations using the `Finding` struct: `artifact_path`, `entry_path`, `is_test_artifact`, `is_shaded`,
`class_name`, `method_name`, `method_descriptor`, `invoked_targets[]`, `constant_strings_sample[]` (≤ 16 strings
≤ 120 chars), `evidence_refs[]`. Matching rules are `J4S-BC-01…06`.

**SPEC-09-06 Interoperability.** `scripts/scan_java4shell_jars.py` MUST emit byte-compatible JSONL
(SPEC-02-26) so either tool can feed `j4s_analyzer`, and the CI workflow MAY use whichever is built.

## 3. Python reachability and SARIF analyzer `j4s_analyzer` (runbook §6)

**SPEC-09-07 Modules.** `models.py` (`InputKind`, `ReachabilityVerdict`, `EvidenceItem`, `DependencyPath`,
`ReachabilityFinding`), `ast_taint.py` (`SOURCE_PATTERNS`, `BASE64_CALL_RE`, tree-sitter when available with
regex fallback), `dep_graph.py` (`DependencyGraph.load_cyclonedx_json`, `load_tree_text`, `shortest_chain_to`,
`resolve_for_finding`), `reachability.py` (`RuntimeContext.from_dict`, `evaluate_reachability`), `reporters.py`
(`write_json_report`, `write_sarif_report`), `cli.py`.

**SPEC-09-08 CLI.**

```
python3 -m j4s_analyzer.cli --jsonl findings.jsonl [--source-root DIR] [--sbom-cyclonedx FILE] [--dep-tree FILE]
   [--runtime-json FILE] [--out-json reachability-findings.json] [--out-sarif reachability-findings.sarif] [--fail-on-high]
```

`--runtime-json` accepts the fleet audit JSON (SPEC-02-15: reads `cpu.arch`, `cpu.avx512_vbmi`) or a flat
object with `arch`, `avx512_vbmi`, `mitigation_flag_present`, `jdk_patched`.

**SPEC-09-09 Output.** JSON `{cve, alias, summary{total_findings, by_verdict{}}, findings[]}` with finding IDs
`J4S-0001…`; SARIF 2.1.0 with rule `CVE-2026-114938/BASE64-VBMI` (`Java4ShellBase64VbmiReachability`), level
`error` for `REACHABLE_HIGH`, `warning` for `REACHABLE_CODE_ONLY`, `note` otherwise, properties carrying
`findingId`, `verdict`, `confidence`, `inputKind`, `inputSources`, `isTest`, `isShaded`, `dependencyChain`,
`evidence[]`. Verdict logic per SPEC-01-12. `--fail-on-high` exits 1 on any `REACHABLE_HIGH`.
`scripts/gate_cve_2026_114938.py --reachability-json` MUST read this JSON (`findings[].verdict`,
`finding_id`, `class_name`, `method_name`, `artifact_path`).

**SPEC-09-10 Known limitation.** AST correlation joins bytecode records to source by simple class name (file
stem); the shipped `scan_java4shell_source.py` provides the more precise per-call-site classification and
SHOULD be preferred for `DYNAMIC_UNTRUSTED` decisions.

## 4. CI workflow examples (runbook §7.2)

**SPEC-09-11 GitHub Actions** `.github/workflows/cve-2026-114938-gate.yml`: triggers on `pull_request` and
`push` to `main` and `release/**`; permissions `contents: read`, `security-events: write`; steps: checkout,
setup-python 3.12, run `scripts/gate_cve_2026_114938.py --scan-dir . --require-flag --jvm-opts
"${JAVA_TOOL_OPTIONS:-}"`, optionally run `j4s-extract` + `j4s_analyzer` + gate with `--reachability-json`,
upload SARIF via `github/codeql-action/upload-sarif@v3` when the file exists.

**SPEC-09-12 GitLab CI** `.gitlab-ci.yml`: stage `security-gate`, image `python:3.12-slim`, variable
`JAVA_TOOL_OPTIONS: "-XX:-UseBASE64Intrinsics"`, script runs the gate with `--require-flag`, rules for merge
requests, default branch and `release/` branches.

**SPEC-09-13 Detection by the posture scanner.** `github/gh_j4s_actions.sh` and `gh_j4s_scan.py` MUST recognise
a workflow as the gate when its name, path or contents reference `gate_cve_2026_114938` or `CVE-2026-114938`
(`J4S-ID-01`).

## 5. Quick search patterns (runbook §7.3)

**SPEC-09-14.** The three quick regexes (Java decoder calls, auth/JWT/SAML decoding context, JVM flags and
options) and the `/proc/cpuinfo` AVX-512 one-liner are catalogued as `J4S-SRC-01`, `J4S-SRC-04`, `J4S-FLAG-01`
and `J4S-RT-03`; `patterns/SPEC.md` §10 carries the ripgrep forms.

## 6. Runbook text superseded by this specification

**SPEC-09-15.** The following runbook code behaviours are recorded as superseded (details in SPEC-01-05,
SPEC-01-07, SPEC-02-03, SPEC-05-08): `JDK_VER_RE` / `parse_semver4` 4-component parsing; `classify_flag_text`
without `=` delimiter; manifest Java-workload detection by `java|jdk|jvm` words only; bash audit treating
`17.x` (`minor != 0`) as unaffected; `ast_taint.classify_expression` promoting literal arguments to
`DYNAMIC_UNTRUSTED` when sources appear in the context window; the fixed 15/5-line context window. A runbook
revision that adopts the corrections closes these entries.
