# 05 — Pattern Catalogue (`patterns/`)

The catalogue indexes every search or match pattern used across the runbook and the shipped components into
one file per pattern, so tickets, gate output, PR descriptions and SARIF rules can reference a stable ID instead
of a regex.

## 1. Structure

**SPEC-05-01 Index.** `patterns/SPEC.md` is the index. It carries a version (`1.1.0`, 2026-11-20), a status, a
"How to use" section, the conventions table, one table per area linking each pattern file, the phase map,
the verdict matrix, ripgrep recipes, the outcome-per-class table and a change log. Adding or changing a pattern
MUST bump the version and add a change-log row.

**SPEC-05-02 Identifier.** `J4S-<AREA>-<NN>` with optional letter suffix for a supplementary variant
(`J4S-VER-01b`). Identifiers are stable: a withdrawn pattern keeps its file with a "Superseded by" note; numbers
are never reused.

**SPEC-05-03 Pattern file.** `patterns/<ID>.md` MUST contain, in order: title `# <ID> — <name>`; `**Area:**`;
`**Source:**` (runbook path); `**Index:**` link; then bullet fields `Surface`, `Flavor`, optional `Result label` /
`Capture group`, a fenced ```regex``` (or table for decision patterns) block, and optional `Known gap` notes
with the verification date and the corrected form.

**SPEC-05-04 Fields.**

| Field | Allowed values |
| :--- | :--- |
| Surface | Java source, bytecode, Dockerfile, K8s manifest, `/proc` cmdline/environ, `java -version` text, HTTP request header/body, dependency tree, CycloneDX JSON, logs |
| Flavor | `ERE` (grep -E / rg), `PCRE` (rg -P), `Python`, `Lua`, `nginx`, `bash-glob`, `AWS WAF regex`, decision table |
| Severity on match | `INFO`, `REVIEW`, `MITIGATE`, `BLOCK` |

## 2. Areas and inventory (41 patterns)

| Area | IDs | Purpose |
| :--- | :--- | :--- |
| 1 Identity | `ID-01` CVE/alias/upstream id; `ID-02` CWE classes | find prior references |
| 2 Java source | `SRC-01` quick decoder grep; `SRC-02` precise invocation with argument capture; `SRC-03` untrusted-source signatures; `SRC-04` auth/JWT/SAML context; `SRC-05` file pre-filter | reachability of `java.util.Base64` decoding |
| 3 Bytecode | `BC-01` scannable extensions; `BC-02` owner class incl. relocated; `BC-03` method names; `BC-04` test-artifact heuristic; `BC-05` shaded heuristic; `BC-06` class magic | `j4s-extract` / `scan_java4shell_jars.py` |
| 4 JVM flags | `FLAG-01` broad locator; `FLAG-02` strict ACTIVE; `FLAG-03` strict CAPPED; `FLAG-04` explicit re-enable; `FLAG-05` loose (fleet audit); `FLAG-06` loose (CI gate); `FLAG-07` manifest scan; `FLAG-08` env variable names; `FLAG-09` live `jcmd` extraction | mitigation state |
| 5 Versions | `VER-01` vendor-prefixed version (gap recorded); `VER-01b` underscore/5-component extractor; `VER-02` Oracle 8 perf; `VER-03` `java -version` token; `VER-04` numeric tuple parser; `VER-05` vulnerable range decision table | version classification |
| 6 Runtime | `RT-01` JVM via `libjvm.so` in maps; `RT-02` `JAVA_HOME` from `libjvm.so` path; `RT-03` AVX-512 CPU flags; `RT-04` JVM-like K8s container; `RT-05` Java workload mention; `RT-06` container PID list | process discovery |
| 7 Dependencies | `DEP-01` Maven/Gradle tree line; `DEP-02` CycloneDX fields | `dep_graph.py` |
| 8 Edge | `EDGE-01` `={3,}`; `EDGE-02` padding followed by alphabet; `EDGE-03` 64+ run with single terminal `=`; `EDGE-04` nginx auth-header selector; `EDGE-05` body size window (64 B – 1 MiB) | WAF / proxy compensating controls |

## 3. Semantics

**SPEC-05-05 Match semantics.** A match means the pattern's action applies. A non-match is **not** proof of
safety unless the pattern's notes say so. Patterns are tested against the stated surface only.

**SPEC-05-06 Phase map.** `SPEC.md` §9 MUST map each of the seven runbook steps to pattern IDs:

| Step | Pattern IDs |
| :--- | :--- |
| 1 Inventory | RT-01, RT-02, RT-06, VER-01, VER-01b, VER-03, FLAG-08, RT-04 |
| 2 Verify hardware & intrinsic | RT-03, FLAG-02, FLAG-03, FLAG-04, FLAG-09 |
| 3 Scan source, AST, JARs | SRC-01…05, BC-01…06, DEP-01, DEP-02 |
| 4 Trace provenance | SRC-03, SRC-04 |
| 5 Apply mitigation | FLAG-01 (locate), FLAG-02/03 (confirm), FLAG-09 (live) |
| 6 Verify & monitor | FLAG-09, RT-03, EDGE-01…05 (log-only) |
| 7 Patch & gate | VER-01, VER-01b, VER-02…05, FLAG-06, RT-05, BC-04, gate on `REACHABLE_HIGH` |

**SPEC-05-07 Outcome per class.** `SPEC.md` §11 MUST state the remediation on match for: `SRC-*`/`BC-*` with
`DYNAMIC_UNTRUSTED` (flag now, validate input, schedule patch); `FLAG-04` on vulnerable JDK (remove, fail gate);
`FLAG-02/03/05/06/07` absent on Java workload (add via env/args/manifest, re-verify with `FLAG-09`); `VER-05` =
`VULN_RANGE` (upgrade to baseline, retire EOL lines); `VER-02` (replace build); `RT-03` false / non-x86-64 (not in
hardware scope, still patch, verdict `REACHABLE_CODE_ONLY`); `EDGE-*` log-only hits (tune, then block, keep until
patched).

## 4. Known gaps register

**SPEC-05-08.** Verified defects in runbook regexes are recorded in the pattern file with date and corrected
form, and the shipped components implement the correction. Current register:

| Pattern | Gap | Correction | Implemented in |
| :--- | :--- | :--- | :--- |
| `J4S-VER-01` | `\b` fails before `_` (`21.0.12_7` unmatched); 4-component capture misreads `17.0.21.0.3` | `J4S-VER-01b`; five-component comparison (SPEC-01-02) | `scripts/*`, `helpers/j4s_version.py`, `github/*` |
| `J4S-FLAG-02/03/04` | leading class `[[:space:]"]` lacks `=`; env `JAVA_TOOL_OPTIONS=-XX:-…` reported `NOT_SET` | `(^|[[:space:]"=])` (SPEC-01-07) | `scripts/verify_java4shell_runtime.sh`, helpers, `github/` |
| `J4S-VER-05` | bash audit treats `17.x` (`minor != 0`) as unaffected | stricter gate rule: unlisted shapes are `VULN_RANGE` | gate, helpers, GitHub scanners |

## 5. Ripgrep recipes

**SPEC-05-09.** `SPEC.md` §10 MUST provide copy-paste `rg` recipes for: locating JVM option settings
(`FLAG-01`), explicit re-enable (`FLAG-04`), source decoder call sites (`SRC-01` with `SRC-05` prefilter),
pre-auth touchpoints (`SRC-04`, `-i -P`), pinned versions in Dockerfiles/manifests (`VER-01b`, `VER-02`), and
shaded Base64 copies in built artifacts (`unzip -l | rg`), plus the gate's skipped directories and file
selectors.

## 6. Cross-references

**SPEC-05-10.** Every component README, planning document, report template and side-effect note that applies a
pattern MUST cite its ID. SARIF rule IDs emitted by `gh_j4s_scan.py` reuse pattern IDs (SPEC-04-12).
