# 11 — Scanner Noise from Test, Shaded, and Generic Decode Call Sites

**Origin:** static analysis (runbook §5 `j4s-extract`, §6 `j4s_analyzer`, §7.3 quick patterns)
**Impact:** Low (triage time, alert fatigue). **Likelihood:** High on any sizeable codebase.

## What happens

The scanners are intentionally broad so they do not miss reachable paths. The side effect is volume:

- **Every `java.util.Base64` use is a finding.** The bytecode extractor emits one record per class that references `getDecoder`, `getUrlDecoder`, `getMimeDecoder`, `decode`, or `wrap` on the Base64 owner, regardless of what is decoded. Decoding a compiled-in constant is harmless but still reported until the analyzer classifies it `CONSTANT`.
- **Test artifacts** are flagged and merely downgraded to `CONDITIONAL_LOW` (`J4S-BC-04`); they still appear in SARIF and in the report counts. Test fixtures often decode malformed Base64 deliberately.
- **Shaded and relocated copies** (`J4S-BC-05`) create duplicate findings for the same library across every service that bundles it, and dependency-chain resolution by Maven coordinate fails for them, so the "which upgrade fixes this" answer is missing.
- **The quick grep (`J4S-SRC-01`) includes `.decode(` and `.wrap(`**, which match `URLDecoder.decode`, `CharsetDecoder.decode`, `ByteBuffer.wrap`, `Collections.unmodifiable...wrap`, and many non-Base64 calls.
- **Source classification is regex-driven** when tree-sitter is absent. The `DYNAMIC_UNTRUSTED` labels fire on tokens like `Message`, `Scanner`, or `InputStream` appearing anywhere in a 20-line window (`J4S-SRC-03`), so a log line mentioning "message" can promote a constant decode to `REACHABLE_HIGH` and, through the gate (effect 10), block a release.
- **SARIF upload** to GitHub Code Scanning turns each finding into an alert that someone must dismiss, and alerts persist across runs.

## Who feels it

- Application security engineers triaging the first full-fleet scan.
- Developers who receive code-scanning alerts on test code and vendored libraries.
- Library owners pinged for every shaded copy of their artifact.

## How to detect it

- Finding counts far exceeding the number of distinct Base64 call sites in source.
- Many findings with `is_test_artifact: true` or `is_shaded: true`.
- `REACHABLE_HIGH` verdicts whose argument expression is a literal or a `SCREAMING_CASE` constant.

## How to limit it

- Run the full pipeline (extract → analyze with source root and SBOM → gate), not the extractor alone; the analyzer is what turns raw hits into verdicts.
- Install `tree-sitter-java` so classification uses real method-invocation nodes instead of line regexes.
- Exclude test directories and `test-classes` from the SARIF upload while keeping them in the internal report.
- De-duplicate shaded findings by library class name and fix them at the library or base-image level once.
- Use the precise invocation regex (`J4S-SRC-02`) rather than the quick grep for anything that feeds a gate; reserve `J4S-SRC-01` for interactive exploration.
- Review `DYNAMIC_UNTRUSTED` promotions whose only source label is `messaging_or_net` with the word `Message`; tighten the window or the label list for your codebase.
- Remember what the scanner result does and does not mean: a finding is a place where the JVM flag or patch matters, not a confirmed exploit path. The fix is the same (flag, then patch) regardless of count.

## Runbook and pattern references

- Runbook §5 (`is_base64_target`, `looks_like_test_path`, `looks_like_shaded`), §6 (`SOURCE_PATTERNS`, `classify_expression`, `evaluate_reachability`), §7.3.
- Patterns: `J4S-SRC-01..05`, `J4S-BC-02..05`, `J4S-DEP-01`.
