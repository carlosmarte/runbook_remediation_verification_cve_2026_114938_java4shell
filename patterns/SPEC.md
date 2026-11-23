# Search Pattern SPEC — CVE-2026-114938 ("Java4Shell")

**Source of truth:** `../cve_2026_114938_java4shell_remediation_verification_runbook.md`
**Spec version:** 1.1.0 (2026-11-20)
**Status:** Active

This SPEC indexes every search / match pattern used across the runbook (runtime
verification, fleet audit, bytecode extractor, reachability analyzer, CI gate, and
edge controls) into one file per pattern (`patterns/J4S-<AREA>-<NN>.md`) so remediation work can
reference a single pattern ID instead of re-deriving regexes from scripts.

---

## 0. How to use this SPEC

1. Pick the **remediation phase** you are in (Section 9 maps runbook steps to pattern IDs).
2. Run the patterns for that phase against the stated **target surface**.
3. A **match** means the listed **action** applies. A non-match is *not* proof of safety
   unless the pattern's notes say so.
4. Regex flavor is noted per pattern. `PCRE`/`ERE` patterns run with `rg`/`grep -E`;
   `Python` patterns need `re`; `Lua` and `nginx` patterns are engine-specific.

Conventions:

| Field | Meaning |
| :--- | :--- |
| **ID** | Stable identifier `J4S-<AREA>-<NN>`. Reference this in tickets, gate output, PR descriptions. |
| **Surface** | What to run the pattern against (Java source, bytecode, Dockerfile, K8s manifest, `/proc`, HTTP request, etc.). |
| **Flavor** | `ERE` (grep -E / rg), `PCRE` (rg -P), `Python`, `Lua`, `nginx`, `bash-glob`. |
| **Severity on match** | `INFO`, `REVIEW`, `MITIGATE`, `BLOCK`. `BLOCK` = CI gate fails. |

---

## 1. Vulnerability identity patterns

Use these to find existing references, tickets, advisories, and prior work.

| ID | Pattern | File |
| :--- | :--- | :--- |
| `J4S-ID-01` | CVE / alias / upstream ID | [J4S-ID-01.md](J4S-ID-01.md) |
| `J4S-ID-02` | Weakness classes referenced by the advisory | [J4S-ID-02.md](J4S-ID-02.md) |

## 2. Java source patterns (reachability of `java.util.Base64` decoding)

| ID | Pattern | File |
| :--- | :--- | :--- |
| `J4S-SRC-01` | Quick Base64 decoder call grep (runbook §7.3) | [J4S-SRC-01.md](J4S-SRC-01.md) |
| `J4S-SRC-02` | Precise decoder invocation with argument capture (`BASE64_CALL_RE`, runbook §6 `ast_taint.py`) | [J4S-SRC-02.md](J4S-SRC-02.md) |
| `J4S-SRC-03` | Untrusted input source signatures (`SOURCE_PATTERNS`, runbook §6) | [J4S-SRC-03.md](J4S-SRC-03.md) |
| `J4S-SRC-04` | Auth / JWT / SAML / Basic decoding context (runbook §7.3) | [J4S-SRC-04.md](J4S-SRC-04.md) |
| `J4S-SRC-05` | File pre-filter (cheap gate before AST/regex) | [J4S-SRC-05.md](J4S-SRC-05.md) |

## 3. Bytecode / archive patterns (`j4s-extract`, runbook §5)

| ID | Pattern | File |
| :--- | :--- | :--- |
| `J4S-BC-01` | Scannable artifact extensions | [J4S-BC-01.md](J4S-BC-01.md) |
| `J4S-BC-02` | Base64 owner class in constant pool (`is_base64_target`) | [J4S-BC-02.md](J4S-BC-02.md) |
| `J4S-BC-03` | Base64 method names of interest | [J4S-BC-03.md](J4S-BC-03.md) |
| `J4S-BC-04` | Test artifact heuristic (`looks_like_test_path`) | [J4S-BC-04.md](J4S-BC-04.md) |
| `J4S-BC-05` | Shaded / relocated heuristic (`looks_like_shaded`) | [J4S-BC-05.md](J4S-BC-05.md) |
| `J4S-BC-06` | Class file magic | [J4S-BC-06.md](J4S-BC-06.md) |

## 4. JVM flag / option patterns (mitigation state)

Mitigation is **present** when either `-XX:-UseBASE64Intrinsics` or `-XX:UseAVX=<0..2>` is active.

| ID | Pattern | File |
| :--- | :--- | :--- |
| `J4S-FLAG-01` | Broad flag/option locator (runbook §7.3) | [J4S-FLAG-01.md](J4S-FLAG-01.md) |
| `J4S-FLAG-02` | Mitigation present (strict, token-bounded) — `classify_flag_text`, runbook §2 | [J4S-FLAG-02.md](J4S-FLAG-02.md) |
| `J4S-FLAG-03` | Mitigation present via AVX cap — `classify_flag_text` | [J4S-FLAG-03.md](J4S-FLAG-03.md) |
| `J4S-FLAG-04` | Intrinsic explicitly re-enabled (anti-pattern) | [J4S-FLAG-04.md](J4S-FLAG-04.md) |
| `J4S-FLAG-05` | Mitigation present (loose, fleet audit) — `check_cmdline_mitigation` / `check_cmdline_flags` | [J4S-FLAG-05.md](J4S-FLAG-05.md) |
| `J4S-FLAG-06` | Mitigation present (CI gate) — `MITIGATION_FLAG_RE`, runbook §7.1 | [J4S-FLAG-06.md](J4S-FLAG-06.md) |
| `J4S-FLAG-07` | Mitigation present (Kubernetes manifest scan) — `flag_re`, runbook §2 | [J4S-FLAG-07.md](J4S-FLAG-07.md) |
| `J4S-FLAG-08` | JVM option environment variables | [J4S-FLAG-08.md](J4S-FLAG-08.md) |
| `J4S-FLAG-09` | Live JVM flag extraction from `jcmd <pid> VM.flags -all` | [J4S-FLAG-09.md](J4S-FLAG-09.md) |

## 5. JDK version patterns

| ID | Pattern | File |
| :--- | :--- | :--- |
| `J4S-VER-01` | Vendor-prefixed JDK version in text (`JDK_VER_RE`, runbook §7.1) | [J4S-VER-01.md](J4S-VER-01.md) |
| `J4S-VER-01b` | Supplementary version extractor (underscore and 5-component aware) | [J4S-VER-01b.md](J4S-VER-01b.md) |
| `J4S-VER-02` | Vulnerable Oracle Java 8 perf build (`JAVA8_PERF_RE`) | [J4S-VER-02.md](J4S-VER-02.md) |
| `J4S-VER-03` | Version token from `java -version` output (fleet audit) | [J4S-VER-03.md](J4S-VER-03.md) |
| `J4S-VER-04` | Numeric tuple parser | [J4S-VER-04.md](J4S-VER-04.md) |
| `J4S-VER-05` | Vulnerable range decision table | [J4S-VER-05.md](J4S-VER-05.md) |

## 6. Runtime / process discovery patterns

| ID | Pattern | File |
| :--- | :--- | :--- |
| `J4S-RT-01` | JVM process detection via memory maps | [J4S-RT-01.md](J4S-RT-01.md) |
| `J4S-RT-02` | Derive `JAVA_HOME/bin/java` from `libjvm.so` path | [J4S-RT-02.md](J4S-RT-02.md) |
| `J4S-RT-03` | AVX-512 CPU feature flags | [J4S-RT-03.md](J4S-RT-03.md) |
| `J4S-RT-04` | JVM-like Kubernetes container heuristic | [J4S-RT-04.md](J4S-RT-04.md) |
| `J4S-RT-05` | Java workload mention (CI gate, manifests) | [J4S-RT-05.md](J4S-RT-05.md) |
| `J4S-RT-06` | Container process ID list | [J4S-RT-06.md](J4S-RT-06.md) |

## 7. Dependency / SBOM patterns (`dep_graph.py`, runbook §6)

| ID | Pattern | File |
| :--- | :--- | :--- |
| `J4S-DEP-01` | Maven/Gradle dependency tree line | [J4S-DEP-01.md](J4S-DEP-01.md) |
| `J4S-DEP-02` | CycloneDX JSON fields | [J4S-DEP-02.md](J4S-DEP-02.md) |

## 8. Edge / WAF compensating-control patterns (runbook §4)

These detect **malformed trailing padding** in Base64-looking payloads ≥ 64 chars. Deploy in **count / log-only** mode first; they are temporary and do not replace patching or the JVM flag.

| ID | Pattern | File |
| :--- | :--- | :--- |
| `J4S-EDGE-01` | Three or more padding characters | [J4S-EDGE-01.md](J4S-EDGE-01.md) |
| `J4S-EDGE-02` | Padding followed by Base64 alphabet (mid-string `=`) | [J4S-EDGE-02.md](J4S-EDGE-02.md) |
| `J4S-EDGE-03` | Long run with single terminal `=` | [J4S-EDGE-03.md](J4S-EDGE-03.md) |
| `J4S-EDGE-04` | Auth header candidate selector (nginx) | [J4S-EDGE-04.md](J4S-EDGE-04.md) |
| `J4S-EDGE-05` | Body size window | [J4S-EDGE-05.md](J4S-EDGE-05.md) |

---

## 9. Remediation phase → pattern map (runbook §8)

| Step | Runbook action | Pattern IDs |
| :--- | :--- | :--- |
| 1 | Inventory runtimes & containers | RT-01, RT-02, RT-06, VER-01, VER-01b, VER-03, FLAG-08, RT-04 |
| 2 | Verify hardware & intrinsic state | RT-03, FLAG-02, FLAG-03, FLAG-04, FLAG-09 |
| 3 | Scan source, AST & compiled JARs | SRC-01 … SRC-05, BC-01 … BC-06, DEP-01, DEP-02 |
| 4 | Trace input provenance & touchpoints | SRC-03, SRC-04 |
| 5 | Apply immediate mitigation | FLAG-01 (locate), FLAG-02/03 (confirm), FLAG-09 (live) |
| 6 | Verify safely & monitor | FLAG-09, RT-03, EDGE-01 … EDGE-05 (log-only) |
| 7 | Patch JDK & enforce CI gates | VER-01, VER-01b, VER-02 … VER-05, FLAG-06, RT-05, BC-04 (verdict), gate on `REACHABLE_HIGH` |

### Verdict matrix (`evaluate_reachability`)

| Condition | Verdict | Confidence |
| :--- | :--- | :--- |
| `is_test` | `CONDITIONAL_LOW` | MEDIUM |
| JDK patched **or** flag present **or** non-VBMI CPU, input `DYNAMIC_UNTRUSTED` | `REACHABLE_CODE_ONLY` | HIGH |
| JDK patched **or** flag present **or** non-VBMI CPU, other input | `UNREACHABLE_OR_N_A` | HIGH |
| unmitigated, input `DYNAMIC_UNTRUSTED` | `REACHABLE_HIGH` (**BLOCK**) | HIGH |
| unmitigated, input `DYNAMIC_INTERNAL` / `UNKNOWN` | `CONDITIONAL_LOW` | MEDIUM |

---

## 10. Quick ripgrep recipes

```bash
# Where are JVM options set in this repo?  (FLAG-01)
rg -n -e '(-XX:[+-]?UseBASE64Intrinsics|-XX:UseAVX=[0-9]|JAVA_TOOL_OPTIONS|JDK_JAVA_OPTIONS)'

# Is the intrinsic explicitly re-enabled anywhere?  (FLAG-04)
rg -n -e '-XX:\+UseBASE64Intrinsics'

# Base64 decoder call sites in source  (SRC-01, prefiltered by SRC-05)
rg -n -t java -e '\b(Base64\.(getDecoder|getUrlDecoder|getMimeDecoder)|getDecoder\(\)|getUrlDecoder\(\)|getMimeDecoder\(\))'

# Pre-auth decoding touchpoints  (SRC-04; -i because Bearer/Basic are capitalized in code)
rg -n -i -P -e '\b(Authorization|Proxy-Authorization|Basic\s+[A-Za-z0-9+/=_-]+|jwt|jws|saml|bearer)\b.{0,120}\b(Base64|decode|getDecoder)\b'

# JDK versions pinned in Dockerfiles / manifests  (VER-01, VER-02)
rg -n -i -o -P -e '(?<![\d.])(\d+\.\d+\.\d+(?:\.\d+)?)(?:_\d+)?(?![\d.])' -g 'Dockerfile*' -g '*.yml' -g '*.yaml'
rg -n -i -e '8u511b33-perf'

# Shaded / relocated Base64 copies in built artifacts (list entries, then BC-02)
unzip -l app.jar | rg -i -e '(shaded|shadow|repack|reloc).*Base64'
```

Files/dirs the CI gate skips: `.git`, `target`, `node_modules`, `.venv`, `venv`.
Gate file selectors: `dockerfile`, `dockerfile.*`, `*.yaml`, `*.yml`.

---

## 11. Remediation outcome per pattern class

| Pattern class | On match, do |
| :--- | :--- |
| `SRC-*` / `BC-*` with `DYNAMIC_UNTRUSTED` | Add `-XX:-UseBASE64Intrinsics` now; validate Base64 input (reject `={3,}`, mid-string `=`, bad length) before decode; schedule JDK patch. |
| `FLAG-04` on `VULN_RANGE` JDK | Remove `-XX:+UseBASE64Intrinsics`; fail the gate. |
| `FLAG-02/03/05/06/07` absent on Java workload | Add flag via `JAVA_TOOL_OPTIONS`, container args, or manifest `env`; re-verify with `FLAG-09`. |
| `VER-05` = `VULN_RANGE` | Upgrade to `17.0.21.0.3`+ / `21.0.13.1`+ / `25.0.5.1`+ / `27.0.1.1`+ (or vendor equivalent); retire EOL lines 18–20, 22–24, 26. |
| `VER-02` | Replace Oracle `8u511b33-perf` build. |
| `RT-03` `avx512_vbmi` false or non-x86_64 | Host not in hardware scope; still patch for portability (verdict `REACHABLE_CODE_ONLY`). |
| `EDGE-*` hits in log-only mode | Tune false positives on JWT/SAML/form posts, then switch to block; keep until fleet is patched. |

---

## Change log

| Version | Date | Change |
| :--- | :--- | :--- |
| 1.1.0 | 2026-11-20 | Split into one file per pattern; SPEC.md becomes the index. |
| 1.0.0 | 2026-11-20 | Initial extraction from runbook sections 2, 3, 4, 5, 6, 7, 8. Added VER-01b and documented two verified gaps in the runbook's `JDK_VER_RE`. |
