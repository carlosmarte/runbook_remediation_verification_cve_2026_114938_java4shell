# 02 — Scanning Plan

**Objective.** Run every kind of scan the runbook describes, at the right layer, on a schedule, with known noise
handling, and produce machine-readable evidence for the facts builder.
**Runbook basis.** §2 (runtime verification), §3 (fleet audit), §5 (bytecode), §6 (source/AST/dependency), §7.3
(search patterns), plus the GitHub scanners in `github/`.
**Owner.** Security engineering (tooling), platform (runtime access), service teams (source/bytecode).

## 0. Scan map

| Layer | Scan | Tool | Output | Cadence | Plan § |
| :--- | :--- | :--- | :--- | :--- | :--- |
| Runtime (host, container) | fleet audit | `scripts/audit_java4shell.py --pretty` | `audit-<host>.json` | T+0, daily during rollout, weekly after | A |
| Runtime (live flags, health) | non-intrusive verification | `scripts/verify_java4shell_runtime.sh [--k8s] [--health-url]` | text | before/after each change | A |
| Kubernetes | read-only inventory | `helpers/j4s_k8s.sh pods|images|missing|nodes` | text/TSV | daily during rollout | A |
| Repository estate | declared runtime scan | `github/gh_j4s_scan.py --org … --format json [--source] [--sarif-dir]` | `estate.json`, SARIF | T+0, weekly, after org-wide changes | B |
| Repository estate | discovery | `github/gh_j4s_repos.sh --org … --deep` | repo list | before each estate scan | B |
| Repository estate | pipeline posture | `github/gh_j4s_actions.sh --org … --format tsv` | `posture.tsv` | weekly | B |
| Code (wide net) | code-search sweep | `github/gh_j4s_code_search.py --org … --set …` | hits JSON/MD | T+0, then on demand | C |
| Code (precise) | source provenance scan | `scripts/scan_java4shell_source.py ROOT --json --sarif` | `src.json`, SARIF | per repo at T+2 d, per PR | D |
| Artifacts | bytecode / archive scan | `scripts/scan_java4shell_jars.py PATHS --jsonl` (or Rust `j4s-extract`) | `findings.jsonl` | per build, per repo | E |
| Dependencies | reachability over dep graph / SBOM | runbook `j4s_analyzer` (`dep_graph.py`, `reachability.py`) | `reachability-findings.json/.sarif` | per build | E |
| Manifests | policy gate | `scripts/gate_cve_2026_114938.py --scan-dir . --require-flag` | `gate.log` | every CI run | F |
| Images | tag/digest resolution | `docker run IMAGE java -version`; registry config `Env` | notes | per floating pin | G |
| Crash & traffic | triage | `helpers/j4s_hs_err.py`, `helpers/j4s_b64check.py scan` | `crashes.json`, `traffic.json` | continuous (plan 08/09) | — |

## A. Runtime scanning (hosts, containers, Kubernetes)

1. **Access.** Arrange root or JVM-owner execution on every host class (SSH, SSM, Ansible). `jcmd` needs the
   process owner; otherwise live flags read `jcmd-unavailable-or-restricted` and the flag state is unknown.
2. **Footprint review (side effect 09).** The audit spawns `java -version` per distinct JDK (short JVM start) and
   `jcmd` attaches briefly (safepoint). `helpers/j4s_proc.sh` reads `$JAVA_HOME/release` instead of spawning a JVM.
   Run off-peak on latency-sensitive hosts; never run on a host that is already crash-looping.
3. **Run.** `sudo scripts/audit_java4shell.py --pretty > audits/audit-$(hostname).json`; for a human view
   `sudo scripts/verify_java4shell_runtime.sh --k8s --health-url https://svc/health`.
4. **Kubernetes.** `helpers/j4s_k8s.sh missing -n NS` lists JVM-like containers without the flag in their spec;
   `images` lists distinct images for version classification; `nodes` gives node arch. Pod spec is not live state;
   pair with a host audit on a sample node.
5. **Collect.** One JSON per host, named by host, under a dated directory (`audits/2026-11-24/`). Keep the previous
   run for the before/after diff (`helpers/j4s_inventory.py diff`).
6. **Noise.** Build agents, IDE helpers, `jcmd` itself and the audit's own `java -version` can appear briefly;
   discard PIDs that are gone on a second pass. Containers with no shell report `exec-unavailable`; rely on
   `/proc` from the host.

## B. Repository estate scanning (GitHub)

1. **Discover.** `github/gh_j4s_repos.sh --org ORG --deep --no-archived > repos.txt` (add `--include-archived` once,
   to find archived but still-deployed services).
2. **Scan.** `github/gh_j4s_scan.py - --source --format json --out estate.json --sarif-dir sarif/ < repos.txt`.
   Raise `--max-files` for monorepos; the report says when the cap left files unread.
3. **Posture.** `github/gh_j4s_actions.sh - --track --format tsv --out posture.tsv < repos.txt`.
4. **Resolve `UNVERIFIED_*`.** Floating tags → §G; no-pin repos → ask the owner where it runs, then audit that
   runtime (§A). Record the answer in `narrative.json` for the reports.
5. **Noise.** Developer pins (`.sdkmanrc`), CI pins (`setup-java`) and docs are reported as non-runtime and do not
   drive verdicts; GraalVM-style two-component numbers are ignored; the deprecated `openjdk:17` image resolves to
   17.0.2 and is unaffected. See `github/README.md` for the scope rules.
6. **GHES / rate limits.** `--api-url` for Enterprise Server; ~5000 requests/hour cover 60–150 repos; the scanner
   sleeps on rate-limit responses.

## C. Code-search sweep (wide net)

1. Run once at T+0 per organisation: `github/gh_j4s_code_search.py --org ORG --set flags --set oracle8 --set images --set setup-java --set gate --format md --out sweep.md`.
2. Add `--set decoder --set auth` to find decoder calls across every repo, then pipe `--format repos` into the
   estate scanner with `--source`.
3. Budget: 10 requests/minute; the script paces itself. Multiple orgs/users are ORed into one query.
4. Noise: `JAVA_TOOL_OPTIONS` mentions in test code are `MENTION` (REVIEW), not findings; `.decode(` alone is not
   searched because it matches URL and charset decoders (J4S-SRC-01 notes).

## D. Source scanning (per repository, precise)

1. Checkout the default branch (and release branches in production).
2. `scripts/scan_java4shell_source.py ./src --json > src.json --sarif src.sarif`; add `--include-tests` only for
   completeness, not for verdicts.
3. Read `input_kind`: `DYNAMIC_UNTRUSTED` → plan 03 step 4 (validate); `DYNAMIC_INTERNAL` / `UNKNOWN` → review;
   `CONSTANT` → ignore. `preauth_context` marks the critical ones.
4. Upload the SARIF to code scanning so findings appear on PRs (plan 06 §4).
5. Noise (side effect 11): tests, generated code, vendored sources. The scanner classifies string literals and
   `SCREAMING_CASE` constants as `CONSTANT` even inside header-reading methods; multi-line header→decode flows need
   the AST analyzer (`j4s_analyzer/ast_taint.py`) or manual review.

## E. Bytecode, archive and dependency scanning

1. Build the artifact (or pull it from the registry/artifact store) and run
   `scripts/scan_java4shell_jars.py build/libs ~/.m2/repository --jsonl findings.jsonl` (nested archives to depth 3).
2. Treat `is_shaded = true` as real: a relocated `java.util.Base64` copy still executes the same intrinsic.
3. Treat `is_test_artifact = true` as informational (J4S-BC-04).
4. For reachability with dependency chains, run the runbook's `j4s_analyzer.cli --jsonl findings.jsonl --source-root .
   --out-json reachability-findings.json --out-sarif …`, supplying runtime context (JDK status, flag, CPU) so the
   verdict matrix (SPEC §9) yields `REACHABLE_CODE_ONLY` where mitigated.
5. SBOMs: `dep_graph.py` reads Maven/Gradle dependency trees and CycloneDX JSON (J4S-DEP-01/02); keep SBOMs per release.

## F. Manifest and policy scanning

1. Run the gate locally before pushing: `scripts/gate_cve_2026_114938.py --scan-dir . --require-flag --jvm-opts="$JAVA_TOOL_OPTIONS"`.
2. In CI as in plan 06. Save stdout+stderr as `gate.log` for the facts builder.
3. Render Helm charts and Kustomize overlays before gating so the flag set in values is visible.

## G. Image resolution (floating pins)

1. For each `UNVERIFIED_FLOATING` pin: `docker pull IMAGE:TAG && docker run --rm IMAGE:TAG java -version`, or read
   the registry image config `Env` (`JAVA_VERSION=…`) and `created` date without pulling layers.
2. Classify with `helpers/j4s_version.py parse-output`.
3. Pin the digest (`image@sha256:…`) or the exact tag once patched; record both in the repo.

## H. Schedule

| When | Scans |
| :--- | :--- |
| T+0 (day 0) | A on all hosts, B, C, G for internet-facing services |
| Daily until `exposed = 0` | A (changed hosts), Kubernetes `missing`, B for repos touched that day |
| Weekly until closure | A full, B full, posture, D/E for repos changed, before/after diff |
| Every CI run | F; D/E per build where wired |
| After hardware or base-image change | A on affected pools, G |
| Continuous | crash and traffic triage (plan 08/09) |

## I. Exit criteria

- Every scan type has run at least once on its full scope; outputs are in the evidence store named by date.
- Noise rules above are applied and documented in the report (`narrative.json` → R1 §9).
- Facts builder ingests all outputs without error (`report-template/tools/j4s_facts.py … -o facts.json`).
