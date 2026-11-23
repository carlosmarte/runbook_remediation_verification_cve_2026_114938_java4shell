# 04 — GitHub Estate Scanners (`github/`)

Four scripts that audit GitHub repositories for the CVE **without cloning**, through the REST API (Python,
`urllib`) or the `gh` CLI (Bash). They apply runbook §1 (baselines), §2 (flag state), §7 (gate, search
patterns) and §8 steps 1/5/7 to everything a user or organisation owns.

## 1. Common requirements

**SPEC-04-01 Dependencies.** Bash 3.2+ and `gh` 2.x for the shell scripts; Python 3.9+ standard library for the
Python scripts. No third-party modules.

**SPEC-04-02 Read-only.** Nothing writes to GitHub. The SARIF upload command in the README is documentation for
the operator, not a script action.

**SPEC-04-03 Authentication.** Token resolution order for Python: `--token`, `$GH_TOKEN`, `$GITHUB_TOKEN`,
`gh auth token`. Unauthenticated use is permitted for public repositories (60 req/h, no code search). GHES via
`--api-url` / `$GITHUB_API_URL` (Python) or `--hostname` (Bash). Endpoints the token cannot read print `n/a` /
`unknown` rather than failing the run.

**SPEC-04-04 Rate limits.** Primary limit responses are honoured by sleeping until reset (capped by
`--max-wait`, default 300 s). Code search is spaced by `--search-interval` (default 6.5 s for the 10/min limit)
and sleeps on `403`/`429`. Concurrency `--workers` × `--file-workers` SHOULD stay under ~20.

**SPEC-04-05 Self-test.** `gh_j4s_scan.py --self-test` and `gh_j4s_code_search.py --self-test` run offline
checks of parsers, version table and verdict logic and exit non-zero on any failure. The acceptance matrix
(document 10) requires both to pass.

## 2. `gh_j4s_repos.sh` — discovery

**SPEC-04-06 CLI.**

```
gh_j4s_repos.sh (--user LOGIN | --org ORG | --me | --search QUERY)
   [--language LIST] [--all-languages] [--deep] [--topic T[,T]]
   [--include-archived | --only-archived] [--include-forks | --only-forks] [--visibility public|private|internal]
   [--pushed-since YYYY-MM-DD] [--name-regex RE] [--limit N] [--format list|tsv|csv|json|ndjson] [--out FILE] [--hostname HOST]
```

Defaults: language filter `java,kotlin,scala,groovy,clojure` on the primary language (`--deep` matches any
language), archived and forks excluded, limit 1000, format `list` (one `owner/repo` per line, pipeable into the
other three scripts via `-`).

## 3. `gh_j4s_scan.py` — remote repository scan

**SPEC-04-07 What it reads.** Default branch only. Candidate files in priority order, capped by `--max-files`
(80) and `--max-file-size` (512 KB): `Dockerfile*`/`Containerfile`; `.java-version`, `.sdkmanrc`,
`.tool-versions`, `.mise.toml`, `system.properties`, `.jabbarc`; `docker-compose*.yml`; `.github/workflows/*`;
`.gitlab-ci.yml`, `.travis.yml`, `Jenkinsfile`, `Procfile`, `jvm.options`, `.mvn/jvm.config`; other YAML
(deploy/k8s/helm/charts/kustomize paths first); `pom.xml`, Gradle files; `*.service`, `*.vmoptions`, `*.tf`,
`*.hcl`; entrypoint/start scripts; `.env*`; ECS task definitions; `application*.properties`. Vendored
directories (`node_modules`, `vendor`, `target`, `build`, `dist`, `.gradle`, `third_party`) are skipped. When
the cap leaves candidates unread the report says so and a `PATCHED` verdict is downgraded to
`UNVERIFIED_FLOATING`.

Every version or flag finding carries a **scope**: `runtime` (Dockerfiles, compose, Kubernetes/Helm, systemd,
start scripts, Terraform, `system.properties`), `build` (CI paths, `pom.xml`, Gradle, `.mvn/`, `.devcontainer/`),
`dev` (`.sdkmanrc`, `.java-version`, `.tool-versions`, `.mise.toml`, `.jabbarc`), `docs` (`docs/`,
`documentation/`, `examples/`, `samples/`, `demo/`). **Only `runtime` findings decide the verdict**; others are
reported with their scope and may add reasons/actions.

Version sources and kinds: Dockerfile `FROM` with `ARG`/`ENV` expansion and multi-stage aliases skipped
(`EXACT` for full tags, `FLOATING` for major-only such as `eclipse-temurin:21-jre`); `image:` in YAML/HCL/JSON;
Java-mentioning lines with a version (`ENV JAVA_VERSION=jdk-21.0.12+7`, download URLs); distro packages
(`openjdk-17-jre-headless` → `FLOATING`); pin files (`java=21.0.12-tem` → `EXACT`); `actions/setup-java`
`java-version` with matrix resolution (build scope); `pom.xml` / Gradle toolchain levels (`LANGUAGE_LEVEL`,
evidence only).

**SPEC-04-08 Verdicts (per repository, worst-first).**

| Verdict | Rule |
| :--- | :--- |
| `NOT_JAVA` | no JVM language, build file, JDK pin or JVM flag on the default branch |
| `ERROR` | repository not accessible or API failure (`error` field set) |
| `EXPOSED` | a `runtime` pin is `VULN_RANGE` and no mitigation flag in any `runtime` file |
| `EXPLICITLY_ENABLED` | `-XX:+UseBASE64Intrinsics` found (`J4S-FLAG-04`) and the JDK is not proven patched |
| `MITIGATED_FLAG` | `ACTIVE`/`CAPPED` present in a `runtime` file; JDK may still be vulnerable |
| `UNVERIFIED_FLOATING` | only floating or digest-only runtime pins (patched only if built after the fix), or `PATCHED` downgraded by the file cap |
| `UNVERIFIED_NO_PIN` | Java workload but the repository does not define its runtime (platform image, host JDK, Helm values elsewhere, only `setup-java` or `.sdkmanrc`) |
| `PATCHED` | every `runtime` pin meets its baseline |

Each result carries `reasons[]` (one sentence per contributing finding, first one printed in tables) and
`actions[]` (what to do). A repository without a gate workflow that is not `NOT_JAVA`/`PATCHED` gets an "add the
gate" action.

**SPEC-04-09 CLI.**

```
gh_j4s_scan.py [REPO|URL|-]... [--user LOGIN]... [--org ORG]... [--me] [--repos-file FILE]
   [--affiliation owner,collaborator,organization_member] [--org-type all|public|private|forks|sources|member] [--limit N]
   [--language LIST] [--all-languages] [--deep-languages] [--include-archived] [--include-forks]
   [--visibility public|private|internal] [--pushed-since YYYY-MM-DD] [--name-regex RE] [--topic T]...
   [--source] [--source-mode search|paths|both] [--max-source-files N] [--max-files N] [--max-file-size BYTES]
   [--languages-api] [--track-issues] [--strict]
   [--format table|json|ndjson|csv|md] [--out FILE] [--sarif-dir DIR] [--repos-out FILE]
   [--token T] [--api-url URL] [--workers N] [--file-workers N] [--max-wait S] [--timeout S] [-v] [--self-test]
```

**SPEC-04-10 `--source`.** Adds `source_hits[]`: `J4S-SRC-01` decoder calls and `J4S-SRC-04` single-line
pre-auth context, on `.java/.kt/.scala/.groovy/.clj/.jsp`. File selection by one code-search request per
repository (`Base64 repo:owner/name`) with path heuristics as fallback; `--source-mode paths` avoids code
search. Capped by `--max-source-files` (25). The README MUST state that provenance-aware verdicts require
`scripts/scan_java4shell_source.py` on a checkout.

**SPEC-04-11 Output contract (`--format json`).** The document is the dataclass tree serialised with
`asdict`; the fields below are the contract (additional fields MAY appear).

```json
{"cve": "CVE-2026-114938", "alias": "Java4Shell", "tool": "gh_j4s_scan", "tool_version": "...", "generated_at": "...",
 "scope": "org:acme", "api_url": "https://api.github.com",
 "summary": {"repos": 6, "by_verdict": {"EXPOSED": 1}, "exposed": ["acme/payments-api"], "explicitly_enabled": [],
             "unverified": ["..."], "without_ci_gate": ["..."], "errors": []},
 "repos": [{"repo": "acme/payments-api", "html_url": "...", "default_branch": "main", "archived": false, "fork": false,
            "private": true, "pushed_at": "...", "primary_language": "Java", "languages": {"Java": 12345},
            "tree_truncated": false, "files_candidates": 12, "files_skipped": 0, "files_fetched": ["Dockerfile"],
            "java_evidence": ["pom.xml"], "is_java": true, "verdict": "EXPOSED",
            "versions": [{"path": "Dockerfile", "line": 1, "source": "dockerfile-from", "raw": "eclipse-temurin:21.0.12_7-jre",
                          "kind": "EXACT", "status": "VULN_RANGE", "normalized": "21.0.12", "major": 21,
                          "baseline": "21.0.13.1", "reason": "...", "action": "...", "scope": "runtime"}],
            "flags": [{"path": "k8s/deploy.yaml", "line": 31, "state": "ACTIVE", "text": "...", "scope": "runtime"}],
            "source_hits": [{"path": "src/.../Auth.java", "line": 42, "pattern_id": "J4S-SRC-04", "snippet": "...", "pre_auth_context": true}],
            "source_mode": "search", "gate_ci": {"github_workflows": [".github/workflows/cve-2026-114938-gate.yml"], "gitlab_ci": false},
            "cve_mentions": [], "tracking": {}, "reasons": ["..."], "actions": ["..."], "error": null}]}
```

`versions[].source` is one of `dockerfile-from`, `image-ref`, `dockerfile-arg-env`, `setup-java`, `travis-jdk`,
`sdkmanrc`, `java-version-file`, `tool-versions`, `mise`, `system-properties`, `package-manager`,
`pom-language-level`, `gradle-language-level`, `generic`. `versions[].status` is `VULN_RANGE`,
`PATCHED_OR_UNAFFECTED`, `FLOATING_PATCHABLE`, `UNKNOWN` or `LANGUAGE_LEVEL`; `flags[].state` is `ACTIVE`,
`CAPPED`, `EXPLICITLY_ENABLED` or `MENTION`.

`report-template/tools/j4s_facts.py` consumes `repos[].verdict`, `versions[].{raw,normalized,status,kind,scope}`,
`flags[].{state,scope}`, `gate_ci`, `source_hits[].pre_auth_context`, `reasons`, `actions`, `is_java`,
`primary_language`, `pushed_at`. These MUST remain stable.

**SPEC-04-12 Other formats.** `table` (default; columns REPO, VERDICT, RUNTIME JDK PINS, FLAG, GATE, SRC-HITS,
NOTE), `ndjson`, `csv` (scope in brackets), `md` (summary plus detail sections for `EXPOSED`,
`EXPLICITLY_ENABLED`, `MITIGATED_FLAG`, `UNVERIFIED_FLOATING`). `--sarif-dir` writes one SARIF 2.1.0 file per
repository with rules `J4S-VER-05`, `J4S-VER-FLOAT`, `J4S-FLAG-04`, `J4S-FLAG-06`, `J4S-SRC-01`, `J4S-SRC-04`,
named `<owner>__<repo>.sarif`.

**SPEC-04-13 Exit codes.** `2` when any repository is `EXPOSED` or `EXPLICITLY_ENABLED` (`--strict` adds the two
`UNVERIFIED_*`), `1` on execution error, else `0`.

## 4. `gh_j4s_code_search.py` — wide sweep

**SPEC-04-14 Behaviour.** Runs the runbook's search terms as GitHub code-search queries across `--user`,
`--org`, `--repo` scopes (packed into one query per term up to the 256-character limit because repeated
qualifiers are ORed), fetches each matched file (unless `--no-fetch`) and applies the exact pattern regex so each
hit has a file, line number and severity.

| `--set` | Queries | Local verification | Severity |
| :--- | :--- | :--- | :--- |
| `decoder` | `Base64 getDecoder`, `getUrlDecoder`, `getMimeDecoder` | `J4S-SRC-01` (+ `J4S-SRC-04` when auth context on the line) | REVIEW / MITIGATE |
| `auth` | `Authorization Base64`, `Bearer Base64 decode`, `jwt Base64 decode`, `saml Base64 decode` | `J4S-SRC-04` | MITIGATE |
| `flags` | `UseBASE64Intrinsics`, `JAVA_TOOL_OPTIONS`, `JDK_JAVA_OPTIONS`, `UseAVX` | `J4S-FLAG-02` ACTIVE (INFO), `-03` CAPPED (INFO), `-04` EXPLICITLY_ENABLED (BLOCK), `-01` MENTION (REVIEW) | per hit |
| `oracle8` | `8u511b33` | `J4S-VER-02` | BLOCK |
| `images` | `FROM <vendor>` in Dockerfiles for temurin, corretto, openjdk, zulu, liberica, sapmachine, graalvm | `J4S-VER-05` on the tag | BLOCK if `VULN_RANGE`, REVIEW if floating |
| `setup-java` | `setup-java java-version` under `.github/workflows` | `J4S-VER-05` on the CI JDK | REVIEW |
| `gate` | `gate_cve_2026_114938`, `CVE-2026-114938` | `J4S-ID-01` | INFO |

Default sets: `decoder flags oracle8 images setup-java gate`.

**SPEC-04-15 CLI.**

```
gh_j4s_code_search.py [--user LOGIN]... [--org ORG]... [--repo OWNER/REPO]... [--extra-qualifiers Q]
   [--set NAME]... [--max-hits N] [--no-fetch] [--format table|json|ndjson|csv|md|repos] [--out FILE]
   [--min-severity INFO|REVIEW|MITIGATE|BLOCK] [--token T] [--api-url URL] [--search-interval S] [--max-wait S] [--timeout S] [-v] [--self-test]
```

`--format repos` prints only the affected `owner/repo` list for piping into `gh_j4s_scan.py -`. Exit `2` when any
hit is `BLOCK` or `MITIGATE`.

**SPEC-04-16 Documented platform facts.** The README MUST state: authentication mandatory for code search;
default branches and files under 384 KB only; 1000 results per query; 10 requests/minute; indexing lag and
GHES/large-estate unavailability; `--source-mode paths` as the fallback.

## 5. `gh_j4s_actions.sh` — CI/CD and security posture

**SPEC-04-17 CLI.**

```
gh_j4s_actions.sh [REPO...|-] [--user LOGIN | --org ORG | --me] [--language LIST] [--all-languages] [--limit N]
   [--require-gate] [--track] [--org-vars] [--format table|tsv|json|ndjson] [--out FILE] [--hostname HOST]
```

**SPEC-04-18 Columns (TSV order is the contract for `j4s_facts.py`).**

`REPO LANG ARCHIVED BRANCH GATE_WORKFLOW GATE_LAST_RUN GATE_REQUIRED VAR_FLAG CODE_SCANNING DEPENDABOT TRACKING`

| Column | Source | Values |
| :--- | :--- | :--- |
| `GATE_WORKFLOW` | `/actions/workflows` names/paths, then file contents for `gate_cve_2026_114938` / the CVE | file names or `none` |
| `GATE_LAST_RUN` | latest run of that workflow | `success <date> <branch>`, `failure …`, `no-runs`, `none` |
| `GATE_REQUIRED` | rulesets `/rules/branches/<default>`, then classic required status checks | `yes`, `no`, `unknown` |
| `VAR_FLAG` | repository (and `--org-vars` organisation) Actions variables `JAVA_TOOL_OPTIONS`, `JDK_JAVA_OPTIONS`, `_JAVA_OPTIONS`, `JAVA_OPTS`; secret names containing `JAVA` | `ACTIVE`, `CAPPED`, `EXPLICITLY_ENABLED`, `MISSING`, `NONE`, `n/a`; `(secret:NAME)` suffix |
| `CODE_SCANNING` | open alerts whose rule id/description matches `J4S`, `CVE-2026-114938`, `java4shell`, `UseBASE64`, `Base64Vbmi` | count or `n/a` |
| `DEPENDABOT` | open alerts whose advisory lists the CVE | count or `n/a` |
| `TRACKING` | with `--track`: open issues / PRs mentioning CVE or alias | `<n>i/<m>pr` |

**SPEC-04-19 Exit codes.** `2` when any repository has `EXPLICITLY_ENABLED`, open J4S code-scanning alerts, open
Dependabot alerts for the CVE, or (with `--require-gate`) no gate workflow; `1` when a repository was not
accessible; else `0`.

## 6. Known limits (documentation requirement)

**SPEC-04-20.** `github/README.md` MUST keep a "Known limits" section stating at least: default branch only;
floating tags are not resolved; a `PATCHED` repository can still run an old JDK on a host (pair with runtime
verification); Helm values, platform images and Buildpacks hide the runtime; code-search availability limits;
no exploit payloads and no writes.
