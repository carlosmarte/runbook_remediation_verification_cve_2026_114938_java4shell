# GitHub Scanners — CVE-2026-114938 ("Java4Shell")

Self-contained scripts that audit GitHub repositories for CVE-2026-114938 **without cloning them**,
using the GitHub REST API (Python, `urllib`) or the `gh` CLI (Bash). They apply the checks of
`../cve_2026_114938_java4shell_remediation_verification_runbook.md` §1 (version baselines), §2
(flag state), §7 (CI gate, search patterns) and §8 step 1/5/7 to everything a user or organization
owns, or to any filtered repository set. Pattern IDs refer to `../patterns/SPEC.md`.

No third-party dependencies: Bash 3.2+ (macOS default works), Python 3.9+ standard library, `gh` 2.x
for the Bash scripts. Nothing here writes to GitHub; every call is a read.

| Script | Backend | Scope | What it answers |
| :--- | :--- | :--- | :--- |
| `gh_j4s_repos.sh` | `gh repo list` / `gh search repos` | `--user`, `--org`, `--me`, `--search` | Which repositories should I look at? Filters by JVM language (primary or any), topic, archived/fork, visibility, push date, name regex. Emits `owner/repo` lines for the other scripts. |
| `gh_j4s_scan.py` | REST API (`urllib`) | explicit repos, stdin, `--user`, `--org`, `--me` | Per repository: which JDK versions are pinned and are they vulnerable (J4S-VER-01/01b/02/05), is `-XX:-UseBASE64Intrinsics` / `-XX:UseAVX=0..2` set in the runtime definition (J4S-FLAG-02/03/06), is the intrinsic explicitly re-enabled (J4S-FLAG-04), is a CI gate present (runbook §7.2), optionally where does source decode Base64 and in what context (J4S-SRC-01/04). One verdict per repo. |
| `gh_j4s_code_search.py` | REST code search | `--user`, `--org`, `--repo` (repeatable) | Wide sweep: runs the runbook's search terms as code-search queries, fetches every matched file and applies the exact regexes, so each hit has a line number and a severity. Prints the affected repository list for piping into the scanner. |
| `gh_j4s_actions.sh` | `gh api` | explicit repos, stdin, `--user`, `--org`, `--me` | CI/CD and security posture: gate workflow present and its last run, gate required as a status check (rulesets or classic protection), Actions variables carrying the flag, open code-scanning alerts for J4S rules, Dependabot alerts naming the CVE, open tracking issues/PRs. |

All four are also reachable as `j4s gh-repos`, `j4s gh-scan`, `j4s gh-search`, `j4s gh-actions`
(`../helpers/j4s`).

## Quick start

```bash
chmod +x github/*.sh github/*.py
gh auth login                      # or export GH_TOKEN / GITHUB_TOKEN

# Offline sanity check of the parsers and the version table
github/gh_j4s_scan.py --self-test
github/gh_j4s_code_search.py --self-test

# 1. Everything one organization owns, deep scan, Markdown report + one SARIF per repo
github/gh_j4s_scan.py --org acme --format md --out acme-java4shell.md --sarif-dir sarif/

# 2. Discover first, then scan (lets you review the list, add --deep for repos where Java is not the primary language)
github/gh_j4s_repos.sh --org acme --language java,kotlin --deep --pushed-since 2025-01-01 > repos.txt
github/gh_j4s_scan.py - --source --format json --out acme.json < repos.txt

# 3. A user's repositories, including the source scan for Base64 decode call sites
github/gh_j4s_scan.py --user octocat --source

# 4. Wide net: who references the JVM flag, Oracle 8u511b33-perf, vulnerable images, decoder calls?
github/gh_j4s_code_search.py --org acme --set flags --set oracle8 --set images --format md --out sweep.md
github/gh_j4s_code_search.py --org acme --set decoder --set auth --format repos | github/gh_j4s_scan.py - --source

# 5. Is the runbook's CI gate actually wired up and enforced?
github/gh_j4s_repos.sh --org acme | github/gh_j4s_actions.sh - --require-gate --track --format tsv --out posture.tsv

# 6. A handful of named repositories
github/gh_j4s_scan.py acme/payments-api https://github.com/acme/auth-gateway acme/batch --format md
```

## Verdicts (`gh_j4s_scan.py`)

| Verdict | Meaning | Do |
| :--- | :--- | :--- |
| `EXPOSED` | A runtime definition pins a JDK in the vulnerable range and no mitigation flag is set in a runtime file. | Set `JAVA_TOOL_OPTIONS=-XX:-UseBASE64Intrinsics` now; upgrade to the baseline the report names. |
| `EXPLICITLY_ENABLED` | `-XX:+UseBASE64Intrinsics` found (J4S-FLAG-04) and the JDK is not proven patched. | Remove the flag. |
| `MITIGATED_FLAG` | `-XX:-UseBASE64Intrinsics` or `-XX:UseAVX=0..2` is present in a runtime file (Dockerfile `ENV`, manifest `env`, systemd unit, start script, Terraform). The JDK may still be vulnerable. | Keep the flag; schedule the upgrade. |
| `UNVERIFIED_FLOATING` | Only floating pins (`eclipse-temurin:21-jre`, `openjdk-21-jdk` package, `java-version: 21`) or digest-only images. Patched only if built after the fix shipped. | Resolve the real version (`docker run IMAGE java -version`); pin the digest. |
| `UNVERIFIED_NO_PIN` | Java workload, but the repository does not define its runtime (platform image, host JDK, Helm values elsewhere). | Audit the runtime with `../scripts/verify_java4shell_runtime.sh` or `../helpers/j4s_k8s.sh`. |
| `PATCHED` | Every runtime pin meets the baseline (`17.0.21.0.3`, `21.0.13.1`, `25.0.5.1`, `27.0.1.1` or newer; ≤ 16 unaffected). | Nothing for this CVE; the flag may be removed. |
| `NOT_JAVA` | No JVM language, build file, JDK pin or JVM flag on the default branch. | — |
| `ERROR` | Repository not accessible or API failure (see `error`). | Check token scopes / SSO. |

Exit code is `2` when any repository is `EXPOSED` or `EXPLICITLY_ENABLED` (`--strict` adds the two
`UNVERIFIED_*` verdicts), `1` on execution error, otherwise `0`.

### What the scanner reads

Only the default branch, and only files that can pin a JDK or set JVM options, in this order of
priority (`--max-files`, default 80, `--max-file-size` 512 KB; when the cap leaves candidates unread the
report says so and a `PATCHED` verdict is downgraded to `UNVERIFIED_FLOATING`, so repositories with
hundreds of Dockerfiles need `--max-files 300` or more): `Dockerfile*` / `Containerfile`;
`.java-version`, `.sdkmanrc`, `.tool-versions`, `.mise.toml`, `system.properties`, `.jabbarc`;
`docker-compose*.yml`; `.github/workflows/*`; `.gitlab-ci.yml`, `.travis.yml`, `Jenkinsfile`, `Procfile`,
`jvm.options`, `.mvn/jvm.config`; other YAML (deploy/k8s/helm/charts/kustomize paths first); `pom.xml`,
Gradle files; `*.service`, `*.vmoptions`, `*.tf`, `*.hcl`; entrypoint/start scripts; `.env*`; ECS task
definitions; `application*.properties`. Vendored directories (`node_modules`, `vendor`, `target`, `build`,
`dist`, `.gradle`, `third_party`) are skipped.

Version sources and how they are classified:

| Source | Example | Kind |
| :--- | :--- | :--- |
| Dockerfile `FROM` (with `ARG`/`ENV` expansion and multi-stage aliases skipped) | `eclipse-temurin:21.0.12_7-jre-jammy`, `amazoncorretto:17.0.9`, `azul/zulu-openjdk:21.0.4-21.36` | `EXACT` |
| Same, major-only tag | `eclipse-temurin:21-jre`, `maven:3.9-eclipse-temurin-21`, `tomcat:10.1-jdk17-temurin`, `bellsoft/liberica-runtime-container:jdk-21-slim-musl` | `FLOATING` |
| `image:` in YAML / HCL / JSON | same as above | per tag |
| Lines mentioning Java with a version (`ENV JAVA_VERSION=jdk-21.0.12+7`, download URLs `…hotspot_21.0.12_7.tar.gz`) | | `EXACT` |
| Distro packages | `openjdk-17-jre-headless`, `java-21-amazon-corretto`, `temurin-21-jdk` | `FLOATING` |
| `.sdkmanrc`, `.tool-versions`, `.java-version`, `.mise.toml`, `system.properties` | `java=21.0.12-tem`, `java temurin-17.0.21.0.3+9` | `EXACT` / `FLOATING` |
| `actions/setup-java` `java-version:` (matrix values resolved from the same file) | `'21'`, `21.0.12`, `17.0.x`, `${{ matrix.java }}` | `FLOATING` / `EXACT`, **build scope** |
| `pom.xml` compiler level, Gradle toolchain / compatibility | `<java.version>17</java.version>`, `JavaLanguageVersion.of(21)` | `LANGUAGE_LEVEL` (evidence only) |

Every finding carries a **scope**, and only `runtime` findings drive `EXPOSED` / `MITIGATED_FLAG` / `PATCHED`:

| Scope | Paths | Why it does not decide the verdict |
| :--- | :--- | :--- |
| `runtime` | everything else: Dockerfiles, compose, Kubernetes/Helm, systemd, start scripts, Terraform, `system.properties` | this is what runs in production |
| `build` | `.github/workflows/`, `.gitlab-ci.yml`, `Jenkinsfile`, `pom.xml`, Gradle files, `.mvn/`, `.devcontainer/`, other CI paths | protects the CI runner, not the service |
| `dev` | `.sdkmanrc`, `.java-version`, `.tool-versions`, `.mise.toml`, `.jabbarc` | developer-machine JDK |
| `docs` | `docs/`, `documentation/`, `examples/`, `samples/`, `demo/` | illustrative, often stale |

Non-runtime pins and flags are still reported (`non-runtime:` in the table, `[scope]` in CSV/JSON) and a
vulnerable `dev`/`build` pin adds a reason and an action, but a repository whose only JDK mention is
`setup-java` or `.sdkmanrc` ends up `UNVERIFIED_NO_PIN`, not `EXPOSED` or `PATCHED`.

### `--source`

Adds `source_hits`: `java.util.Base64` decoder calls (J4S-SRC-01) and lines where an auth / JWT / SAML /
Bearer / Basic term precedes a decode within 120 characters (J4S-SRC-04). File selection uses one
code-search request per repository (`Base64 repo:owner/name`, 10/minute budget) with path heuristics as
fallback (`--source-mode paths` to avoid code search entirely). Capped by `--max-source-files` (25).
Like the runbook's grep patterns, SRC-04 is single-line: a header read on one line and the decode on the
next is reported as SRC-01 only. For provenance-aware verdicts run `../scripts/scan_java4shell_source.py`
on a checkout.

### Output

`--format table` (default), `json` (full findings, every file:line), `ndjson`, `csv`, `md` (summary +
details for `EXPOSED` / `EXPLICITLY_ENABLED` / `MITIGATED_FLAG` / `UNVERIFIED_FLOATING`). `--sarif-dir`
writes one SARIF 2.1.0 file per repository (rules `J4S-VER-05`, `J4S-VER-FLOAT`, `J4S-FLAG-04`,
`J4S-FLAG-06`, `J4S-SRC-01`, `J4S-SRC-04`) that can be uploaded to that repository's code scanning:

```bash
gh api -X POST repos/acme/payments-api/code-scanning/sarifs \
  -f commit_sha="$(gh api repos/acme/payments-api/commits/HEAD --jq .sha)" -f ref=refs/heads/main \
  -f sarif="$(gzip -c sarif/acme__payments-api.sarif | base64)"
```

## `gh_j4s_code_search.py` pattern sets

| `--set` | Queries | Local verification | Severity |
| :--- | :--- | :--- | :--- |
| `decoder` | `Base64 getDecoder`, `getUrlDecoder`, `getMimeDecoder` | J4S-SRC-01 on `.java/.kt/.scala/.groovy/.clj/.jsp`; J4S-SRC-04 when auth context on the line | REVIEW / MITIGATE |
| `auth` | `Authorization Base64`, `Bearer Base64 decode`, `jwt Base64 decode`, `saml Base64 decode` | J4S-SRC-04 | MITIGATE |
| `flags` | `UseBASE64Intrinsics`, `JAVA_TOOL_OPTIONS`, `JDK_JAVA_OPTIONS`, `UseAVX` | J4S-FLAG-02 `ACTIVE` (INFO), -03 `CAPPED` (INFO), -04 `EXPLICITLY_ENABLED` (BLOCK), -01 `MENTION` (REVIEW) | |
| `oracle8` | `8u511b33` | J4S-VER-02 | BLOCK |
| `images` | `FROM <vendor>` in `Dockerfile` for temurin, corretto, openjdk, zulu, liberica, sapmachine, graalvm | J4S-VER-05 on the `FROM` tag | BLOCK if `VULN_RANGE`, REVIEW if floating |
| `setup-java` | `setup-java java-version` under `.github/workflows` | J4S-VER-05 on the CI JDK | REVIEW |
| `gate` | `gate_cve_2026_114938`, `CVE-2026-114938` | J4S-ID-01 | INFO |

Default sets: `decoder flags oracle8 images setup-java gate`. Exit `2` when any hit is `BLOCK` or
`MITIGATE`. `--format repos` prints only the affected `owner/repo` list.

GitHub code search facts that shape this script: authentication is mandatory; only default branches
and files under 384 KB are indexed; results per query are capped at 1000; the rate limit is **10
requests per minute**, so the script spaces requests 6.5 s apart (`--search-interval`) and sleeps on
`403`/`429`. Repeated `user:` / `org:` / `repo:` qualifiers are ORed by GitHub (verified 2026-11-20), so
all scopes are packed into one query per term up to the 256-character limit. For a handful of named
repositories `gh_j4s_scan.py` is faster; code search pays off at user/org scope.

## `gh_j4s_actions.sh` columns

| Column | Source | Values |
| :--- | :--- | :--- |
| `GATE_WORKFLOW` | `/actions/workflows` names and paths, then workflow file contents | file names or `none` |
| `GATE_LAST_RUN` | latest run of that workflow | `success 2026-11-19 main`, `failure …`, `no-runs`, `none` |
| `GATE_REQUIRED` | `/rules/branches/<default>` (rulesets), then classic `/branches/<b>/protection/required_status_checks` | `yes`, `no`, `unknown` (no permission) |
| `VAR_FLAG` | repository (and with `--org-vars` organization) Actions variables `JAVA_TOOL_OPTIONS`, `JDK_JAVA_OPTIONS`, `_JAVA_OPTIONS`, `JAVA_OPTS`; secret names containing `JAVA` | `ACTIVE`, `CAPPED`, `EXPLICITLY_ENABLED`, `MISSING` (variable exists without the flag), `NONE`, `n/a`; `(secret:NAME)` suffix |
| `CODE_SCANNING` | open alerts whose rule id/description matches `J4S`, `CVE-2026-114938`, `java4shell`, `UseBASE64`, `Base64Vbmi` | count or `n/a` |
| `DEPENDABOT` | open alerts whose advisory lists `CVE-2026-114938` | count or `n/a` |
| `TRACKING` | `--track`: open issues / PRs mentioning the CVE or alias | `2i/1pr` |

Exit `2` when any repository has `EXPLICITLY_ENABLED`, open J4S code-scanning alerts, open Dependabot alerts
for the CVE, or (with `--require-gate`) no gate workflow; `1` when a repository was not accessible.

## Authentication, limits, GHES

- Token resolution for the Python scripts: `--token`, `$GH_TOKEN`, `$GITHUB_TOKEN`, then `gh auth token`.
  Unauthenticated use works for public repositories at 60 requests/hour (no code search).
- Needed scopes: `repo` (or fine-grained *Contents: read*, *Metadata: read*); `gh_j4s_actions.sh`
  additionally benefits from *Actions: read*, *Variables: read*, *Secrets: read* (names only),
  *Code scanning alerts: read*, *Dependabot alerts: read*, *Administration: read* (classic protection).
  Endpoints without permission print `n/a` / `unknown` rather than failing the run.
- Budget: the scanner costs about 3 + one request per fetched file per repository (default cap 80), so
  ~5000 requests/hour covers roughly 60–150 repositories per hour; `--max-files 30` is usually enough
  for application repositories. Rate-limit responses are honoured automatically (sleep until reset,
  `--max-wait` caps the sleep).
- GitHub Enterprise Server: `--api-url https://ghe.example.com/api/v3` (or `$GITHUB_API_URL`) for the
  Python scripts, `--hostname ghe.example.com` for the Bash scripts.
- Concurrency: `--workers` repositories in parallel (default 4) and `--file-workers` fetches each. Keep the
  product under ~20 to stay clear of secondary rate limits.

## Version logic

Identical to `../helpers/j4s_version.py` and the detection scripts: compare up to five numeric
components lexicographically against `17.0.21.0.3`, `21.0.13.1`, `25.0.5.1`, `27.0.1.1`; 17.0.x below
17.0.6 is unaffected; 18–20, 22–24, 26 are EOL with no patch (every build is `VULN_RANGE`, including
floating tags); ≤ 16 unaffected except Oracle `8u511b33-perf`; `_N`, `+N`, `-suffix` qualifiers are
ignored. The two runbook regex gaps documented in `../patterns/J4S-VER-01.md` are avoided. Vendor
numbering caveat: Corretto and Zulu tags carry vendor build components (`21.0.4.7.1`, `21.0.4-21.36`);
the comparison uses the leading OpenJDK version and the fifth component only when the baseline has one.

## Known limits

- Default branch only. Release branches, tags and open PRs are not inspected.
- Floating tags cannot be resolved without pulling the image; the scanner says so (`UNVERIFIED_FLOATING`)
  instead of guessing.
- A repository can be `PATCHED` here and still run an old JDK on a host; the verdict is about what the
  repository declares. Pair with `../scripts/verify_java4shell_runtime.sh` on the hosts.
- Helm `values.yaml` in a separate repository, platform base images and Buildpacks hide the runtime from
  the application repository (`UNVERIFIED_NO_PIN`).
- Code search is not available on repositories with more than ~4000 private repositories in scope,
  during indexing lag, or on some GHES versions; the scanner's `--source-mode paths` does not need it.
- Nothing here sends exploit payloads or writes to GitHub.
