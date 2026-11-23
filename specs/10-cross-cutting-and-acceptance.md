# 10 — Cross-Cutting Requirements and Acceptance

## 1. Portability and dependencies

**SPEC-10-01 No third-party code.** All executables use only Bash (3.2+ for `helpers/` and `github/`, 4+ for
`scripts/*.sh` which use associative arrays) and the Python standard library (3.10+ for `scripts/` and
`helpers/`, 3.9+ for `github/`). Optional external tools (`docker`, `kubectl`, `jcmd`, `curl`, `gh`) are detected
at run time.

**SPEC-10-02 Platforms.** Runtime inspection (`/proc`, `libjvm.so`, `jcmd`) is Linux-only and says so on other
platforms. Static scans, GitHub scanners, helpers and the reporting pipeline run on Linux and macOS.

**SPEC-10-03 Invocation hygiene.** Python called from shell wrappers uses `python3 -I`. Scripts resolve sibling
paths from their own location, never from the working directory. Scripts intended to be streamed over SSH
(`audit_java4shell.py`) have no local imports.

**SPEC-10-04 Executable bits.** Every script in `scripts/`, `helpers/`, `github/`, `report-template/tools/` and
`report-template/examples/build-examples.sh` carries a shebang and is executable in the repository.

## 2. Safety

**SPEC-10-05 Non-intrusive by construction.** No component constructs or sends a malformed Base64 payload to a
target system. The only crafted token in the toolkit, `QUJD====`, is used offline by `j4s_b64check.py` and in a
staged edge replay performed by the operator.

**SPEC-10-06 Read-only by default.** Components that can mutate state (`j4s_flag.sh k8s-apply`) print the
change and exit unless `--yes`. GitHub scanners perform only reads. No component modifies a running JVM.

**SPEC-10-07 Footprint disclosure.** Any component that attaches to a JVM (`jcmd`), spawns one
(`java -version`, `docker exec`) or walks `/proc` for every PID MUST document this in its README with a pointer
to side effect 09, and SHOULD offer a lower-footprint path where one exists (`$JAVA_HOME/release`).

**SPEC-10-08 Secrets.** Tokens are read from `--token`, environment or `gh auth token` and are never written to
output files or logs. Reports truncate Base64 tokens to 40 characters.

## 3. Data-contract stability

**SPEC-10-09.** The following shapes are public contracts between components and MUST only change additively:
audit JSON (SPEC-02-15), source scan JSON (SPEC-02-21), bytecode JSONL (SPEC-02-26), gate log text
(SPEC-02-30), estate scan JSON (SPEC-04-11), posture TSV columns (SPEC-04-18), crash triage JSON (SPEC-03-14),
traffic JSON (SPEC-03-13), `facts.json` (SPEC-06-03/04/05). A field removal or rename requires a major version
bump of this specification and simultaneous updates to every consumer and to `DATA-DICTIONARY.md`.

## 4. Documentation duties

**SPEC-10-10 Deviation register.** Every deliberate difference between shipped code and runbook text MUST be
listed in the owning component README ("Deviations from the runbook text" or "Version logic") and in the relevant
`patterns/` file with a verification date (SPEC-05-08).

**SPEC-10-11 READMEs.** Each top-level folder has a README that states purpose, a component table, quick start,
exit codes, and pointers to patterns and side effects. The runbook stays the source of truth for vulnerability
facts; READMEs reference it rather than restating constants, except where the vocabulary tables of document 00
require repetition.

**SPEC-10-12 Vocabulary drift.** A new verdict, state or severity string MUST be added to document 00 §5,
`DATA-DICTIONARY.md`, `planning/README.md` conventions and `report-template/README.md` conventions in the same
change.

## 5. Acceptance test matrix

**SPEC-10-13.** A change is acceptable when every applicable row passes. Rows marked *offline* need no network,
root or Linux and MUST be run for every change.

| # | Check | Command | Pass criterion | Offline |
| :--- | :--- | :--- | :--- | :--- |
| A1 | Shell syntax | `bash -n scripts/*.sh helpers/j4s helpers/*.sh github/*.sh report-template/examples/build-examples.sh` | exit 0 | yes |
| A2 | Python syntax | `python3 -m py_compile scripts/*.py helpers/*.py github/*.py report-template/tools/*.py` | exit 0 | yes |
| A3 | Estate scanner self-test | `github/gh_j4s_scan.py --self-test` | exit 0 | yes |
| A4 | Code-search self-test | `github/gh_j4s_code_search.py --self-test` | exit 0 | yes |
| A5 | Version table | `helpers/j4s_version.py classify 17.0.21.0.3 17.0.21.0.2 21.0.12_7 21.0.13.1_9 25.0.5.1 27.0.1.1 8u511b33-perf 11.0.20 18.0.2` | statuses: PATCHED, VULN, VULN, PATCHED, PATCHED, PATCHED, VULN, PATCHED, VULN; exit 2 | yes |
| A6 | Gate version parity | `scripts/gate_cve_2026_114938.py --jdk-version 17.0.21.0.3` and `--jdk-version 21.0.12_7` | first exits 0, second exits 1 | yes |
| A7 | Flag detection with `=` | `helpers/j4s_proc.sh classify 'JAVA_TOOL_OPTIONS=-XX:-UseBASE64Intrinsics'` and `helpers/j4s_flag.sh has 'JAVA_TOOL_OPTIONS=-XX:-UseBASE64Intrinsics'` | `ACTIVE`; `present` | yes |
| A8 | Flag idempotence | `helpers/j4s_flag.sh add '-Xmx1g -XX:+UseBASE64Intrinsics'` then `add` again on the result | `-Xmx1g -XX:-UseBASE64Intrinsics`, unchanged on second call | yes |
| A9 | Token analysis | `helpers/j4s_b64check.py token 'QUJD===='` | `excess_padding`, `J4S-EDGE-01`, suspicious, exit 2 | yes |
| A10 | Source scan on examples | `scripts/scan_java4shell_source.py <fixture> --json` | parses; `DYNAMIC_UNTRUSTED` count matches fixture expectation | yes |
| A11 | Bytecode scan | `scripts/scan_java4shell_jars.py <jar fixture> --jsonl -` | JSONL records with all SPEC-02-26 keys | yes |
| A12 | Gate on fixtures | `scripts/gate_cve_2026_114938.py --scan-dir <fixture>` | fails on vulnerable Dockerfile and bare `amazoncorretto:17.0.9`, passes on patched + flag | yes |
| A13 | Reporting pipeline | `report-template/examples/build-examples.sh` | exit 0; eleven `R*.example.md` and `facts.example.json` regenerated; `render.py --strict` on each template reports no missing required values beyond documented optional `extra.*` | yes |
| A14 | RAG parity | `helpers/j4s_report.py` and `j4s_facts.py` on `examples/data/` | both `RED` | yes |
| A15 | `j4s` dispatch | `helpers/j4s help`; `helpers/j4s version table` | usage printed; table printed; unknown command exits 2 | yes |
| A16 | Pattern index integrity | every `patterns/J4S-*.md` referenced from `SPEC.md` and vice versa; every `J4S-*` cited in READMEs/plans/templates exists | no dangling IDs | yes |
| A17 | Plan command integrity | every `scripts/`, `helpers/`, `github/` command and option cited in `planning/*.md` exists (SPEC-07-12) | no stale commands | yes |
| A18 | Runtime verification (Linux, root) | `scripts/verify_java4shell_runtime.sh --k8s` on a host with one JVM started with `JAVA_TOOL_OPTIONS=-XX:-UseBASE64Intrinsics` | `Cmd/Env Flag: ACTIVE`, `Live VM Flag: jcmd: -UseBASE64Intrinsics …` | no |
| A19 | Fleet audit (Linux, root) | `scripts/audit_java4shell.py --pretty` | valid JSON per SPEC-02-15; verdict matches SPEC-01-10 for each process | no |
| A20 | GitHub scanners (token) | `github/gh_j4s_scan.py <known repo> --format json`; `github/gh_j4s_actions.sh <known repo> --format tsv` | expected verdict; eleven TSV columns | no |

Fixtures for A10–A12 SHOULD live under a `tests/fixtures/` directory when added; until then the
`report-template/examples/data/` shapes serve as the reference for A13–A14.

## 6. Change control

**SPEC-10-14 Versioning.** This specification carries a semantic version in `specs/README.md`. Patch: wording
and corrections. Minor: new requirement, new component, additive contract field. Major: removed or renamed
contract field, changed verdict semantics, changed decision table.

**SPEC-10-15 Change checklist.** A change to the repository MUST update, in the same change set:

| If you change… | …also update |
| :--- | :--- |
| version or flag logic | document 01, `patterns/J4S-VER-*` / `J4S-FLAG-*`, every implementing component, A5–A8 expectations |
| a script's CLI or output | document 02/03/04, its README, `DATA-DICTIONARY.md` if consumed, examples |
| a verdict vocabulary | document 00 §5, `DATA-DICTIONARY.md`, `planning/README.md`, `report-template/README.md` |
| a template | `DATA-DICTIONARY.md` if new paths, regenerated examples, document 06 catalogue if audience/cadence changed |
| a plan | document 07 if structure changed; A17 |
| a side-effect note | document 08 inventory table; `docs/side-efforts/README.md` index |
| the runbook's facts (§1) | document 00 §2, `j4s_facts.py` meta constants, `planning/README.md` facts list, R0 text |

**SPEC-10-16 Verification dates.** Any claim about external behaviour (GitHub API limits, regex gaps, vendor tag
shapes) carries the date it was verified, as the existing documents do (`verified 2026-11-20`).

## 7. Traceability

**SPEC-10-17.** Each requirement in documents 01–09 traces to at least one of: a runbook section, a shipped
file, or a documented deviation. Reviewers MAY reject a requirement with no trace. Traceability summary:

| Document | Runbook §§ | Shipped files |
| :--- | :--- | :--- |
| 00 | §1, §8 | all READMEs, `planning/README.md`, `j4s_facts.py` meta |
| 01 | §2, §3, §6, §7.1 | `helpers/j4s_version.py`, `helpers/j4s_flag.sh`, `helpers/j4s_proc.sh`, `scripts/audit_java4shell.py`, `github/gh_j4s_scan.py` |
| 02 | §2, §3, §5, §6, §7 | `scripts/*` |
| 03 | §2, §3, §4, §8 | `helpers/*` |
| 04 | §1, §2, §7, §8 | `github/*` |
| 05 | §2–§8 | `patterns/*` |
| 06 | §1–§8 | `report-template/*` |
| 07 | §8, §1 | `planning/*` |
| 08 | §1 side effects, §2, §4 | `docs/side-efforts/*` |
| 09 | §4, §5, §6, §7.2, §7.3 | (reference only) |
