# 10 — CI Gate Blocks Releases on False Positives

**Origin:** policy gate (runbook §7.1 `gate_cve_2026_114938.py`, §7.2 CI examples)
**Impact:** Medium (release velocity, emergency hotfixes delayed). **Likelihood:** Medium; several gate rules over-match by design.

## What happens

The gate exits non-zero on any violation, and the GitHub Actions / GitLab examples run it on every
pull request and push to `main` and `release/**`. Known ways it fails a clean change:

| Rule | False-positive behaviour |
| :--- | :--- |
| `JDK_VER_RE` (`J4S-VER-01`) | Captures only four version components. The patched baseline `17.0.21.0.3` parses as `17.0.21.0`, build `0 < 3`, so the **fixed** image is reported vulnerable. Verified 2026-11-20. |
| `JDK_VER_RE` | Matches **any** `x.y.z` in a Dockerfile or YAML: application versions, Helm chart versions, Python or Node versions, IP-like strings, `apiVersion` comments. Each unlucky match is run through the JDK range table. |
| `JDK_VER_RE` | Misses Temurin-style `21.0.12_7` tags entirely, so a vulnerable image can pass (a false negative, the opposite failure). |
| `--require-flag` | Fails every Dockerfile that mentions `java`, `jdk`, or `jvm` anywhere (including comments or unrelated tool names) unless the flag appears in the same file. Multi-stage builds that set the flag in a Helm chart rather than the Dockerfile fail. |
| K8s manifest check | Any YAML with `kind:` and a JVM keyword must contain the flag, so ConfigMaps, Ingresses, and CRDs that merely mention `java` fail. |
| Reachability check | Any `REACHABLE_HIGH` finding fails the build, even on a platform that is already patched or non-x86, unless the runtime context JSON is supplied to the analyzer. |

Conversely, once the flag is set at the environment level (GitLab example sets `JAVA_TOOL_OPTIONS` in the job), `--jvm-opts` is always satisfied and the check proves nothing about production.

## Who feels it

- Developers whose unrelated pull requests go red.
- Release managers during the incident itself, when a hotfix that **adds** the fix is blocked by the gate that is supposed to enforce it.
- Teams on vendor tag schemes the regex does not understand.

## How to detect it

- Gate output lines of the form `[Dockerfile:...] JDK 17.0.21.0 ...` or versions that are obviously not JDKs.
- Gate failures on files with no `FROM` of a JDK image.
- A rising count of `--require-flag` overrides or skipped jobs.

## How to limit it

- Start the gate in **warn mode** (report, do not fail) for at least one release cycle.
- Fix the version parser before enforcing: use `J4S-VER-01b` and extend `parse_semver4` to compare five components, or normalise vendor tags to the upstream `major.minor.patch.build` form before comparison.
- Restrict `JDK_VER_RE` to lines that also match a JDK image or vendor token (`FROM`, `image:`, `temurin`, `corretto`, etc.) rather than the whole file.
- Narrow the "mentions Java" heuristic to `FROM`/`image:` lines and `JAVA_TOOL_OPTIONS`/`JDK_JAVA_OPTIONS` keys.
- Feed the reachability analyzer the runtime context (`jdk_patched`, `mitigation_flag_present`, `avx512_vbmi`) so verdicts downgrade correctly on safe platforms.
- Provide a documented, audited override label for genuine emergencies.

## Runbook and pattern references

- Runbook §7.1–7.2, §8 step 7.
- Patterns: `J4S-VER-01`, `J4S-VER-01b`, `J4S-VER-04`, `J4S-VER-05`, `J4S-FLAG-06`, `J4S-RT-05`.
