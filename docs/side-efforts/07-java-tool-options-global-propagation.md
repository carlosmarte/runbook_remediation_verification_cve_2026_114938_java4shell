# 07 — `JAVA_TOOL_OPTIONS` Leaks into Every JVM on the Host

**Origin:** mitigation delivery mechanism (runbook §2 recommends `export JAVA_TOOL_OPTIONS="-XX:-UseBASE64Intrinsics"`)
**Impact:** Low to Medium. **Likelihood:** High wherever the variable is set at host, node, or base-image level.

## What happens

`JAVA_TOOL_OPTIONS` is read by **every** HotSpot JVM that starts in that environment, including
ones you did not intend to touch:

- Build tools and their daemons (Maven, Gradle, Bazel, sbt), test runners, and code generators.
- Sidecars, agents, and operators: APM agents, log shippers, Kafka tooling, `jcmd`/`jinfo` themselves.
- JVMs launched by scripts with their own tuned options; the env var is **prepended**, so a later explicit `-XX:+UseBASE64Intrinsics` on the command line wins silently.

Secondary effects:

- Each JVM prints `Picked up JAVA_TOOL_OPTIONS: -XX:-UseBASE64Intrinsics` to **stderr** at start-up. Tools that parse stderr (version probes, health checks, some CI log matchers) can break or misreport. The runbook's own `java -version` probes read the first two lines of stderr (`J4S-VER-03`), so the banner can push the real version line out of the sample window.
- The variable has a platform length limit; appending to an already long value can truncate existing options.
- Non-HotSpot runtimes (OpenJ9) honour the variable but reject or ignore HotSpot-only `-XX` flags, which may fail start-up with "Unrecognized VM option" if `-XX:+IgnoreUnrecognizedVMOptions` is not set.
- `JDK_JAVA_OPTIONS` is only read by the `java` launcher (JDK 9+), so tools that embed the JVM via JNI ignore it; `_JAVA_OPTIONS` overrides the command line. Mixing the three produces hard-to-debug precedence.

## Who feels it

- CI runners and developer machines where the variable is set globally.
- Services with carefully tuned option strings that now carry an unexpected prefix.
- Anyone diagnosing a start-up failure on OpenJ9 or a stderr-parsing breakage.

## How to detect it

- `J4S-FLAG-08` finds the variable in `/proc/<pid>/environ`, Docker `Config.Env`, and Kubernetes `env`; compare against the intended target list.
- The runtime verification script reports `JVM Env:` for each process; unexpected processes carrying the flag indicate over-broad propagation.
- "Picked up JAVA_TOOL_OPTIONS" lines appearing in logs of tools that never had them.

## How to limit it

- Prefer setting the flag in the service's own launch configuration (container `args`, systemd `ExecStart`, application `JAVA_OPTS`) once the inventory is known; use host-level `JAVA_TOOL_OPTIONS` only for the first emergency wave (effect 03 explains why that wave is still worth it).
- Where the variable must be global, append rather than overwrite, and verify with `J4S-FLAG-09` that the live flag is `-UseBASE64Intrinsics` and nothing later re-enabled it (`J4S-FLAG-04`).
- Document the stderr banner for teams that parse `java -version`; the fleet audit should take the version from the quoted token rather than the first line (`classify_java_version` does this in the Python audit).
- Remove the variable when the JDK is patched to avoid permanent configuration drift.

## Runbook and pattern references

- Runbook §2 (flag and `JVM Env` reporting), §3 (`JAVA_TOOL_OPTIONS` in audits), §7.2 (GitLab sets it in CI).
- Patterns: `J4S-FLAG-04`, `J4S-FLAG-08`, `J4S-FLAG-09`, `J4S-VER-03`.
