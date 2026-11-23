# 08 — Regression and EOL Migration Risk from the JDK Upgrade

**Origin:** the permanent fix (runbook §1 "Patched Baselines", §8 step 7)
**Impact:** Medium. **Likelihood:** Medium for in-support lines, High for EOL feature releases.

## What happens

The runbook's patched baselines are `17.0.21.0.3`+ (or vendor equivalent), `21.0.13.1`+,
`25.0.5.1`+, and `27.0.1.1`+. Two different kinds of upgrade are hiding in that list:

1. **Update release within a supported line** (17, 21, 25, 27). Normally low risk, but a security
   update that changes an intrinsic can shift performance, and vendors occasionally bundle other
   fixes (TLS defaults, timezone data, certificate store changes) in the same drop. The odd
   five-component Liberica/Temurin version (`17.0.21.0.3`) also trips version parsers (see effect 10).
2. **Feature-release jump for EOL lines** (18–20, 22–24, 26). There is **no patch** for these;
   the only remedy is moving to 21, 25, or 27. That is a major upgrade with real compatibility
   work: removed or deprecated APIs, security-manager removal, stronger encapsulation,
   `--add-opens` needs, agent and bytecode-library compatibility (ASM, ByteBuddy, Mockito),
   build-tool plugin versions, and container base-image changes.
3. **Oracle Java `8u511b33-perf`** is a special Oracle build. Replacing it may mean moving to a
   standard 8 build (unaffected) or to a supported LTS, each with licensing and support consequences.

Until the upgrade lands, these services rely entirely on the flag (effects 04, 07) and edge rules (effect 06).

## Who feels it

- Teams on EOL feature releases who have to plan a major migration under incident pressure.
- Platform teams maintaining many base images across vendors (Temurin, Corretto, Zulu, Liberica, SapMachine, Red Hat, Oracle, GraalVM), each with its own version string and release timing.
- Downstream consumers of GraalVM native images, which need a rebuild rather than a runtime swap.

## How to detect it

- `J4S-VER-05` returns `VULN_RANGE` with major in `{18,19,20,22,23,24,26}`: that service needs a feature-release migration, not a patch.
- `J4S-VER-02` matches: an Oracle perf build is in use.
- Post-upgrade: failing integration tests, `InaccessibleObjectException`, agent attach failures, or changed TLS negotiation.

## How to limit it

- Keep the flag in place through the upgrade and only remove it after `J4S-VER-05` reports `PATCHED_OR_UNAFFECTED` on the live process (not just in the manifest).
- Canary the update release behind the same metrics used for effect 04.
- For EOL lines, choose the nearest LTS (21 or 25), run the application's test suite on it with the flag set first, then schedule the migration as a project. The vulnerability is mitigated by the flag in the meantime; the migration should not be rushed into a crash.
- Pin exact image digests in manifests so the gate (effect 10) can verify what actually ships.
- Prefer vendor builds that publish the fix in their standard tag scheme so `J4S-VER-01` / `J4S-VER-01b` parse it correctly.

## Runbook and pattern references

- Runbook §1 (affected runtimes, patched baselines), §7.1 (version gate), §8 step 7.
- Patterns: `J4S-VER-01`, `J4S-VER-01b`, `J4S-VER-02`, `J4S-VER-05`, `J4S-FLAG-09`.
