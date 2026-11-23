# 05 — Patch & Upgrade Plan

**Objective.** Move every Java runtime to a patched build (17.0.21.0.3+, 21.0.13.1+, 25.0.5.1+, 27.0.1.1+ or vendor
equivalent), migrate lines that have no patch (18–20, 22–24, 26, Oracle 8u511b33-perf), pin what was floating, and
retire the flag once the fleet is patched.
**Runbook basis.** §1 (baselines), §8 step 7; side effect 08 (compatibility and EOL migration).
**Owner.** Service teams, with platform owning base images. **Timing.** T+2 d to T+30 d; EOL migrations on their
own dated plan.

## 1. Target table

| Current line | Target | Notes |
| :--- | :--- | :--- |
| 17.0.6 – 17.0.21.0.2 | 17.0.21.0.3+ (vendor equivalent) | 17.0.x < 17.0.6 is unaffected |
| 21 < 21.0.13.1 | 21.0.13.1+ | |
| 25 < 25.0.5.1 | 25.0.5.1+ | |
| 27 < 27.0.1.1 | 27.0.1.1+ | |
| 18, 19, 20 | migrate to 21 | no patch; flag until migrated |
| 22, 23, 24 | migrate to 25 | no patch |
| 26 | migrate to 27 | no patch |
| Oracle 8u511b33-perf | standard JDK 8 build or an LTS above | only this perf build is affected |
| ≤ 16 (incl. standard 8, 11) | none for this CVE | still EOL; separate lifecycle concern |

`helpers/j4s_version.py table` prints this; `classify` checks any string; `baseline N` gives the target.

## 2. Steps

1. **Platform first: publish patched base images.** For every internal base image (`acme/java:21`, builder images,
   Jib/buildpack bases) rebuild on the vendor's patched tag, verify with `docker run IMAGE java -version`, pin the
   digest, and publish the mapping old → new. Keep `ENV JAVA_TOOL_OPTIONS` in the base image until step 9.
2. **Teams: pick up the base image or vendor tag.** Change `FROM`, `image:`, Jib `<from><image>`, buildpack
   `BP_JVM_VERSION`, `.sdkmanrc`, `.java-version`, `setup-java` `java-version`, and infrastructure pins in the same
   PR. Prefer exact tags (`21.0.13.1_2-jre-jammy`) or digests over floating ones.
3. **Compatibility check (side effect 08).** Within a line (21.0.12 → 21.0.13.1) risk is low: run the test suite and
   a canary. Across lines (19 → 21, 23 → 25): check removed APIs, `--add-opens` needs, agent and framework support
   (Spring/Jakarta versions), serialization, GC flag changes, CDS archives; run full regression.
4. **Canary and roll out** behind the same progressive delivery as plan 04; keep the flag on during the rollout so
   a slow rollout does not re-expose anything.
5. **Verify the running version** with the fleet audit (`PATCHED_OR_SAFE_VERSION`) and the estate scan (`PATCHED`);
   `java -version` from the mapped `libjvm.so` path, not from PATH.
6. **Pin floating references.** Each `UNVERIFIED_FLOATING` repo gets an exact tag or digest; renovate/dependabot
   rules can keep it current afterwards.
7. **EOL migrations.** For each 18–20 / 22–24 / 26 workload: owner, target line, dated plan, interim flag and edge
   rule; track in R2 as a separate workstream. Retire the service if nobody owns it (legacy-sso pattern).
8. **Developer and build environments.** Update `.sdkmanrc` / `.tool-versions` / `setup-java` pins to the baseline
   too; VBMI CI runners decoding test fixtures are in scope, and stale dev pins reintroduce old images via local builds.
9. **Flag removal (optional, after patch).** When a service is `PATCHED` on every host and image, remove the flag in
   one PR, re-benchmark (performance should return), and re-audit. Keep the flag if any instance of the service can
   still land on an unpatched runtime (shared hosts, blue/green with old images).
10. **Close the loop in CI.** The gate (plan 06) now enforces the baseline; `MITIGATED_FLAG` repos convert to
    `PATCHED` as PRs merge; R7 tracks the count.

## 3. Sequencing

1. Internet-facing pre-auth services on VBMI hardware (highest exposure, most benefit from removing the flag's cost).
2. Services where the flag hurt performance most.
3. Internal services, batch, agents.
4. EOL migrations by business priority.
5. Developer/CI pins (can run in parallel, low risk).

## 4. Outputs

| Output | Consumer |
| :--- | :--- |
| Patched base-image catalogue (old → new, digests) | teams, R2 |
| Upgrade PRs per repo, with test evidence | R4, R7 |
| EOL migration plan with dates | R1 §5, R0 decision |
| Post-upgrade audits | R6, trend, R9 |

## 5. Exit criteria

- `fleet.patch_coverage = 100 %` for in-scope hosts, or exceptions with expiry.
- `repos.patched = repos.java − exceptions`; no `UNVERIFIED_FLOATING`.
- Every EOL workload migrated or on a signed plan with an interim flag live.
- Flag removed only where the above holds; performance back to baseline where removed.

## 6. Pitfalls

- Vendor build numbers differ from OpenJDK's (Corretto `21.0.13.7.1`, Zulu `21.0.13-21.40`); compare the leading
  OpenJDK version and confirm with the vendor advisory.
- The deprecated `openjdk` Docker image has no patched tags; move to Temurin/Corretto/etc.
- Multi-stage Dockerfiles: upgrade the **runtime** stage, not only the build stage.
- Buildpacks and Jib hide the base image in `pom.xml`/`build.gradle`; search for `BP_JVM_VERSION`, `runImage`, `<from>`.
