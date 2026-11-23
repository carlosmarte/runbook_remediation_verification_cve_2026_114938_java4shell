# Side Effects — CVE-2026-114938 ("Java4Shell") Remediation

**Source:** `../../cve_2026_114938_java4shell_remediation_verification_runbook.md`
**Patterns referenced:** `../../patterns/SPEC.md`
**Last updated:** 2026-11-20

This folder documents every side effect that the vulnerability itself, or the remediation
and verification steps in the runbook, can have on production systems. Each file answers
the same questions: what the effect is, what in the runbook causes it, who feels it, how to
detect it, how to limit it, and which runbook sections and pattern IDs apply.

## Index

| # | Side effect | Origin | Impact | Likelihood | File |
| :-- | :--- | :--- | :--- | :--- | :--- |
| 01 | JVM crash / denial of service | Vulnerability | High | Medium on VBMI hosts | [01-denial-of-service-jvm-crash.md](01-denial-of-service-jvm-crash.md) |
| 02 | Heap information disclosure ("JavaBleed") | Vulnerability | High | Low–Medium | [02-information-disclosure-javableed.md](02-information-disclosure-javableed.md) |
| 03 | Exposure beyond inbound HTTP (internal, outbound, client) | Vulnerability scope | Medium | High | [03-touchpoint-scope-beyond-inbound-http.md](03-touchpoint-scope-beyond-inbound-http.md) |
| 04 | CPU and latency increase from `-XX:-UseBASE64Intrinsics` | Mitigation | Low–Medium | High on Base64-heavy services | [04-base64-intrinsic-performance-impact.md](04-base64-intrinsic-performance-impact.md) |
| 05 | Fleet-wide AVX-512 loss from `-XX:UseAVX=0..2` | Alternative mitigation | Medium | High if chosen | [05-useavx-cap-broad-performance-impact.md](05-useavx-cap-broad-performance-impact.md) |
| 06 | Legitimate requests blocked by edge/WAF rules | Compensating control | High | High until tuned | [06-edge-waf-false-positives.md](06-edge-waf-false-positives.md) |
| 07 | `JAVA_TOOL_OPTIONS` leaks into every JVM on the host | Mitigation delivery | Low–Medium | High | [07-java-tool-options-global-propagation.md](07-java-tool-options-global-propagation.md) |
| 08 | Regression and EOL migration risk from JDK upgrade | Patch | Medium | Medium | [08-jdk-upgrade-compatibility-and-eol-migration.md](08-jdk-upgrade-compatibility-and-eol-migration.md) |
| 09 | Audit script footprint on production hosts | Verification | Low | High | [09-audit-script-footprint.md](09-audit-script-footprint.md) |
| 10 | CI gate blocks releases on false positives | Policy gate | Medium | Medium | [10-ci-gate-false-positives-and-release-blocking.md](10-ci-gate-false-positives-and-release-blocking.md) |
| 11 | Scanner noise from test and shaded artifacts | Static analysis | Low | High | [11-scanner-noise-test-and-shaded-artifacts.md](11-scanner-noise-test-and-shaded-artifacts.md) |

## How the effects relate

- Effects **01–03** are what the vulnerability does if left alone. They justify accepting **04–11**.
- Effects **04–08** are costs of the remediation itself. They are acceptable and mostly reversible, but each needs a measurement before and after.
- Effects **09–11** are costs of verifying the remediation. They are the cheapest to absorb and the easiest to tune away.

## Rollout order that minimizes side effects

1. Measure baseline CPU, p99 latency, and error rate on Base64-heavy endpoints (prerequisite for 04 and 05).
2. Deploy edge rules in log-only mode (06) and review hits for one to two traffic cycles.
3. Roll `-XX:-UseBASE64Intrinsics` by canary, scoped per service rather than per host where possible (04, 07).
4. Run verification scripts off-peak and as the process owner (09).
5. Upgrade JDKs behind the same canary gates; retire EOL feature lines on their own schedule (08).
6. Turn CI gates from warn to block only after the version-regex gaps are fixed (10).
7. Remove edge rules and, if desired, the JVM flag once the fleet is on patched builds.
