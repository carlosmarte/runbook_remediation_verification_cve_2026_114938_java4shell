# 08 — Side-Effect Documentation (`docs/side-efforts/`)

Every effect that the vulnerability itself, or a remediation or verification step, can have on production
systems is documented once, in a fixed structure, and referenced by ID from plans, reports and READMEs.

## 1. Inventory

**SPEC-08-01.** The folder MUST contain `README.md` (index, relationships, rollout order) and these eleven notes:

| # | Side effect | Origin | Impact | Likelihood |
| :--- | :--- | :--- | :--- | :--- |
| 01 | JVM crash / denial of service | vulnerability | High | Medium on VBMI hosts |
| 02 | Heap information disclosure ("JavaBleed") | vulnerability | High | Low–Medium |
| 03 | Exposure beyond inbound HTTP (internal, outbound, client-side) | vulnerability scope | Medium | High |
| 04 | CPU and latency increase from `-XX:-UseBASE64Intrinsics` | mitigation | Low–Medium | High on Base64-heavy services |
| 05 | Fleet-wide AVX-512 loss from `-XX:UseAVX=0..2` | alternative mitigation | Medium | High if chosen |
| 06 | Legitimate requests blocked by edge/WAF rules | compensating control | High | High until tuned |
| 07 | `JAVA_TOOL_OPTIONS` leaks into every JVM on the host | mitigation delivery | Low–Medium | High |
| 08 | Regression and EOL migration risk from the JDK upgrade | patch | Medium | Medium |
| 09 | Audit and verification script footprint on production hosts | verification | Low | High |
| 10 | CI gate blocks releases on false positives | policy gate | Medium | Medium |
| 11 | Scanner noise from test, shaded and generic decode call sites | static analysis | Low | High |

## 2. Structure of a note

**SPEC-08-02.** Each note `NN-<slug>.md` MUST have: title `# NN — <name>`; bold `Origin`, `Impact`, `Likelihood`
lines; and the sections **What happens**, **Who feels it**, **How to detect it**, **How to limit it**,
**Runbook and pattern references** (runbook sections and `J4S-*` IDs). The index table in `README.md` MUST list
the same impact and likelihood words as the note.

## 3. Relationships and rollout order

**SPEC-08-03.** `README.md` MUST state that effects 01–03 are what the vulnerability does if left alone and
justify accepting 04–11; that 04–08 are remediation costs needing before/after measurement; that 09–11 are
verification costs. It MUST give the rollout order that minimises side effects:

1. Baseline CPU, p99 latency and error rate on Base64-heavy endpoints (prerequisite for 04, 05).
2. Edge rules in log-only mode (06); review one to two traffic cycles.
3. Roll `-XX:-UseBASE64Intrinsics` by canary, scoped per service rather than per host (04, 07).
4. Run verification scripts off-peak and as the process owner (09).
5. Upgrade JDKs behind the same canary gates; EOL lines on their own schedule (08).
6. Turn CI gates from warn to block only after the version-regex gaps are fixed (10).
7. Remove edge rules and, if desired, the flag once the fleet is patched.

## 4. Referencing duties

**SPEC-08-04.** Any component, plan or template that recommends an action MUST cite the side-effect number it
triggers. Minimum mapping:

| Action | Cite |
| :--- | :--- |
| Add `-XX:-UseBASE64Intrinsics` | 04, 07 |
| Use `-XX:UseAVX=0..2` | 05 |
| Deploy nginx/Envoy/WAF rules | 06 |
| Run `audit_java4shell.*`, `verify_java4shell_runtime.sh`, `j4s_proc.sh` on production | 09 |
| Enforce `gate_cve_2026_114938.py` as a blocking check | 10 |
| Interpret source or bytecode findings | 11 |
| Upgrade or migrate a JDK | 08 |
| Explain why urgency is warranted | 01, 02, 03 |

**SPEC-08-05 Specific normative statements** that other documents rely on and MUST NOT contradict:

- 04: the flag disables the intrinsic for encoding **and** decoding, not only the VBMI path; small inputs show
  no measurable difference; never add `-XX:+UseBASE64Intrinsics` to "restore" performance after patching, remove
  the `-` flag instead; a non-VBMI host class MAY omit the flag as a recorded exception re-evaluated on hardware
  change.
- 05: the AVX cap affects every vectorised path in the JVM and is a last resort.
- 06: rules start in count/log mode; JWT, SAML and form posts are the known false-positive sources; EDGE-03 alone
  on a valid token is a false positive.
- 07: host-wide `JAVA_TOOL_OPTIONS` hits every JVM including unrelated tools; prefer per-service delivery; the
  JVM prints `Picked up JAVA_TOOL_OPTIONS` to stderr.
- 09: `jcmd` attaches at a safepoint; `java -version` and `docker exec` spawn JVMs; `j4s_proc.sh` reads
  `$JAVA_HOME/release` to avoid a spawn; run off-peak as the owner.
- 10: gates MUST use the corrected version parser before blocking; keep an exemption register with expiry.
- 11: test artifacts (`J4S-BC-04`) and shaded copies (`J4S-BC-05`) are reported but ranked below production
  sites; `CONSTANT` arguments are informational.
