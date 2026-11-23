# CVE-2026-114938 ("Java4Shell") — Executive Brief

| | |
| :--- | :--- |
| **Organisation / scope** | Acme Corp (fictional example) — Payments, Identity and Finance Ops production |
| **Report date** | 2026-11-24 (day 7 after public disclosure on 2026-11-17) |
| **Overall status** | **RED** |
| **Prepared by / owner** | Platform Security / CISO |
| **Classification** | Internal / Confidential |

## 1. What this is

A critical, pre-authentication remote code execution flaw (8.1 High CVSS 3.1, 9.2 Critical CVSS 4.0) in the Java
runtime's Base64 decoder on modern x86-64 servers with AVX-512 VBMI (Intel Ice Lake and newer, AMD Zen 4 and newer).
Any Java service that decodes attacker-controlled Base64 — HTTP Basic auth, JWT/SAML tokens, file uploads — can be
crashed or taken over. Patched Java builds are available (17.0.21.0.3+ / 21.0.13.1+ / 25.0.5.1+ / 27.0.1.1+); a single JVM start-up flag
(`-XX:-UseBASE64Intrinsics`) removes the exposure immediately at a small CPU cost.

## 2. Where we stand

| Runtime fleet | Value |
| :--- | ---: |
| Hosts audited / on affected hardware | 2 / 1 |
| Java processes found | 5 |
| **Exposed now** (vulnerable version, no flag, affected CPU) | **1** (20%) |
| Protected by flag or patch | 60% |
| Fully patched | 40% |
| Vulnerable but on unaffected hardware | 1 |

| Source & deployment estate (GitHub) | Value |
| :--- | ---: |
| Java repositories scanned | 6 of 7 |
| **Deploy a vulnerable JDK without mitigation** | **2** (33.3%) |
| Mitigated by flag, upgrade still due | 1 |
| Cannot be verified from the repository (floating tag / runtime defined elsewhere) | 1 + 1 (33.3%) |
| Patched | 1 |
| Pipelines enforcing the release gate | 3 of 6 (50%) |

**Trend since last report:** exposed JVMs 3 → 1; protected 0% → 60%; patched 0% → 40%. 1 improved, 0 regressed, 3 new.

**Exploitation indicators:** 1 JVM crash file(s) match the exploit signature and are being handled as a security incident (see R8).
**Probing observed:** 3 malformed Base64 token(s) matching the trigger shape were seen at the edge.

## 3. Why the status is RED

- 1 JVM(s) exposed on AVX-512 VBMI hosts without patch or flag
- 2 repositor(ies) deploy a vulnerable JDK without the mitigation flag or re-enable the intrinsic
- 1 crash file(s) triaged LIKELY Java4Shell
- 1 repositor(ies) re-enable the intrinsic through Actions variables
- 1 unverified and 1 flag-mitigated JVM(s) still on vulnerable versions
- 2 repositor(ies) unverified, 1 mitigated by flag only
- 2 production call site(s) decode untrusted Base64
- CI gate failing with 4 violation(s)
- 1 crash file(s) triaged POSSIBLE
- 3 suspicious malformed-Base64 token(s) in traffic

## 4. Decisions requested

1. **Emergency change window** — Approve out-of-hours restart of payments-api on web-01 to apply the flag today _(owner: Head of Payments Engineering, needed by 2026-11-24)_
2. **Accept temporary latency** — Accept up to +8% p99 on /authorize while the flag is active (measured in staging) _(owner: Payments product owner, needed by 2026-11-25)_
3. **Fund legacy-sso migration** — JDK 19 has no patch; approve 3 engineer-weeks to move legacy-sso to JDK 21 or retire it _(owner: CTO, needed by 2026-12-01)_

## 5. Plan and dates

| Milestone | Target | Status |
| :--- | :--- | :--- |
| Flag live on every exposed JVM (SLA 2 days) | 2026-11-19 | **BREACHED** |
| Patched JDK on every service (SLA 30 days) | 2026-12-17 | in progress |
| Release gate enforced in every Java pipeline | 2026-12-05 | 50% |
| Edge rules EDGE-01/02 to block mode on api.acme.example | 2026-11-26 | count mode, 0 false positives so far |
| legacy-sso migration plan | 2026-12-01 | not started |

## 6. Residual risk and side effects to expect

- Services relying on the flag remain on vulnerable builds until upgraded; the flag is a stop-gap, not a fix.
- Base64-heavy services may show higher CPU and latency with the flag; benchmarks are part of each rollout.
- Edge/WAF blocking rules can reject legitimate logins and API calls until tuned; they run in count mode first.
- Hosts without AVX-512 VBMI are not exploitable today but become exposed on the next hardware migration.

_Next review: 2026-12-01. Detail reports: R1 programme status, R6 runtime verification, R7 GitHub estate._
