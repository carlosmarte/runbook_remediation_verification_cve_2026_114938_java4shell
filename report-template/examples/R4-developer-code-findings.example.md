## CVE-2026-114938 (Java4Shell) — Base64 decoding findings for `acme/payments-api`

_PR #1187 (fix/java4shell-flag-and-validation) — scanned 2026-11-24_

**4** `java.util.Base64` decode call sites in 4 files
· **2 decode untrusted input** (2 in production code)
· 1 internal · 1 constant · 0 unknown
· 1 sit in an authentication / token path.

### Must fix before merge (untrusted input)

| File:line | Call | Argument | Sources | Pre-auth | Fix |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `main/java/com/acme/pay/auth/BasicAuthFilter.java:48` | `Base64.getDecoder().decode` | `authorization.substring(6)` | getHeader("Authorization") | yes | Validate length %4, padding count <=2 and no mid-string '=' before decode; apply -XX:-UseBASE64Intrinsics; upgrade JDK |
| `main/java/com/acme/pay/webhook/SignatureVerifier.java:77` | `Base64.getDecoder().decode` | `header` | getHeader("X-Signature") | no | Validate before decode; compare signature length to the expected digest length first |

Reference fix (validate before decode; keep it even after the JDK upgrade):

```java
static byte[] decodeStrict(String s) {
    if (s == null || s.length() % 4 != 0 || s.contains("===")) throw new IllegalArgumentException("bad base64");
    int pad = s.indexOf('=');
    if (pad >= 0 && pad < s.length() - 2) throw new IllegalArgumentException("padding inside body");
    if (!s.matches("[A-Za-z0-9+/]*={0,2}")) throw new IllegalArgumentException("alphabet");
    return java.util.Base64.getDecoder().decode(s);
}
```

### Review (internal / constant / unknown provenance, production code)

| File:line | Call | Argument | Input kind | Why |
| :--- | :--- | :--- | :--- | :--- |
| `main/java/com/acme/pay/config/KeyLoader.java:31` | `Base64.getMimeDecoder().decode` | `pem` | DYNAMIC_INTERNAL | argument read from a configured file path at start-up; operator-controlled |

_1 finding(s) in test code are listed in the JSON but not blocking (pattern J4S-BC-04 / side effect 11)._

### Compiled artifacts

4 class(es) in 2 artifact(s) reference Base64 decoding; **1 shaded copies** (a relocated `java.util.Base64` in a dependency still runs on the same vulnerable intrinsic). 1 test artifacts excluded from the verdict.

| Artifact | Class | Targets | Shaded | Test |
| :--- | :--- | :--- | :--- | :--- |
| `payments-api/build/libs/payments-api-2.14.0.jar` | `com.acme.shaded.java.util.Base64$Decoder` | com/acme/shaded/java/util/Base64$Decoder.decode0:([BII[B)I | yes | no |
| `payments-api/build/libs/payments-api-2.14.0.jar` | `com.acme.pay.auth.BasicAuthFilter` | java/util/Base64.getDecoder:()Ljava/util/Base64$Decoder;, java/util/Base64$Decoder.decode:(Ljava/lang/String;)[B | no | no |
| `payments-api/build/libs/payments-api-2.14.0.jar` | `com.acme.pay.webhook.SignatureVerifier` | java/util/Base64$Decoder.decode:(Ljava/lang/String;)[B | no | no |
| `payments-api/build/libs/payments-api-2.14.0-tests.jar` | `com.acme.pay.auth.BasicAuthFilterTest` | java/util/Base64$Decoder.decode:(Ljava/lang/String;)[B | no | yes |

### Release gate: **FAILED**

- [Dockerfile:payments-api/Dockerfile] JDK 21.0.12 (< 21.0.13.1) is unpatched
- [Dockerfile:payments-api/Dockerfile] Missing -XX:-UseBASE64Intrinsics (or -XX:UseAVX=0..2) in ENV/ENTRYPOINT/CMD
- [Manifest:payments-api/deploy/k8s/deployment.yaml] JVM workload missing -XX:-UseBASE64Intrinsics (e.g., via JAVA_TOOL_OPTIONS or container args)
- [Reachability:reachability-findings.json] J4S-0001 is REACHABLE_HIGH in com.acme.pay.auth.BasicAuthFilter.doFilter (payments-api/build/libs/payments-api-2.14.0.jar)

### Runtime definition in this repository

| Verdict | Runtime JDK pins | Flag | Gate workflow |
| :--- | :--- | :--- | :--- |
| `EXPOSED` | 21.0.12 (VULN_RANGE) | MISSING | no |
| `EXPLICITLY_ENABLED` | 19-jdk (VULN_RANGE) | EXPLICITLY_ENABLED | no |
| `MITIGATED_FLAG` | 21.0.5 (VULN_RANGE) | ACTIVE | yes |
| `UNVERIFIED_FLOATING` | 25-jre (FLOATING_PATCHABLE) | MISSING | yes |
| `UNVERIFIED_NO_PIN` | - | MISSING | no |
| `PATCHED` | 21.0.13.1 (PATCHED_OR_UNAFFECTED) | MISSING | yes |

### What to do in this PR

1. Validate every untrusted Base64 input before `decode()` (see reference fix); add a negative test with `QUJD====` and `QU=JD`.
2. If this repo owns a Dockerfile or manifest: set `JAVA_TOOL_OPTIONS=-XX:-UseBASE64Intrinsics` and pin the JDK to 17.0.21.0.3+ / 21.0.13.1+ / 25.0.5.1+ / 27.0.1.1+.
3. Never add `-XX:+UseBASE64Intrinsics` (J4S-FLAG-04); the gate fails on it.
4. Keep `scripts/gate_cve_2026_114938.py --scan-dir . --require-flag` green.

<sub>Patterns: J4S-SRC-01..05, J4S-BC-01..06, J4S-FLAG-04/06, J4S-VER-05 · runbook §5–§7 · false positives: docs/side-efforts/11</sub>
