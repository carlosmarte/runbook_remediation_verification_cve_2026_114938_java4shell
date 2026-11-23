# 03 — Input Provenance & Tracing Plan

**Objective.** For every `java.util.Base64` decode call site that matters, know where its input comes from, which
touchpoint exposes it, whether it is reachable before authentication, and therefore whether the runbook's
verdict is `REACHABLE_HIGH`, `REACHABLE_CODE_ONLY`, `CONDITIONAL_LOW` or `UNREACHABLE_OR_N_A`. Then harden the
untrusted ones regardless of JDK.
**Runbook basis.** §1 side effects (inbound, internal, outbound, client touchpoints), §6 (`ast_taint.py`,
`dep_graph.py`, `reachability.py`), §8 step 4, patterns J4S-SRC-01..05.
**Owner.** AppSec with the service team. **Timing.** T+2 d to T+14 d, then per PR.

## 1. Touchpoint model

| Touchpoint | Examples | Trust | Default input kind |
| :--- | :--- | :--- | :--- |
| Inbound HTTP, pre-auth | `Authorization: Basic`, `Bearer` JWT, SAML `SAMLResponse`, OAuth `state`, cookies, multipart uploads, data URLs | untrusted | `DYNAMIC_UNTRUSTED`, `preauth_context = true` |
| Inbound HTTP, post-auth | API bodies with Base64 fields, webhooks with signatures | untrusted (authenticated user is still an attacker) | `DYNAMIC_UNTRUSTED` |
| Internal service-to-service | gRPC/REST between services, Kafka/SQS messages, shared files, DB columns | semi-trusted; one compromised producer reaches all consumers | `DYNAMIC_INTERNAL` (escalate if producers accept external data) |
| Outbound responses | decoding third-party API responses, OIDC discovery, certificate chains | untrusted (the third party or a MITM) | `DYNAMIC_UNTRUSTED` |
| Configuration / start-up | keys from files, env vars, secrets managers | operator-controlled | `DYNAMIC_INTERNAL` |
| Client / desktop / agent JVMs | IDE plug-ins, CLI tools, monitoring agents decoding server responses | untrusted server side | `DYNAMIC_UNTRUSTED` on VBMI laptops/servers |
| Constants | literals, `SCREAMING_CASE` constants | trusted | `CONSTANT` |

## 2. Steps

1. **Enumerate call sites.** From plan 02 §D (`src.json`) and §E (`findings.jsonl`). Include shaded copies.
2. **Classify provenance automatically.** `scan_java4shell_source.py` traces the decode argument within the
   enclosing method against `SOURCE_PATTERNS` (J4S-SRC-03: `getHeader`, `getParameter`, request bodies, streams,
   sockets, files…). Multi-method flows need `ast_taint.py` from the runbook §6 or manual tracing.
3. **Map each site to a touchpoint** using the table above; record protocol, authentication state and whether the
   caller is external, internal or a third party. Architecture diagrams and API gateways' route tables are the
   fastest source.
4. **Decide the verdict** with the runbook matrix (SPEC §9), using runtime context from plan 01:

   | Condition | Verdict |
   | :--- | :--- |
   | test code | `CONDITIONAL_LOW` |
   | JDK patched **or** flag live **or** non-VBMI CPU, input untrusted | `REACHABLE_CODE_ONLY` |
   | same, input not untrusted | `UNREACHABLE_OR_N_A` |
   | unmitigated, input untrusted | **`REACHABLE_HIGH`** (gate BLOCK) |
   | unmitigated, input internal/unknown | `CONDITIONAL_LOW` |

5. **Harden untrusted sites (independent of the JDK).** Before `decode()`:
   - length `% 4 == 0` (standard alphabet) or valid URL-safe length; reject `===`; reject `=` anywhere but the last
     two positions; reject mixed alphabets; cap length per field.
   - Use `helpers/j4s_b64check.py` `is_strictly_valid()` as the reference semantics; port it to Java as a shared
     utility (see R4 template for a reference implementation).
   - Add negative tests: `QUJD====`, `QU=JD`, `QUJDRA`, 10 MB inputs.
6. **Prioritise.** `REACHABLE_HIGH` and pre-auth first (Basic/JWT/SAML handlers, upload parsers), then internal
   consumers of external data (webhook relays, message consumers), then outbound decoders, then client tools.
7. **Feed the gate.** Export `reachability-findings.json`; plan 06 fails builds on `REACHABLE_HIGH`. Supply runtime
   context so already-mitigated services get `REACHABLE_CODE_ONLY`, not a false block.
8. **Trace across services.** For `DYNAMIC_INTERNAL` sites, follow the producer: if any producer accepts external
   input into the same field, reclassify the consumer as untrusted (side effect 03). Record the chain.
9. **Document per service** in R3 §4 and per PR in R4; keep the provenance table with the service's threat model.
10. **Re-run per PR.** The source scan on changed files plus the SARIF upload keep the classification current.

## 3. Observability hooks for tracing (runtime confirmation)

- Count decode failures per endpoint (`IllegalArgumentException` from `Base64.Decoder`) as a metric; a spike in
  malformed input on a pre-auth route is both a tracing confirmation and an attack signal (plan 08).
- Log the rejecting validator with route, length and anomaly class, never the token itself.
- Distributed traces: tag spans that perform Base64 decoding of request data (`j4s.decode=true`) so pre-auth paths
  are visible in trace search.

## 4. Outputs

| Output | Consumer |
| :--- | :--- |
| Provenance table per service (site → touchpoint → kind → verdict) | R3, R4, threat model |
| `reachability-findings.json` / `.sarif` | gate (plan 06), code scanning |
| Validation utility + tests merged | plan 05 (independent of JDK), R4 |
| Cross-service chains for internal inputs | architecture review, plan 04 ordering |

## 5. Exit criteria

- Every `DYNAMIC_UNTRUSTED` production site is wrapped in validation or has a written justification.
- No `REACHABLE_HIGH` in any build on the default branch.
- Pre-auth touchpoints are listed per service and match the edge-rule scope in plan 07.

## 6. Pitfalls

- Single-line patterns (J4S-SRC-04) miss header-on-one-line, decode-on-the-next; use the AST analyzer or review.
- `.decode(` and `.wrap(` match URL and charset decoders; prefilter with `Base64|Decoder` (J4S-SRC-05).
- Shaded Base64 in a dependency is reachable from your code paths even though your source never mentions it.
- "Internal" is not "safe": message queues and shared files are the classic path by which external data arrives
  unvalidated at a consumer.
