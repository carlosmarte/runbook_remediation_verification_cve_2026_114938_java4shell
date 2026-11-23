# 04 — CPU and Latency Increase from `-XX:-UseBASE64Intrinsics`

**Origin:** the primary mitigation (runbook §1 "Performance Impact of Mitigation", §2)
**Impact:** Low to Medium. **Likelihood:** High on Base64-heavy workloads, negligible elsewhere.

## What happens

`-XX:-UseBASE64Intrinsics` removes the HotSpot intrinsic for `java.util.Base64` encoding **and**
decoding, not just the vulnerable VBMI decode path. Every Base64 operation falls back to the
plain Java implementation, which is JIT-compiled but scalar. On VBMI hardware the intrinsic can be
several times faster for large inputs, so the fallback shows up as:

- Higher CPU per request on endpoints that decode or encode large payloads (file upload/download APIs, image or document services, SAML assertions, large JWTs).
- Higher p99 latency and more GC pressure where Base64 sits on the hot path.
- Reduced headroom: a service near its CPU limit may start throttling or scaling out.

Small inputs (a Basic-auth header, a typical JWT) see no measurable difference.

## Who feels it

- Services that move binary data as Base64 in JSON or XML.
- Message pipelines that Base64-encode payloads (SQS, Pub/Sub, some Kafka serializers).
- Cost owners: more CPU-seconds at the same traffic.

## How to detect it

- Compare CPU utilization and p95/p99 latency per endpoint before and after the flag, at the same traffic level.
- Profile for `java.util.Base64$Decoder.decode0` / `Encoder.encode0` frames rising in the CPU profile.
- Watch HPA / autoscaler events for unexpected scale-outs after rollout.

## How to limit it

- Benchmark the highest-throughput Base64 endpoints first, as the runbook instructs, and roll by canary.
- Prefer the flag over `-XX:UseAVX=0..2` (effect 05); the flag's blast radius is limited to Base64.
- Treat the flag as temporary: once a service is on a patched JDK the intrinsic is safe to re-enable by removing the flag. Do not add `-XX:+UseBASE64Intrinsics` explicitly (`J4S-FLAG-04`), because that would re-expose the service if it is ever rolled back to an unpatched build.
- Where latency is unacceptable and the host has no `avx512_vbmi` (`J4S-RT-03`), the flag can be omitted for that host class, since the vulnerable path is never selected there. Record this exception; it must be re-evaluated if the workload moves to newer hardware.

## Runbook and pattern references

- Runbook §1, §2, §8 steps 5–6.
- Patterns: `J4S-FLAG-01`, `J4S-FLAG-02`, `J4S-FLAG-04`, `J4S-FLAG-09`, `J4S-RT-03`.
