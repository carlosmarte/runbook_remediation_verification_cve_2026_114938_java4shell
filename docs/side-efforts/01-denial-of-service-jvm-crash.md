# 01 — JVM Crash / Denial of Service

**Origin:** the vulnerability (runbook §1, "Side Effects, Risk Dimensions & Mitigation Trade-Offs")
**Impact:** High. **Likelihood:** Medium on any x86-64 host that exposes `avx512_vbmi` and runs an unpatched JDK.

## What happens

The AVX-512 VBMI Base64 decoding intrinsic mis-computes the tail write mask when input ends in
malformed padding (`=`). The intrinsic writes past the destination array on the Java heap
**before** the decoder's validation rejects the input. The write can land on an adjacent object's
header or length field. The JVM then either crashes immediately with a `SIGSEGV`, fails a later GC
with a heap verification error, or throws unexplained `ArrayIndexOutOfBounds` /
`ClassCastException` from unrelated code.

An attacker does not need a working RCE chain for this. Any pre-authentication path that decodes
attacker-controlled Base64 is a remote crash primitive.

## Who feels it

- Services that decode `Authorization: Basic`, JWT, SAML, or Base64 request bodies before authentication.
- Internal consumers: queue workers, file pipelines, and outbound API clients that decode third-party responses (see effect 03).
- Anything co-located in the same JVM: one bad request takes down every tenant and endpoint in that process.

## How to detect it

- Crash files `hs_err_pid*.log` with a frame in the Base64 intrinsic stub or in `java.util.Base64$Decoder.decode`.
- Container restart loops with exit code 134 or 139 and no application-level error before the exit.
- Spikes in 5xx or connection resets that correlate with requests whose Base64 fields fail validation.
- Edge rule hits (`J4S-EDGE-01`, `J4S-EDGE-02`, `J4S-EDGE-03`) in log-only mode that line up with restarts.

## How to limit it

- Apply `-XX:-UseBASE64Intrinsics` now (runbook §2). This removes the intrinsic path entirely; the fallback Java decoder validates before writing.
- Confirm the flag is live with `J4S-FLAG-09` (`jcmd <pid> VM.flags -all`), not just present on the command line.
- Patch to the November 2026 baselines (`17.0.21.0.3`+, `21.0.13.1`+, `25.0.5.1`+, `27.0.1.1`+).
- Validate Base64 length and padding at the edge or in a filter before calling `decode`.
- Hosts without `avx512_vbmi` (`J4S-RT-03`) and all ARM64 hosts are not exposed to this crash.

## Runbook and pattern references

- Runbook §1 (root cause), §2 (flag), §4 (edge rules), §8 step 5.
- Patterns: `J4S-FLAG-02`, `J4S-FLAG-09`, `J4S-RT-03`, `J4S-EDGE-01..03`, `J4S-SRC-04`.
