# 05 — Fleet-Wide AVX-512 Loss from `-XX:UseAVX=0..2`

**Origin:** the alternative mitigation the runbook's scripts accept as "mitigated" (`J4S-FLAG-03`, `J4S-FLAG-05..07`)
**Impact:** Medium. **Likelihood:** High wherever this option is chosen instead of the Base64 flag.

## What happens

The audit scripts and CI gate treat `-XX:UseAVX=0`, `1`, or `2` as a valid mitigation because it
prevents HotSpot from selecting any AVX-512 intrinsic, including the VBMI Base64 decoder. The side
effect is that **every** AVX-512-accelerated intrinsic is disabled at the same time:

- String and array intrinsics (`indexOf`, `equals`, `compareTo`, array copy and fill, `Arrays.equals`).
- Cryptographic intrinsics (AES-GCM, SHA-2/SHA-3, ChaCha20, Poly1305) and CRC32C.
- Vector API (`jdk.incubator.vector`) code, which degrades to narrower lanes or scalar loops.
- Big-number arithmetic used by RSA and some TLS handshakes.

The performance cost is therefore broad and hard to attribute: TLS termination, JSON parsing,
hashing, and search-heavy code all slow down, not just Base64. With `UseAVX=0` even AVX/AVX2
paths are gone.

## Who feels it

- Any service on a VBMI host where the operator chose the AVX cap because it was already present in a tuning template.
- Crypto-heavy services: TLS-terminating gateways, token signers, encryption-at-rest layers.
- Teams that inherit the flag from a shared base image without knowing why it is there.

## How to detect it

- `J4S-FLAG-03` matches on the command line while `J4S-FLAG-02` does not: the service is relying on the AVX cap alone.
- `jcmd <pid> VM.flags -all` shows `UseAVX = 0|1|2` (`J4S-FLAG-09`).
- Broad CPU regression across unrelated endpoints after a mitigation rollout, with no single hot frame.

## How to limit it

- Use `-XX:-UseBASE64Intrinsics` as the primary mitigation. Reserve the AVX cap for cases where the Base64 flag is unavailable or not honoured by the vendor build.
- If an AVX cap already exists for another reason, still add the Base64 flag so the cap can later be lifted independently.
- When the gate reports `MITIGATED_FLAG` purely from an AVX cap, record which flag satisfied it so the broader cost is visible in the change record.
- Remove the cap as soon as the JDK is patched.

## Runbook and pattern references

- Runbook §2 (`classify_flag_text` → `CAPPED`), §3 (`check_cmdline_mitigation`), §7.1 (`MITIGATION_FLAG_RE`).
- Patterns: `J4S-FLAG-03`, `J4S-FLAG-05`, `J4S-FLAG-06`, `J4S-FLAG-07`, `J4S-FLAG-09`.
