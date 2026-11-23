# 02 — Heap Information Disclosure ("JavaBleed")

**Origin:** the vulnerability (runbook §1)
**Impact:** High. **Likelihood:** Low to Medium; requires more attacker effort than the crash in effect 01.

## What happens

The same out-of-bounds write that causes crashes can instead corrupt the **length field** of an
adjacent array or the bounds of an adjacent buffer. If the application later serializes or returns
that object, it reads past its real contents and leaks neighbouring heap memory. The runbook calls
this "JavaBleed". The leaked bytes can include session tokens, API keys, decrypted credentials,
other users' request data, or internal object layouts useful for a follow-on RCE.

Unlike a crash, a successful disclosure leaves no `hs_err` file and may leave no error log at all.

## Who feels it

- Any service that both decodes attacker-controlled Base64 and later returns byte arrays or strings to a caller (echo endpoints, token introspection, file download, error bodies that include request fragments).
- Services sharing a JVM with sensitive material: secrets managers, auth servers, payment handlers.
- Downstream systems that trust data produced by the affected JVM.

## How to detect it

- Responses whose body length exceeds the expected or declared content length.
- Non-printable or clearly foreign bytes appearing in fields that should be ASCII (tokens, usernames).
- Repeated near-identical requests from one client varying only the trailing padding of a Base64 field. This is the signature of someone probing for a stable leak.
- Edge rule hits with **no** corresponding crash. A crash means the attacker has not yet found a stable layout; silence after many malformed requests is more concerning.

## How to limit it

- Same primary controls as effect 01: `-XX:-UseBASE64Intrinsics`, then patch.
- Rotate secrets that were resident in any exposed JVM's heap during the window between disclosure (2026-11-17) and mitigation. Treat this as a precaution, not a confirmed breach, unless logs show probing.
- Enforce strict response length and content-type checks at the edge so an over-long body is dropped rather than returned.
- Keep edge rules (effect 06) in block mode for untrusted ingress until the fleet is patched, because they stop the probing traffic as well as the crash traffic.

## Runbook and pattern references

- Runbook §1 ("Information Disclosure"), §4, §8 steps 4–6.
- Patterns: `J4S-SRC-03` (`http_auth_header`, `jwt_saml_token` labels identify the highest-value leak paths), `J4S-EDGE-01..04`.
