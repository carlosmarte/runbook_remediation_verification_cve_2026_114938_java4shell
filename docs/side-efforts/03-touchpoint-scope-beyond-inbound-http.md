# 03 — Exposure Beyond Inbound HTTP (Internal, Outbound, Client-Side)

**Origin:** vulnerability scope (runbook §1, "Inbound, Outbound & Client-Side Touchpoints")
**Impact:** Medium (it widens effects 01 and 02 to systems teams assume are safe). **Likelihood:** High.

## What happens

Teams naturally focus on internet-facing HTTP: `Authorization: Basic`, JWT, SAML, uploads. The
runbook is explicit that the bug triggers on **any** Base64 decode of malformed input, regardless
of where the bytes came from. The side effect of a narrowly scoped remediation is a false sense of
completion while these paths remain exposed:

- **Service-to-service**: an internal caller that forwards a client-supplied token unchanged.
- **Queues and files**: Kafka/SQS messages, S3 objects, CSV or JSON imports that embed Base64 fields.
- **Outbound decoders**: parsing a third-party API response, webhook, or OIDC discovery document. A compromised or malicious partner can crash your JVM.
- **Client and desktop runtimes**: Java desktop apps, CLI tools, build agents, and monitoring agents on VBMI workstations and CI runners. These usually have no WAF in front of them and are rarely in the server inventory.

## Who feels it

- Platform teams who scoped the rollout to "edge services" only.
- Data and integration teams whose workers are not in the web-tier inventory.
- Developer-tooling owners: Jenkins, Gradle daemons, IDE JVMs on Ice Lake / Sapphire Rapids / Zen 4 laptops and runners.

## How to detect it

- Run the source scan (`J4S-SRC-01`, `J4S-SRC-02`) across **all** repositories, not just web services, and classify arguments with `J4S-SRC-03`. The `messaging_or_net` and `file_or_stream_io` labels specifically flag the non-HTTP paths.
- Run the bytecode extractor (`J4S-BC-*`) against built artifacts, including agents and CLI jars that have no source in your org.
- Inventory JVMs by `libjvm.so` in process maps (`J4S-RT-01`) rather than by service catalogue; this finds sidecars, agents, and forgotten daemons.
- Check the Kubernetes heuristic (`J4S-RT-04`) for `kafka`, `elasticsearch`, `jenkins`, `keycloak` images.

## How to limit it

- Deliver `-XX:-UseBASE64Intrinsics` at the base-image or node level for the first wave so coverage does not depend on knowing every service (accepting effect 07).
- Add the flag to CI runner and build-agent JVM options.
- Treat outbound response parsing as untrusted input in the reachability verdict; do not downgrade it to `DYNAMIC_INTERNAL`.
- Keep the inventory as a living artifact; re-run the fleet audit after each deploy window until patched.

## Runbook and pattern references

- Runbook §1, §3 (fleet audit), §5–6 (extractor and analyzer), §8 steps 1, 3, 4.
- Patterns: `J4S-SRC-03`, `J4S-BC-01..03`, `J4S-RT-01`, `J4S-RT-04`, `J4S-DEP-01`.
