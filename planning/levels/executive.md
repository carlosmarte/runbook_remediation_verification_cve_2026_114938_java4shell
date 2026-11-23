# Executive-level plan (board, CISO, CIO, business unit heads)

**You own:** risk appetite for this CVE, the SLAs, the budget and people for EOL migrations, emergency change
windows, acceptance of temporary performance cost and WAF risk, and every external statement.
**You receive:** R0 at T+24 h and weekly; R9 at closure; an R8 headline on any SEV-1.
**You deliver:** decisions in writing, on the dates R0 asks for.

## Steps

1. **T+0: confirm the appetite.** Approve the SLAs (mitigate within 2 days, patch within 30 days unless policy
   differs) and the principle that an exposed internet-facing service may be restarted out of hours without a
   further approval. Name the accountable executive (usually the CISO) and the programme manager.
2. **T+0: pre-approve the emergency change window** so the first mitigation is not waiting on a meeting.
3. **T+24 h: read R0 §2–§3.** Three numbers matter: exposed JVMs (must go to zero within the SLA), protected share
   (flag or patch), patched share (the only one that reaches 100 % at closure). Ask for the unknowns list.
4. **Decide what R0 §4 asks.** Typical decisions: accept +X % latency on Base64-heavy services for 30 days; fund
   migrations for JDK 18–20 / 22–24 / 26 services (no patch exists); approve WAF block mode on authentication routes
   knowing some legitimate traffic may be rejected until tuned; retire unowned legacy services.
5. **Weekly: track the trend, not the snapshot.** R0 shows before → after; regressions mean the control is not
   durable and the CI gate (plan 06) needs a push. Ask why gate adoption is below 100 %.
6. **On SEV-1 (R8 headline): assume disclosure.** The vulnerability can leak heap memory; approve secret rotation and
   session invalidation without waiting for proof of exfiltration. Approve external communications only from R9
   facts, through legal.
7. **At the patch SLA (T+30 d): review exceptions.** Every service not at baseline needs a signed exception with
   compensating control and expiry; sign or reject.
8. **Closure: sign R9.** It attests scope, coverage, exceptions and evidence; audit witnesses. Approve the retention
   of monitoring for crashes and probes after the controls are retired.
9. **After closure: fund the durable fixes.** Patched base images owned by platform, mandatory release gate, hardware
   inventory that includes CPU features, and a JDK lifecycle that retires EOL lines before the next CVE.

## Questions to ask at each review

- How many JVMs are exposed right now, and when was that number last measured (date of the audit)?
- Which exposed services are internet-facing and decode credentials or tokens before authentication?
- What is unknown (hosts not audited, repositories whose runtime is defined elsewhere)?
- What did the mitigation cost in latency and CPU, and who accepted it?
- Which services can never be patched on their current JDK line, and what is the migration date?
- Is the fix durable: what percentage of Java pipelines block a vulnerable image today?
- Have we seen probing or crashes, and what did we rotate?

## Side effects you are accepting

| Decision | Side effect (docs/side-efforts) |
| :--- | :--- |
| Flag rollout | 04 CPU/latency on Base64-heavy services; 07 flag reaches every JVM on shared hosts |
| `-XX:UseAVX` cap (only if the flag is unavailable) | 05 broad throughput loss |
| WAF block mode | 06 legitimate logins/API calls rejected until tuned |
| JDK upgrades and EOL migrations | 08 regressions, engineering time |
| Mandatory CI gate | 10 releases blocked on false positives until tuned |
