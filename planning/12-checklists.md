# 12 — Checklists

Tick-box versions of the plans. Copy the relevant block into the ticket, change record or PR. Each line names the
command or artefact that proves it.

## A. Day-0 checklist (programme, T+0 to T+24 h)

- [ ] Incident channel open; programme manager and technical lead named; SLAs recorded (mitigate 2 d, patch 30 d)
- [ ] Scope statement written (environments, clouds, dev/CI machines, vendor appliances in/out)
- [ ] Hardware exposure map started (node pools / instance families → `avx512_vbmi`)
- [ ] Fleet audit started: `sudo scripts/audit_java4shell.py --pretty > audits/audit-$(hostname).json` on all hosts
- [ ] Kubernetes inventory: `helpers/j4s_k8s.sh missing` per cluster
- [ ] Estate scan started: `github/gh_j4s_repos.sh --org ORG --deep | github/gh_j4s_scan.py - --source --format json --out estate.json`
- [ ] Code-search sweep: `github/gh_j4s_code_search.py --org ORG --set flags --set oracle8 --set images`
- [ ] Posture: `github/gh_j4s_actions.sh --org ORG --format tsv --out posture.tsv`
- [ ] Edge rules deployed in count mode on every public entry point
- [ ] Emergency change window pre-approved (R0 decision)
- [ ] First `facts.json`, R0 and R1 issued; cadence published
- [ ] Any internet-facing JVM with vulnerable version on VBMI hardware flagged **today**

## B. Per-host checklist (platform / SRE)

- [ ] CPU class recorded (`grep -oE '\bavx512[a-z0-9_]*\b' /proc/cpuinfo | sort -u`)
- [ ] Audit run as root or JVM owner; JSON stored by date
- [ ] Every JVM has a verdict; `jcmd-unavailable-or-restricted` resolved by re-running as owner
- [ ] Each `EXPOSED_ON_VBMI_HOST`: flag delivered (mechanism noted), process restarted
- [ ] Live confirmation: `jcmd <pid> VM.flags -all | grep UseBASE64Intrinsics` → `-UseBASE64Intrinsics`
- [ ] No `-XX:+UseBASE64Intrinsics` in cmdline/env (`helpers/j4s_proc.sh flags <pid>`)
- [ ] Shared-host propagation checked (`JAVA_TOOL_OPTIONS` picked up by unrelated JVMs acceptable?)
- [ ] Before/after CPU and p99 recorded for Base64-heavy services
- [ ] Re-audit after change; diff shows `improved`, no `regressed`
- [ ] Non-VBMI hosts with vulnerable versions scheduled for patch before hardware moves

## C. Per-service checklist (service owner; mirrors R3 §7)

- [ ] Service tier, owner, internet-facing and pre-auth surface recorded
- [ ] Runtime located (image, host, platform) and audited
- [ ] Flag in the runtime definition (Dockerfile `ENV` / manifest `env` / unit file / Helm values) and live-verified
- [ ] Explicit re-enables removed everywhere (manifests, scripts, Actions variables)
- [ ] Source scan run: `scripts/scan_java4shell_source.py src --json`; untrusted sites listed
- [ ] Validation added before each `DYNAMIC_UNTRUSTED` decode; negative tests (`QUJD====`, `QU=JD`) added
- [ ] Bytecode scan run on the built artifact; shaded Base64 copies noted
- [ ] JDK upgraded to baseline (exact tag or digest pinned); test suite green on new JDK
- [ ] Gate workflow present and required; last run green
- [ ] Re-audit shows `PATCHED_OR_SAFE_VERSION`; estate scan shows `PATCHED`
- [ ] Flag removal decided (keep until every instance can only land on patched runtimes)
- [ ] Ticket closed with evidence links (audit JSON, scan JSON, gate run URL)

## D. Per-repository checklist (AppSec / repo owner; mirrors R7)

- [ ] Verdict from `gh_j4s_scan.py` understood (`EXPOSED` / `MITIGATED_FLAG` / `UNVERIFIED_*` / `PATCHED`)
- [ ] Runtime pins exact (no floating tag, no distro "latest"), digest recorded
- [ ] `JAVA_TOOL_OPTIONS=-XX:-UseBASE64Intrinsics` in runtime files until patched
- [ ] Dev/CI pins (`.sdkmanrc`, `.tool-versions`, `setup-java`) at baseline
- [ ] Jib / buildpack / `BP_JVM_VERSION` / `runImage` pins checked
- [ ] Gate workflow added; `java4shell-policy-gate` required on default and release branches
- [ ] SARIF from source scan uploaded; code scanning shows no open `J4S-SRC-04` without validation
- [ ] No `-XX:+UseBASE64Intrinsics` in repo or Actions variables
- [ ] `UNVERIFIED_NO_PIN`: runtime owner named and audited; note added to `narrative.json`

## E. Pull-request checklist (developer / reviewer; mirrors R4)

- [ ] No new `Base64.getDecoder()/getUrlDecoder()/getMimeDecoder()` call on untrusted input without validation
- [ ] Validation checks length `% 4`, rejects `===`, rejects `=` inside the body, single alphabet, length cap
- [ ] Negative tests present
- [ ] Dockerfile / manifest changes keep the flag and the baseline pin
- [ ] Never adds `-XX:+UseBASE64Intrinsics`
- [ ] `scripts/gate_cve_2026_114938.py --scan-dir . --require-flag` passes locally
- [ ] Source scan on changed files shows no new `DYNAMIC_UNTRUSTED` (or justified in the PR)

## F. Release checklist (release manager; mirrors R5)

- [ ] Gate job passed on the release commit (run URL recorded)
- [ ] Built image verified: `docker run IMAGE java -version` → baseline; digest in release notes
- [ ] Flag present in the deployed manifest (until fleet patched)
- [ ] Reachability JSON shows no `REACHABLE_HIGH` (where artifacts are analysed)
- [ ] Exemptions used by this release listed with expiry
- [ ] Post-deploy audit scheduled (plan 10 step 2)

## G. Edge-rule checklist (edge team; mirrors R10)

- [ ] Rules deployed in count mode on every public entry point; metrics and sampling on
- [ ] One traffic cycle reviewed with `helpers/j4s_b64check.py scan`
- [ ] EDGE-01/02 promoted to block; EDGE-03 per route with owner confirmation
- [ ] SAML ACS, multipart and legacy clients handled (exclusions / size window)
- [ ] Block hits alert the SOC; count hits reviewed daily
- [ ] Retirement criteria recorded

## H. Incident checklist (SOC; mirrors R8)

- [ ] Crash files triaged (`helpers/j4s_hs_err.py --json`); verdicts recorded
- [ ] Edge logs for the window analysed; source IPs and routes noted
- [ ] Host audit of affected hosts captured
- [ ] Flag applied and live-verified on affected JVMs; edge rules blocking on affected routes
- [ ] Evidence preserved with chain of custody before pod recycling
- [ ] Heap-resident secrets enumerated and rotated; sessions invalidated where applicable
- [ ] Fleet-wide hunt for the same token shapes and IPs completed
- [ ] Affected services patched ahead of schedule
- [ ] R8 finalised; lessons fed into plans 04/06/08

## I. Closure checklist (programme / audit; mirrors R9)

- [ ] `fleet.exposed_vbmi = 0`, `fleet.unverified = 0` or exceptions with expiry
- [ ] `fleet.patch_coverage = 100 %` or exceptions
- [ ] `repos.blocking = 0`; `repos.unverified_* = 0` or owner/audit recorded; `repos.gate_adoption = 100 %`
- [ ] No `REACHABLE_HIGH`; all untrusted sites validated
- [ ] Flag removed where patched and re-benchmarked; kept where justified
- [ ] Edge rules retired or retention justified
- [ ] Alerts for crashes and probes remain active
- [ ] Side-effect measurements archived (performance, propagation, gate FPs, WAF FPs)
- [ ] Independent spot check (10 % hosts, 10 % repos) passed
- [ ] R9 signed by risk owner, witnessed by audit; evidence register complete
- [ ] Lessons learned written back into these plans
