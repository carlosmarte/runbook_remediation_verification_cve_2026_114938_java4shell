# Engineer / operator plan (developer, SRE, SOC analyst, edge engineer)

The hands-on steps, by role. Every step names the command. All tools are in this repository; run them from its root.

## Developer (plan 03, 06; reports R4)

1. Scan your working tree: `scripts/scan_java4shell_source.py src --json > src.json` (exit 2 means untrusted decode sites exist).
2. For each `DYNAMIC_UNTRUSTED` site, add validation before `decode()`; reference semantics in
   `helpers/j4s_b64check.py` (`is_strictly_valid`), Java reference implementation in R4; add tests for `QUJD====`,
   `QU=JD`, wrong length, oversize.
3. Scan the built artifact: `scripts/scan_java4shell_jars.py build/libs --jsonl findings.jsonl`; shaded Base64 in a
   dependency means that dependency needs attention too.
4. Keep the runtime definition correct: Dockerfile `FROM` at baseline (`helpers/j4s_version.py classify <tag>` → `PATCHED_OR_UNAFFECTED`),
   `ENV JAVA_TOOL_OPTIONS="-XX:-UseBASE64Intrinsics"` until the fleet is patched, never `-XX:+UseBASE64Intrinsics`.
5. Run the gate before pushing: `scripts/gate_cve_2026_114938.py --scan-dir . --require-flag --jvm-opts="$JAVA_TOOL_OPTIONS"`.
6. Update dev pins: `.sdkmanrc`, `.tool-versions`, `.java-version` to the baseline (`helpers/j4s_version.py baseline 21`).

## SRE / platform operator (plans 02 A, 04, 05, 10; reports R6)

1. CPU class: `grep -oE '\bavx512[a-z0-9_]*\b' /proc/cpuinfo | sort -u` (VBMI present → hardware in scope).
2. Audit the host: `sudo scripts/audit_java4shell.py --pretty > audit-$(hostname).json`; human view
   `sudo scripts/verify_java4shell_runtime.sh --k8s`.
3. Per JVM: `helpers/j4s_proc.sh report` (all), `helpers/j4s_proc.sh flags <pid>` (cmdline/env vs live `jcmd`).
4. Apply the flag: compute the merged value `helpers/j4s_flag.sh add "$JAVA_TOOL_OPTIONS"`; deliver via the platform
   mechanism (`helpers/j4s_flag.sh snippet systemd|k8s-env|k8s-patch|compose|dockerfile|tomcat`); restart.
5. Kubernetes: `helpers/j4s_k8s.sh missing -n <ns>`; `helpers/j4s_flag.sh k8s-apply <deploy> -n <ns> -c <container>`
   (prints the patch; `--yes` applies); `helpers/j4s_flag.sh k8s-verify <deploy> -n <ns>`.
6. Verify live: `jcmd <pid> VM.flags -all | grep -i base64` → `-UseBASE64Intrinsics`. Run as the process owner or root.
7. Diff runs: `helpers/j4s_inventory.py diff before/*.json --split after/*.json`; `regressed` rows are alerts.
8. Resolve floating images: `docker run --rm IMAGE:TAG java -version 2>&1 | helpers/j4s_version.py parse-output`.
9. Patch: swap to the platform base image or vendor tag; pin digest; re-audit.
10. Footprint: run audits off-peak on latency-critical hosts; never on a crash-looping JVM; `j4s_proc.sh` avoids spawning a JVM.

## SOC analyst (plans 08, 09; reports R8)

1. Triage a crash: `helpers/j4s_hs_err.py /var/log/<svc>/hs_err_pid*.log --json > crashes.json` → `LIKELY` pages, `POSSIBLE` investigates.
2. Analyse traffic: `helpers/j4s_b64check.py scan access.log --min-len 64 --json > traffic.json`; headers: `helpers/j4s_b64check.py headers < captured.txt`;
   single token: `helpers/j4s_b64check.py token 'QUJD===='`.
3. Correlate: edge hit on route → crash on the service behind it within 10 min → SEV-1 (plan 09 §1).
4. Contain: ask platform for the flag + restart on affected JVMs; ask edge for block mode on the routes; preserve
   `hs_err`, heap dumps, logs, image digests before pods recycle.
5. Assume heap disclosure: list secrets resident in the JVM; drive rotation.
6. Hunt: run the traffic scan across all edge logs for ±72 h; search for the same token shapes and IPs.
7. Record the timeline in R8; close with plan 09 exit criteria.

## Edge / WAF engineer (plan 07; reports R10)

1. Deploy runbook §4 rules in count mode: nginx `cve-2026-114938.conf` (`set $block_cve_2026_114938 0`), Envoy Lua filter
   (`logWarn` only), AWS WAFv2 pattern set with `Action: Count`.
2. After one cycle, export samples/logs and run `helpers/j4s_b64check.py scan FILE --min-len 64 --json`.
3. Promote EDGE-01/02 to block fleet-wide; EDGE-03 per route after owner confirmation; exclude SAML ACS and large
   multipart bodies; keep header and body rules separately switchable.
4. Test: send `Authorization: Basic QUJD====` to a staging route → 403 in block mode; confirm a valid JWT and a SAML
   POST still pass.
5. Wire metrics (`CVE2026114938AuthHeaderMalformedB64`, `…BodyMalformedB64`) and sampled requests to the SOC.
6. Retire only on the programme's instruction (plan 07 step 10).

## Release / DevOps engineer (plan 06; reports R5)

1. Add `.github/workflows/cve-2026-114938-gate.yml` (plan 06 §3) or the GitLab job; pilot non-blocking for a week.
2. Make `java4shell-policy-gate` a required status check on default and release branches.
3. Upload SARIF (`src.sarif`, `gh_j4s_scan.py --sarif-dir`) with `github/codeql-action/upload-sarif@v3`.
4. Set `JAVA_TOOL_OPTIONS` as an Actions variable for VBMI runners; never `+UseBASE64Intrinsics`.
5. Check posture: `github/gh_j4s_actions.sh --org ORG --require-gate --format tsv`.
6. Exemptions: `.j4s-exemptions.yml` with rule, path, reason, approver, expiry; mirrored in R9.

## Security engineer (plans 01, 02, 10; reports R1, R7)

1. Discover and scan the estate: `github/gh_j4s_repos.sh --org ORG --deep | github/gh_j4s_scan.py - --source --format json --out estate.json --sarif-dir sarif/`.
2. Sweep code: `github/gh_j4s_code_search.py --org ORG --set flags --set oracle8 --set images --set decoder --set auth --format md --out sweep.md`.
3. Posture: `github/gh_j4s_actions.sh --org ORG --track --format tsv --out posture.tsv`.
4. Build facts and reports: `report-template/tools/j4s_facts.py --audit audits/*.json --gh-scan estate.json --actions posture.tsv … -o facts.json`;
   `report-template/tools/render.py report-template/templates/R1-program-status.md facts.json -o R1.md`.
5. Keep dated evidence directories; run the independent spot check at closure (plan 10 step 10).
