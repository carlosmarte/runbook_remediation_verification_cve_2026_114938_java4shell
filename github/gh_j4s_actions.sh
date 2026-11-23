#!/usr/bin/env bash
# gh_j4s_actions.sh - CI/CD and security posture of GitHub repositories for CVE-2026-114938 (Java4Shell).
#
# For every repository (arguments, --user/--org discovery, or stdin) this answers, read-only, via `gh api`:
#   GATE_WORKFLOW   is there a GitHub Actions workflow referencing the runbook gate (gate_cve_2026_114938 / CVE-2026-114938 / java4shell)?
#   GATE_LAST_RUN   conclusion + date of its latest run
#   GATE_REQUIRED   is a java4shell/cve-2026-114938 status check required on the default branch (rulesets or classic protection)?
#   VAR_FLAG        do repository Actions variables JAVA_TOOL_OPTIONS / JDK_JAVA_OPTIONS / _JAVA_OPTIONS / JAVA_OPTS carry the mitigation?
#                   (ACTIVE / CAPPED / EXPLICITLY_ENABLED / MISSING / NONE; secrets with those names are reported by name only)
#   CODE_SCANNING   open code-scanning alerts whose rule is J4S-* / CVE-2026-114938 (SARIF uploaded by the runbook gate or these scanners)
#   DEPENDABOT      open Dependabot alerts whose advisory lists CVE-2026-114938
#   TRACKING        open issues / PRs mentioning the CVE (with --track; uses the search API, 30/min)
#
#   gh_j4s_actions.sh acme/payments-api acme/auth-gateway
#   gh_j4s_actions.sh --org acme --language java --format tsv --out posture.tsv
#   gh_j4s_repos.sh --org acme | gh_j4s_actions.sh - --require-gate --track
#   gh_j4s_actions.sh --user octocat --format json
#
# Needs: gh (authenticated), Bash 3.2+, python3 for --format json. Permission-denied endpoints print "n/a".
# Exit codes: 0 nothing to flag, 2 open J4S alerts / explicit re-enable / (with --require-gate) a Java repo without the gate, 1 error.
set -u

FORMAT="table"
OUT=""
REQUIRE_GATE=0
TRACK=0
ORG_VARS=0
SCOPE_KIND=""
SCOPE_OWNER=""
LANGS="java,kotlin,scala,groovy,clojure"
ALL_LANGS=0
LIMIT=500
HOST_ARGS=()
REPOS=()

usage() {
  sed -n '2,22p' "$0" | sed 's/^# \{0,1\}//'
  cat <<'U'

Options
  --user LOGIN | --org ORG | --me   discover repositories (filtered by --language unless --all-languages)
  --language LIST                   primary-language filter for discovery (default java,kotlin,scala,groovy,clojure)
  --all-languages                   disable the language filter
  --limit N                         max repositories to discover (default 500)
  --require-gate                    exit 2 when a repository has no gate workflow
  --track                           also count open issues/PRs mentioning the CVE (search API)
  --org-vars                        also inspect organization-level Actions variables (needs org permission)
  --format table|tsv|json|ndjson    (default table)
  --out FILE
  --hostname HOST                   GitHub Enterprise host
  -h, --help
U
}
die() { echo "gh_j4s_actions.sh: $*" >&2; exit 1; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --user) SCOPE_KIND="user"; SCOPE_OWNER="${2:-}"; shift 2 ;;
    --org) SCOPE_KIND="org"; SCOPE_OWNER="${2:-}"; shift 2 ;;
    --me) SCOPE_KIND="me"; shift ;;
    --language) LANGS="${2:-}"; shift 2 ;;
    --all-languages) ALL_LANGS=1; shift ;;
    --limit) LIMIT="${2:-}"; shift 2 ;;
    --require-gate) REQUIRE_GATE=1; shift ;;
    --track) TRACK=1; shift ;;
    --org-vars) ORG_VARS=1; shift ;;
    --format) FORMAT="${2:-}"; shift 2 ;;
    --out) OUT="${2:-}"; shift 2 ;;
    --hostname) HOST_ARGS=(--hostname "${2:-}"); shift 2 ;;
    -h|--help) usage; exit 0 ;;
    -) while IFS= read -r line; do line="${line%%#*}"; line="$(printf '%s' "$line" | tr -d '[:space:]')"; [[ -n "$line" ]] && REPOS+=("$line"); done; shift ;;
    -*) usage >&2; die "unknown option: $1" ;;
    *) REPOS+=("$1"); shift ;;
  esac
done
command -v gh >/dev/null 2>&1 || die "gh CLI not found"
case "$FORMAT" in table|tsv|json|ndjson) ;; *) die "unknown --format $FORMAT" ;; esac

ghapi() { gh "${HOST_ARGS[@]+"${HOST_ARGS[@]}"}" api "$@"; }

normalise_repo() {  # URL or owner/repo -> owner/repo
  local s="$1"
  s="${s#https://github.com/}"; s="${s#http://github.com/}"; s="${s#git@github.com:}"; s="${s%.git}"; s="${s%/}"
  printf '%s' "$s"
}

# ---- discovery ------------------------------------------------------------------------------
if [[ -n "$SCOPE_KIND" ]]; then
  jqf='.[] | select((.archived|not) and (.fork|not)) | [.full_name, (.language // "")] | @tsv'
  case "$SCOPE_KIND" in
    user) listing="$(ghapi --paginate "users/$SCOPE_OWNER/repos?type=owner&per_page=100" --jq "$jqf" 2>/dev/null)" ;;
    org)  listing="$(ghapi --paginate "orgs/$SCOPE_OWNER/repos?type=all&per_page=100" --jq "$jqf" 2>/dev/null)" ;;
    me)   listing="$(ghapi --paginate "user/repos?affiliation=owner&per_page=100" --jq "$jqf" 2>/dev/null)" ;;
  esac
  [[ -n "${listing:-}" ]] || die "discovery returned nothing for $SCOPE_KIND ${SCOPE_OWNER}"
  n=0
  langs_lc="$(printf ',%s,' "$LANGS" | tr '[:upper:]' '[:lower:]')"
  while IFS=$'\t' read -r full lang; do
    [[ -n "$full" ]] || continue
    if [[ $ALL_LANGS -eq 0 ]]; then
      l="$(printf '%s' "$lang" | tr '[:upper:]' '[:lower:]')"
      [[ -n "$l" && "$langs_lc" == *",$l,"* ]] || continue
    fi
    REPOS+=("$full"); n=$((n+1))
    [[ $n -ge $LIMIT ]] && break
  done <<< "$listing"
fi
[[ ${#REPOS[@]} -gt 0 ]] || { usage >&2; die "no repositories: pass owner/repo arguments, '-' for stdin, or --user/--org/--me"; }

# ---- helpers --------------------------------------------------------------------------------
GATE_RE='gate_cve_2026_114938|cve-2026-114938|cve_2026_114938|java4shell|j4s'

classify_flag_value() {  # J4S-FLAG-02/03/04 with the `=` delimiter fix
  local v="$1"
  if printf '%s' "$v" | grep -qE -- '(^|[[:space:]"'"'"'=,;])-XX:\+UseBASE64Intrinsics([[:space:]"'"'"',;]|$)'; then echo "EXPLICITLY_ENABLED"
  elif printf '%s' "$v" | grep -qE -- '(^|[[:space:]"'"'"'=,;])-XX:-UseBASE64Intrinsics([[:space:]"'"'"',;]|$)'; then echo "ACTIVE"
  elif printf '%s' "$v" | grep -qE -- '(^|[[:space:]"'"'"'=,;])-XX:UseAVX=[0-2]([[:space:]"'"'"',;]|$)'; then echo "CAPPED"
  else echo "MISSING"; fi
}

worst_flag() {  # combine several states: EXPLICITLY_ENABLED > MISSING > CAPPED > ACTIVE > NONE
  local states="$1" w="NONE"
  for s in $states; do
    case "$s" in
      EXPLICITLY_ENABLED) w="EXPLICITLY_ENABLED" ;;
      MISSING) [[ "$w" != "EXPLICITLY_ENABLED" ]] && w="MISSING" ;;
      CAPPED) [[ "$w" == "NONE" || "$w" == "ACTIVE" ]] && w="CAPPED" ;;
      ACTIVE) [[ "$w" == "NONE" ]] && w="ACTIVE" ;;
    esac
  done
  echo "$w"
}

count_paginated() {  # sum a per-page `... | length` jq expression across all pages; "n/a" when the endpoint is unavailable
  local out
  out="$(ghapi --paginate "$1" --jq "$2" 2>/dev/null)" || { echo "n/a"; return; }
  printf '%s\n' "$out" | awk '{s+=$1} END{print s+0}'
}

inspect_repo() {
  local repo="$1"
  local owner="${repo%%/*}"
  local default_branch lang archived
  local meta
  # every field non-empty: `read` with IFS=tab collapses consecutive tabs, which would shift columns
  meta="$(ghapi "repos/$repo" --jq '[(.default_branch // "-"), (.language // "-"), (.archived|tostring)] | @tsv' 2>/dev/null)" || { printf '%s\tERROR\tfalse\t-\tnone\tnone\tunknown\tn/a\tn/a\tn/a\trepository not accessible\n' "$repo"; return; }
  IFS=$'\t' read -r default_branch lang archived <<< "$meta"

  # 1. gate workflow(s)
  local wf_lines gate_wf="" gate_wf_id="" gate_run="none"
  # NB: gh api prints the error body on stdout, so always use `x="$(...)" || x=fallback`, never `$(... || echo fallback)`
  wf_lines="$(ghapi --paginate "repos/$repo/actions/workflows?per_page=100" --jq '.workflows[] | [.id, .path, .name, .state] | @tsv' 2>/dev/null)" || wf_lines=""
  while IFS=$'\t' read -r wid wpath wname wstate; do
    [[ -n "$wid" ]] || continue
    if printf '%s %s' "$wpath" "$wname" | grep -qiE "$GATE_RE"; then
      gate_wf="${gate_wf:+$gate_wf,}${wpath#.github/workflows/}"
      [[ -z "$gate_wf_id" ]] && gate_wf_id="$wid"
    fi
  done <<< "$wf_lines"
  # a workflow whose *content* references the gate but whose name does not: grep the files
  if [[ -z "$gate_wf" ]]; then
    local wf_paths
    wf_paths="$(ghapi "repos/$repo/contents/.github/workflows?ref=$default_branch" --jq '.[] | select(.type=="file") | .path' 2>/dev/null)" || wf_paths=""
    while IFS= read -r p; do
      [[ -n "$p" ]] || continue
      if ghapi "repos/$repo/contents/$p?ref=$default_branch" -H 'Accept: application/vnd.github.raw+json' 2>/dev/null | grep -qiE "$GATE_RE"; then
        gate_wf="${gate_wf:+$gate_wf,}${p#.github/workflows/}"
      fi
    done <<< "$wf_paths"
    [[ -n "$gate_wf" ]] && gate_wf_id="$(printf '%s' "$wf_lines" | awk -F'\t' -v p=".github/workflows/${gate_wf%%,*}" '$2==p{print $1; exit}')"
  fi
  if [[ -n "$gate_wf_id" ]]; then
    gate_run="$(ghapi "repos/$repo/actions/workflows/$gate_wf_id/runs?per_page=1" --jq '.workflow_runs[0] // empty | "\(.conclusion // .status) \(.created_at[0:10]) \(.head_branch)"' 2>/dev/null)" || gate_run="n/a"
    [[ -z "$gate_run" || "$gate_run" == "null" ]] && gate_run="no-runs"
  fi
  [[ -z "$gate_wf" ]] && gate_wf="none"

  # 2. required status checks on the default branch (rulesets first, then classic protection)
  local required="no" contexts
  contexts="$(ghapi "repos/$repo/rules/branches/$default_branch" --jq '.[] | select(.type=="required_status_checks") | .parameters.required_status_checks[].context' 2>/dev/null)" || contexts=""
  if [[ -z "$contexts" ]]; then
    contexts="$(ghapi "repos/$repo/branches/$default_branch/protection/required_status_checks" --jq '.contexts[]?, .checks[]?.context' 2>/dev/null)" || { contexts=""; required="unknown"; }
  fi
  if [[ -n "$contexts" ]] && printf '%s' "$contexts" | grep -qiE "$GATE_RE"; then required="yes"; fi

  # 3. Actions variables (repo, optionally org) and secret names
  local var_states="" var_lines secret_names
  var_lines="$(ghapi --paginate "repos/$repo/actions/variables?per_page=100" --jq '.variables[] | select(.name | test("^(JAVA_TOOL_OPTIONS|JDK_JAVA_OPTIONS|_JAVA_OPTIONS|JAVA_OPTS)$")) | [.name, .value] | @tsv' 2>/dev/null)" || var_lines="__NA__"
  if [[ "$var_lines" == "__NA__" ]]; then
    var_states="n/a"
  else
    while IFS=$'\t' read -r vn vv; do [[ -n "$vn" ]] && var_states="$var_states $(classify_flag_value "$vv")"; done <<< "$var_lines"
    if [[ $ORG_VARS -eq 1 ]]; then
      local org_lines
      org_lines="$(ghapi --paginate "orgs/$owner/actions/variables?per_page=100" --jq '.variables[] | select(.name | test("^(JAVA_TOOL_OPTIONS|JDK_JAVA_OPTIONS|_JAVA_OPTIONS|JAVA_OPTS)$")) | [.name, .value] | @tsv' 2>/dev/null)" || org_lines=""
      while IFS=$'\t' read -r vn vv; do [[ -n "$vn" ]] && var_states="$var_states $(classify_flag_value "$vv")"; done <<< "$org_lines"
    fi
    secret_names="$(ghapi "repos/$repo/actions/secrets?per_page=100" --jq '.secrets[] | select(.name | test("JAVA")) | .name' 2>/dev/null)" || secret_names=""
    secret_names="$(printf '%s' "$secret_names" | tr '\n' ',' | sed 's/,$//')"
    var_states="$(worst_flag "$var_states")"
    [[ -n "$secret_names" ]] && var_states="$var_states(secret:$secret_names)"
  fi

  # 4. code scanning alerts for J4S rules
  local cs
  cs="$(count_paginated "repos/$repo/code-scanning/alerts?state=open&per_page=100" '[.[] | select(((.rule.id // "") | test("J4S|CVE-2026-114938|java4shell|UseBASE64|Base64Vbmi"; "i")) or ((.rule.description // "") | test("CVE-2026-114938|java4shell"; "i")))] | length')"

  # 5. dependabot alerts naming the CVE
  local db
  db="$(count_paginated "repos/$repo/dependabot/alerts?state=open&per_page=100" '[.[] | select((.security_advisory.cve_id // "") == "CVE-2026-114938" or ([.security_advisory.identifiers[]?.value] | index("CVE-2026-114938")) != null)] | length')"

  # 6. tracking issues / PRs
  local track="-"
  if [[ $TRACK -eq 1 ]]; then
    track="$(ghapi -X GET search/issues -f q="repo:$repo CVE-2026-114938 OR Java4Shell state:open" -F per_page=20 --jq '"\([.items[] | select(.pull_request == null)] | length)i/\([.items[] | select(.pull_request != null)] | length)pr"' 2>/dev/null)" || track="n/a"
  fi

  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$repo" "${lang:--}" "${archived:--}" "${default_branch:--}" "${gate_wf:-none}" "${gate_run:-none}" "${required:-unknown}" "${var_states:-n/a}" "${cs:-n/a}" "${db:-n/a}" "${track:--}"
}

# ---- run ------------------------------------------------------------------------------------
header=$'REPO\tLANG\tARCHIVED\tBRANCH\tGATE_WORKFLOW\tGATE_LAST_RUN\tGATE_REQUIRED\tVAR_FLAG\tCODE_SCANNING\tDEPENDABOT\tTRACKING'
rows=""
total=${#REPOS[@]}
i=0
for r in "${REPOS[@]}"; do
  i=$((i+1))
  repo="$(normalise_repo "$r")"
  [[ "$repo" == */* ]] || { echo "gh_j4s_actions.sh: skipping '$r' (not owner/repo)" >&2; continue; }
  [[ $total -gt 3 ]] && echo "gh_j4s_actions.sh: [$i/$total] $repo" >&2
  row="$(inspect_repo "$repo")"
  rows="${rows:+$rows$'\n'}$row"
done

render() {
  case "$FORMAT" in
    tsv) printf '%s\n%s\n' "$header" "$rows" ;;
    table) printf '%s\n%s\n' "$header" "$rows" | column -t -s $'\t' 2>/dev/null || printf '%s\n%s\n' "$header" "$rows" ;;
    json|ndjson) printf '%s\n%s\n' "$header" "$rows" | python3 -I -c "$PY_JSON" "$FORMAT" ;;
  esac
}
read -r -d '' PY_JSON <<'PY' || true
import csv, json, sys
fmt = sys.argv[1]
rows = list(csv.DictReader(sys.stdin, delimiter="\t"))
rows = [{k.lower(): v for k, v in r.items()} for r in rows]
for r in rows:
    r["exposed_posture"] = (r.get("var_flag", "").startswith("EXPLICITLY_ENABLED")
                            or r.get("code_scanning", "0") not in ("0", "n/a")
                            or r.get("dependabot", "0") not in ("0", "n/a"))
if fmt == "json":
    print(json.dumps({"cve": "CVE-2026-114938", "tool": "gh_j4s_actions", "repos": rows}, indent=2))
else:
    for r in rows:
        print(json.dumps(r))
PY
if [[ -n "$OUT" ]]; then render > "$OUT" || die "cannot write $OUT"; echo "gh_j4s_actions.sh: written to $OUT" >&2; else render; fi

# ---- exit code ------------------------------------------------------------------------------
rc=0
while IFS=$'\t' read -r repo lang archived branch gate_wf gate_run required var_flag cs db track; do
  [[ -n "$repo" ]] || continue
  [[ "$lang" == "ERROR" ]] && { echo "gh_j4s_actions.sh: $repo: $track" >&2; rc=1; continue; }
  if [[ "$var_flag" == EXPLICITLY_ENABLED* ]] || { [[ "$cs" != "n/a" && "$cs" != "0" ]]; } || { [[ "$db" != "n/a" && "$db" != "0" ]]; }; then rc=2; fi
  if [[ $REQUIRE_GATE -eq 1 && "$gate_wf" == "none" ]]; then rc=2; fi
done <<< "$rows"
exit $rc
