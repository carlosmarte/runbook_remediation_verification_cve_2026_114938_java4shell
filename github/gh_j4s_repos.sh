#!/usr/bin/env bash
# gh_j4s_repos.sh - discover GitHub repositories to audit for CVE-2026-114938 (Java4Shell) with the gh CLI.
#
# Lists repositories owned by a user / organization (or the authenticated user, or a search query) and
# filters them by JVM language (primary OR any language), topic, archived/fork state, visibility, last
# push date and name regex. Prints owner/repo lines by default so the result pipes straight into
# gh_j4s_scan.py, gh_j4s_actions.sh and gh_j4s_code_search.py.
#
#   gh_j4s_repos.sh --user octocat
#   gh_j4s_repos.sh --org acme --language java,kotlin --no-archived --pushed-since 2025-01-01
#   gh_j4s_repos.sh --me --deep --format tsv
#   gh_j4s_repos.sh --search 'org:acme topic:payments' --format json
#   gh_j4s_repos.sh --org acme | gh_j4s_scan.py - --format md --out acme.md
#
# Needs: gh (authenticated: `gh auth login`), Bash 3.2+. jq is NOT required (gh's built-in --jq is used).
# Exit codes: 0 repositories listed, 2 nothing matched, 1 error / usage.
set -u

OWNER_KIND=""        # user | org | me | search
OWNER=""
SEARCH_QUERY=""
LANGS="java,kotlin,scala,groovy,clojure"
ALL_LANGS=0
DEEP=0               # match on any language, not just primary
TOPICS=""
ARCHIVED="exclude"   # exclude | include | only
FORKS="exclude"      # exclude | include | only
VISIBILITY=""
PUSHED_SINCE=""
NAME_RE=""
LIMIT=1000
FORMAT="list"
OUT=""
HOST_ARGS=()

usage() {
  sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'
  cat <<'U'

Options
  --user LOGIN | --org ORG | --me       scope (one of them, or --search QUERY using gh search repos syntax)
  --search QUERY                        e.g. 'org:acme language:java', 'user:octocat archived:false'
  --language LIST                       comma list matched against the repository languages (default java,kotlin,scala,groovy,clojure)
  --all-languages                       disable the language filter
  --deep                                match --language against every language of the repo, not only the primary one
  --topic T[,T]                         keep repositories carrying any of these topics
  --include-archived | --only-archived  (default: archived excluded)
  --include-forks | --only-forks        (default: forks excluded)
  --visibility public|private|internal
  --pushed-since YYYY-MM-DD             keep repositories pushed on/after this date
  --name-regex RE                       keep repositories whose name matches RE (gojq regex)
  --limit N                             max repositories to fetch (default 1000)
  --format list|tsv|csv|json|ndjson     list = owner/repo per line (default)
  --out FILE                            write output to FILE
  --hostname HOST                       GitHub Enterprise host (passed to gh)
  -h, --help
U
}

die() { echo "gh_j4s_repos.sh: $*" >&2; exit 1; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --user) OWNER_KIND="user"; OWNER="${2:-}"; shift 2 ;;
    --org) OWNER_KIND="org"; OWNER="${2:-}"; shift 2 ;;
    --me) OWNER_KIND="me"; shift ;;
    --search) OWNER_KIND="search"; SEARCH_QUERY="${2:-}"; shift 2 ;;
    --language) LANGS="${2:-}"; shift 2 ;;
    --all-languages) ALL_LANGS=1; shift ;;
    --deep|--deep-languages) DEEP=1; shift ;;
    --topic) TOPICS="${TOPICS:+$TOPICS,}${2:-}"; shift 2 ;;
    --include-archived) ARCHIVED="include"; shift ;;
    --only-archived) ARCHIVED="only"; shift ;;
    --no-archived) ARCHIVED="exclude"; shift ;;
    --include-forks) FORKS="include"; shift ;;
    --only-forks) FORKS="only"; shift ;;
    --no-forks) FORKS="exclude"; shift ;;
    --visibility) VISIBILITY="$(printf '%s' "${2:-}" | tr '[:upper:]' '[:lower:]')"; shift 2 ;;
    --pushed-since) PUSHED_SINCE="${2:-}"; shift 2 ;;
    --name-regex) NAME_RE="${2:-}"; shift 2 ;;
    --limit) LIMIT="${2:-}"; shift 2 ;;
    --format) FORMAT="${2:-}"; shift 2 ;;
    --out) OUT="${2:-}"; shift 2 ;;
    --hostname) HOST_ARGS=(--hostname "${2:-}"); shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; die "unknown option: $1" ;;
  esac
done

command -v gh >/dev/null 2>&1 || die "gh CLI not found (https://cli.github.com)"
[[ -n "$OWNER_KIND" ]] || { usage >&2; die "one of --user, --org, --me or --search is required"; }
case "$FORMAT" in list|tsv|csv|json|ndjson) ;; *) die "unknown --format $FORMAT" ;; esac
[[ "$LIMIT" =~ ^[0-9]+$ ]] || die "--limit must be a number"
if [[ -n "$PUSHED_SINCE" ]]; then
  [[ "$PUSHED_SINCE" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]] || die "--pushed-since must be YYYY-MM-DD"
  PUSHED_SINCE="${PUSHED_SINCE}T00:00:00Z"
fi
if ! gh "${HOST_ARGS[@]+"${HOST_ARGS[@]}"}" auth status >/dev/null 2>&1; then
  echo "gh_j4s_repos.sh: gh is not authenticated; run 'gh auth login' (continuing, public data only)" >&2
fi

# Normalise every record to one shape so the filters and formatters are identical for list/search.
#   {repo, name, owner, url, archived, fork, visibility, primary, languages[], topics[], pushedAt, defaultBranch, description}
FIELDS_LIST="nameWithOwner,name,owner,url,isArchived,isFork,visibility,primaryLanguage,languages,repositoryTopics,pushedAt,defaultBranchRef,description"
NORMALISE_LIST='[.[] | {
  repo: .nameWithOwner, name: .name, owner: .owner.login, url: .url,
  archived: .isArchived, fork: .isFork, visibility: (.visibility | ascii_downcase),
  primary: (.primaryLanguage.name // ""),
  languages: ([.languages[]?.node.name] | unique),
  topics: ([.repositoryTopics[]?.name] | unique),
  pushedAt: .pushedAt, defaultBranch: (.defaultBranchRef.name // ""), description: (.description // "")}]'
FIELDS_SEARCH="fullName,name,owner,url,isArchived,isFork,visibility,language,pushedAt,defaultBranch,description"
NORMALISE_SEARCH='[.[] | {
  repo: .fullName, name: .name, owner: .owner.login, url: .url,
  archived: .isArchived, fork: .isFork, visibility: (.visibility | ascii_downcase),
  primary: (.language // ""), languages: ([.language // empty]), topics: [],
  pushedAt: .pushedAt, defaultBranch: (.defaultBranch // ""), description: (.description // "")}]'

raw=""
case "$OWNER_KIND" in
  user|org)
    [[ -n "$OWNER" ]] || die "--$OWNER_KIND needs a login"
    raw="$(gh "${HOST_ARGS[@]+"${HOST_ARGS[@]}"}" repo list "$OWNER" --limit "$LIMIT" --json "$FIELDS_LIST" --jq "$NORMALISE_LIST")" || die "gh repo list $OWNER failed"
    ;;
  me)
    raw="$(gh "${HOST_ARGS[@]+"${HOST_ARGS[@]}"}" repo list --limit "$LIMIT" --json "$FIELDS_LIST" --jq "$NORMALISE_LIST")" || die "gh repo list failed"
    ;;
  search)
    [[ -n "$SEARCH_QUERY" ]] || die "--search needs a query"
    # gh search repos caps --limit at 1000
    sl="$LIMIT"; [[ "$sl" -gt 1000 ]] && sl=1000
    # shellcheck disable=SC2086
    raw="$(gh "${HOST_ARGS[@]+"${HOST_ARGS[@]}"}" search repos $SEARCH_QUERY --limit "$sl" --json "$FIELDS_SEARCH" --jq "$NORMALISE_SEARCH")" || die "gh search repos failed"
    ;;
esac
[[ -n "$raw" ]] || raw="[]"

# Build the filter as a single jq program; string arguments are passed with --arg to avoid quoting bugs.
csv_to_json_array() { python3 -I -c 'import json,sys; print(json.dumps([t.strip().lower() for t in sys.argv[1].split(",") if t.strip()]))' "$1"; }
langs_json="$(csv_to_json_array "$LANGS")"
topics_json="$(csv_to_json_array "$TOPICS")"

FILTER='
def lc: ascii_downcase;
map(select(
  ( $archived == "include" or ($archived == "exclude" and (.archived|not)) or ($archived == "only" and .archived) )
  and ( $forks == "include" or ($forks == "exclude" and (.fork|not)) or ($forks == "only" and .fork) )
  and ( $visibility == "" or .visibility == $visibility )
  and ( $since == "" or (.pushedAt // "") >= $since )
  and ( $name_re == "" or (.name | test($name_re)) )
  and ( ($topics|length) == 0 or ([.topics[] | lc] | any(. as $t | $topics | index($t) != null)) )
  and ( $all_langs == "1"
        or ( (.primary | lc) as $p | ($langs | index($p)) != null )
        or ( $deep == "1" and ([.languages[] | lc] | any(. as $l | $langs | index($l) != null)) ) )
))
| sort_by(.repo)'

# gh's embedded jq only runs on API responses, so the filter runs through jq when installed, else python3.
apply_filter() {
  if command -v jq >/dev/null 2>&1; then
    jq --arg archived "$ARCHIVED" --arg forks "$FORKS" --arg visibility "$VISIBILITY" --arg since "$PUSHED_SINCE" \
       --arg name_re "$NAME_RE" --argjson topics "$topics_json" --argjson langs "$langs_json" \
       --arg all_langs "$ALL_LANGS" --arg deep "$DEEP" "$FILTER"
  else
    python3 -I -c "$PY_FILTER" "$ARCHIVED" "$FORKS" "$VISIBILITY" "$PUSHED_SINCE" "$NAME_RE" "$topics_json" "$langs_json" "$ALL_LANGS" "$DEEP"
  fi
}
# python fallback for the filter (stdin carries the JSON, so the program is passed with -c, not as a heredoc)
read -r -d '' PY_FILTER <<'PY' || true
import json, re, sys
archived, forks, visibility, since, name_re, topics, langs, all_langs, deep = sys.argv[1:10]
topics = [t.lower() for t in json.loads(topics)]
langs = [l.lower() for l in json.loads(langs)]
rows = json.load(sys.stdin)
out = []
for r in rows:
    if archived == "exclude" and r.get("archived"): continue
    if archived == "only" and not r.get("archived"): continue
    if forks == "exclude" and r.get("fork"): continue
    if forks == "only" and not r.get("fork"): continue
    if visibility and r.get("visibility") != visibility: continue
    if since and (r.get("pushedAt") or "") < since: continue
    if name_re and not re.search(name_re, r.get("name", "")): continue
    if topics and not (set(t.lower() for t in r.get("topics", [])) & set(topics)): continue
    if all_langs != "1":
        p = (r.get("primary") or "").lower()
        ok = p in langs
        if not ok and deep == "1":
            ok = bool(set(l.lower() for l in r.get("languages", [])) & set(langs))
        if not ok: continue
    out.append(r)
out.sort(key=lambda r: r["repo"])
json.dump(out, sys.stdout)
PY
filtered="$(printf '%s' "$raw" | apply_filter)" || die "filter failed"

count="$(printf '%s' "$filtered" | python3 -I -c 'import json,sys; print(len(json.load(sys.stdin)))' 2>/dev/null || echo 0)"

render() {
  case "$FORMAT" in
    json) printf '%s\n' "$filtered" | python3 -I -c 'import json,sys; print(json.dumps(json.load(sys.stdin), indent=2))' ;;
    ndjson) printf '%s' "$filtered" | python3 -I -c 'import json,sys; [print(json.dumps(r)) for r in json.load(sys.stdin)]' ;;
    list) printf '%s' "$filtered" | python3 -I -c 'import json,sys; [print(r["repo"]) for r in json.load(sys.stdin)]' ;;
    tsv|csv) printf '%s' "$filtered" | python3 -I -c "$PY_TABLE" "$FORMAT" ;;
  esac
}
read -r -d '' PY_TABLE <<'PY' || true
import csv, json, sys
fmt = sys.argv[1]
rows = json.load(sys.stdin)
w = csv.writer(sys.stdout, delimiter="\t" if fmt == "tsv" else ",", lineterminator="\n")
w.writerow(["repo", "primary_language", "languages", "archived", "fork", "visibility", "pushed_at", "default_branch", "topics", "url"])
for r in rows:
    w.writerow([r["repo"], r.get("primary", ""), ",".join(r.get("languages", [])), r.get("archived"), r.get("fork"), r.get("visibility", ""),
                r.get("pushedAt", ""), r.get("defaultBranch", ""), ",".join(r.get("topics", [])), r.get("url", "")])
PY

if [[ -n "$OUT" ]]; then
  render > "$OUT" || die "cannot write $OUT"
  echo "gh_j4s_repos.sh: $count repositories written to $OUT" >&2
else
  render
fi
echo "gh_j4s_repos.sh: $count repositories matched (scope=$OWNER_KIND${OWNER:+:$OWNER}${SEARCH_QUERY:+:$SEARCH_QUERY}, languages=$([[ $ALL_LANGS -eq 1 ]] && echo any || echo "$LANGS"), deep=$DEEP, archived=$ARCHIVED, forks=$FORKS)" >&2
[[ "$count" -gt 0 ]] && exit 0 || exit 2
