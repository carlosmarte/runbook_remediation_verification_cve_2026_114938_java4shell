#!/usr/bin/env bash
# j4s_flag.sh - remediation helpers for the CVE-2026-114938 (Java4Shell) JVM mitigation flag.
# Self-contained (bash 3.2+). Source it for functions, or run it as a CLI.
#
#   source helpers/j4s_flag.sh
#   j4s_flag_has "$JAVA_TOOL_OPTIONS"            # 0 if -XX:-UseBASE64Intrinsics or -XX:UseAVX=0..2 present
#   JAVA_TOOL_OPTIONS="$(j4s_flag_add "$JAVA_TOOL_OPTIONS")"   # idempotent; also strips -XX:+UseBASE64Intrinsics
#   j4s_flag_remove "<opts>"                     # for post-patch cleanup
#
#   helpers/j4s_flag.sh has|add|remove "<opts>"
#   helpers/j4s_flag.sh snippet dockerfile|compose|k8s-env|k8s-patch|systemd|helm|tomcat|gradle|maven|bash
#   helpers/j4s_flag.sh k8s-apply <deployment> [-n ns] [-c container] [--kind Deployment|StatefulSet|DaemonSet] [--yes]
#   helpers/j4s_flag.sh k8s-verify <deployment> [-n ns]
set -u

J4S_FLAG='-XX:-UseBASE64Intrinsics'

j4s_flag_has() {
  printf '%s' " ${1:-} " | grep -qE -- '[[:space:]"=](-XX:-UseBASE64Intrinsics|-XX:UseAVX=[0-2])[[:space:]"]'
}

j4s_flag_enabled_explicitly() {
  printf '%s' " ${1:-} " | grep -qE -- '[[:space:]"=]-XX:\+UseBASE64Intrinsics[[:space:]"]'
}

# Prints the option string with the mitigation added once and any explicit re-enable removed.
j4s_flag_add() {
  local opts="${1:-}"
  opts="$(printf '%s' "$opts" | sed -E 's/(^|[[:space:]])-XX:\+UseBASE64Intrinsics([[:space:]]|$)/\1\2/g')"
  if printf '%s' " $opts " | grep -qE -- '[[:space:]]-XX:-UseBASE64Intrinsics[[:space:]]'; then
    printf '%s\n' "$opts" | sed -E 's/^[[:space:]]+|[[:space:]]+$//g'
  else
    printf '%s\n' "$opts $J4S_FLAG" | sed -E 's/^[[:space:]]+|[[:space:]]+$//g; s/[[:space:]]{2,}/ /g'
  fi
}

j4s_flag_remove() {
  printf '%s\n' "${1:-}" | sed -E 's/(^|[[:space:]])-XX:-UseBASE64Intrinsics([[:space:]]|$)/\1\2/g; s/^[[:space:]]+|[[:space:]]+$//g; s/[[:space:]]{2,}/ /g'
}

j4s_flag_snippet() {
  case "${1:-}" in
    dockerfile) cat <<'S'
# Dockerfile - applies to every JVM started in the image (build tools included)
ENV JAVA_TOOL_OPTIONS="-XX:-UseBASE64Intrinsics ${JAVA_TOOL_OPTIONS:-}"
# or, scoped to the entrypoint only:
# ENTRYPOINT ["java", "-XX:-UseBASE64Intrinsics", "-jar", "/app/app.jar"]
S
    ;;
    compose) cat <<'S'
# docker-compose.yml
services:
  app:
    environment:
      JAVA_TOOL_OPTIONS: "-XX:-UseBASE64Intrinsics"
S
    ;;
    k8s-env) cat <<'S'
# Pod/Deployment container spec fragment
env:
  - name: JAVA_TOOL_OPTIONS
    value: "-XX:-UseBASE64Intrinsics"
S
    ;;
    k8s-patch) cat <<'S'
# Strategic-merge patch (replace CONTAINER with the container name)
kubectl patch deployment NAME -n NAMESPACE --type strategic -p '
spec:
  template:
    spec:
      containers:
      - name: CONTAINER
        env:
        - name: JAVA_TOOL_OPTIONS
          value: "-XX:-UseBASE64Intrinsics"'
S
    ;;
    systemd) cat <<'S'
# /etc/systemd/system/<service>.service.d/java4shell.conf
[Service]
Environment="JAVA_TOOL_OPTIONS=-XX:-UseBASE64Intrinsics"
# then: systemctl daemon-reload && systemctl restart <service>
S
    ;;
    helm) cat <<'S'
# values.yaml (chart must render .Values.env or extraEnv)
env:
  - name: JAVA_TOOL_OPTIONS
    value: "-XX:-UseBASE64Intrinsics"
S
    ;;
    tomcat) cat <<'S'
# $CATALINA_BASE/bin/setenv.sh
CATALINA_OPTS="$CATALINA_OPTS -XX:-UseBASE64Intrinsics"
S
    ;;
    gradle) cat <<'S'
# gradle.properties (build daemon and test JVMs)
org.gradle.jvmargs=-XX:-UseBASE64Intrinsics
# build.gradle(.kts) for the application run/test tasks:
tasks.withType(JavaExec).configureEach { jvmArgs "-XX:-UseBASE64Intrinsics" }
tasks.withType(Test).configureEach   { jvmArgs "-XX:-UseBASE64Intrinsics" }
S
    ;;
    maven) cat <<'S'
# .mvn/jvm.config
-XX:-UseBASE64Intrinsics
# surefire/failsafe: <argLine>-XX:-UseBASE64Intrinsics</argLine>
S
    ;;
    bash) cat <<'S'
# shell / CI job
export JAVA_TOOL_OPTIONS="-XX:-UseBASE64Intrinsics${JAVA_TOOL_OPTIONS:+ $JAVA_TOOL_OPTIONS}"
S
    ;;
    *) echo "snippet: dockerfile|compose|k8s-env|k8s-patch|systemd|helm|tomcat|gradle|maven|bash" >&2; return 2 ;;
  esac
}

# j4s_flag_k8s_apply NAME [-n ns] [-c container] [--kind Deployment] [--yes]
j4s_flag_k8s_apply() {
  local name="${1:-}"; shift || true
  local ns="" container="" kind="deployment" yes=0
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -n) ns="$2"; shift 2 ;;
      -c) container="$2"; shift 2 ;;
      --kind) kind="$2"; shift 2 ;;
      --yes) yes=1; shift ;;
      *) echo "unknown arg: $1" >&2; return 2 ;;
    esac
  done
  [[ -z "$name" ]] && { echo "usage: k8s-apply NAME [-n ns] [-c container] [--kind kind] [--yes]" >&2; return 2; }
  command -v kubectl >/dev/null 2>&1 || { echo "kubectl not found" >&2; return 1; }
  local nsargs=(); [[ -n "$ns" ]] && nsargs=(-n "$ns")

  local containers
  containers="$(kubectl get "$kind" "$name" "${nsargs[@]}" -o jsonpath='{range .spec.template.spec.containers[*]}{.name}{"\n"}{end}' 2>/dev/null)" || { echo "cannot read $kind/$name" >&2; return 1; }
  [[ -z "$container" ]] && container="$(printf '%s\n' "$containers" | head -n1)"

  local existing
  existing="$(kubectl get "$kind" "$name" "${nsargs[@]}" -o jsonpath="{.spec.template.spec.containers[?(@.name=='$container')].env[?(@.name=='JAVA_TOOL_OPTIONS')].value}" 2>/dev/null || true)"
  local newval; newval="$(j4s_flag_add "$existing")"

  local patch
  patch="$(printf '{"spec":{"template":{"spec":{"containers":[{"name":"%s","env":[{"name":"JAVA_TOOL_OPTIONS","value":"%s"}]}]}}}}' "$container" "$newval")"
  echo "# $kind/$name container=$container ns=${ns:-<current>}"
  echo "# current JAVA_TOOL_OPTIONS: '${existing}'  ->  '${newval}'"
  echo "kubectl patch $kind $name ${nsargs[*]} --type strategic -p '$patch'"
  if [[ "$yes" -eq 1 ]]; then
    kubectl patch "$kind" "$name" "${nsargs[@]}" --type strategic -p "$patch" && kubectl rollout status "$kind/$name" "${nsargs[@]}" --timeout=300s
  else
    echo "# dry run. Re-run with --yes to apply (this triggers a rolling restart)."
  fi
}

# j4s_flag_k8s_verify NAME [-n ns] [--kind kind]  -> checks spec env and live jcmd inside pods (if jcmd exists in image)
j4s_flag_k8s_verify() {
  local name="${1:-}"; shift || true
  local ns="" kind="deployment"
  while [[ $# -gt 0 ]]; do
    case "$1" in -n) ns="$2"; shift 2 ;; --kind) kind="$2"; shift 2 ;; *) shift ;; esac
  done
  command -v kubectl >/dev/null 2>&1 || { echo "kubectl not found" >&2; return 1; }
  local nsargs=(); [[ -n "$ns" ]] && nsargs=(-n "$ns")
  local spec
  spec="$(kubectl get "$kind" "$name" "${nsargs[@]}" -o jsonpath='{range .spec.template.spec.containers[*]}{.name}{": args="}{.args}{" cmd="}{.command}{" env="}{.env[?(@.name=="JAVA_TOOL_OPTIONS")].value}{"\n"}{end}')"
  printf '%s\n' "$spec" | while IFS= read -r line; do
    if j4s_flag_has "$line"; then echo "SPEC OK   $line"; else echo "SPEC MISS $line"; fi
  done
  local selector
  selector="$(kubectl get "$kind" "$name" "${nsargs[@]}" -o jsonpath='{.spec.selector.matchLabels}' | sed -E 's/[{}"]//g; s/:/=/g')"
  for pod in $(kubectl get pods "${nsargs[@]}" -l "$selector" -o jsonpath='{.items[*].metadata.name}'); do
    local out
    out="$(kubectl exec "${nsargs[@]}" "$pod" -- sh -c 'command -v jcmd >/dev/null 2>&1 && for p in $(jcmd -l 2>/dev/null | grep -v JCmd | cut -d" " -f1); do jcmd "$p" VM.flags -all 2>/dev/null | grep -oE "(\+|-)UseBASE64Intrinsics|UseAVX *= *[0-9]+" | tr "\n" " "; done' 2>/dev/null || true)"
    echo "LIVE  $pod: ${out:-jcmd unavailable in image; rely on SPEC + hs_err/metrics}"
  done
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  cmd="${1:-}"; shift || true
  case "$cmd" in
    has) j4s_flag_has "${1:-}" && { echo "present"; exit 0; } || { echo "missing"; exit 1; } ;;
    add) j4s_flag_add "${1:-}" ;;
    remove) j4s_flag_remove "${1:-}" ;;
    snippet) j4s_flag_snippet "${1:-}" ;;
    k8s-apply) j4s_flag_k8s_apply "$@" ;;
    k8s-verify) j4s_flag_k8s_verify "$@" ;;
    *) sed -n '2,15p' "$0"; exit 2 ;;
  esac
fi
