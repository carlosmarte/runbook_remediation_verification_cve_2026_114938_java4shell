#!/usr/bin/env bash
set -u
if (( BASH_VERSINFO[0] < 4 )); then
  echo "error: bash 4+ required (associative arrays); found $BASH_VERSION. Run on the Linux target host." >&2
  exit 2
fi
# Self-contained, non-intrusive runtime verification for CVE-2026-114938 (Java4Shell).
# Sends no payloads. Requires: bash 4+, coreutils, grep, awk; optional: docker, kubectl+python3, jcmd, curl.

HEALTH_URLS=()
CHECK_DOCKER=1
CHECK_K8S=0
K8S_NAMESPACE=""
K8S_SELECTOR=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --health-url)
      HEALTH_URLS+=("${2:-}")
      shift 2
      ;;
    --no-docker)
      CHECK_DOCKER=0
      shift
      ;;
    --k8s)
      CHECK_K8S=1
      shift
      ;;
    --k8s-namespace)
      CHECK_K8S=1
      K8S_NAMESPACE="${2:-}"
      shift 2
      ;;
    --k8s-selector)
      CHECK_K8S=1
      K8S_SELECTOR="${2:-}"
      shift 2
      ;;
    *)
      echo "Usage: $0 [--health-url URL] [--no-docker] [--k8s] [--k8s-namespace NS] [--k8s-selector LABEL]" >&2
      exit 2
      ;;
  esac
done

ARCH="$(uname -m)"
VBMI="false"
VBMI2="false"
AVX512F="false"

if [[ "$ARCH" == "x86_64" ]] && [[ -r /proc/cpuinfo ]]; then
  grep -Eq '\bavx512f\b' /proc/cpuinfo && AVX512F="true"
  grep -Eq '\bavx512_vbmi\b' /proc/cpuinfo && VBMI="true"
  grep -Eq '\bavx512_vbmi2\b' /proc/cpuinfo && VBMI2="true"
fi

echo "=== CVE-2026-114938 (Java4Shell) Non-Intrusive Runtime Verification ==="
echo "Host Arch:        $ARCH"
echo "CPU Flags:        avx512f=$AVX512F | avx512_vbmi=$VBMI | avx512_vbmi2=$VBMI2"
echo ""

classify_flag_text() {
  local text="$1"
  if printf '%s' "$text" | grep -qE -- '(^|[[:space:]"=])-XX:-UseBASE64Intrinsics([[:space:]"]|$)'; then
    echo "ACTIVE (-XX:-UseBASE64Intrinsics)"
  elif printf '%s' "$text" | grep -qE -- '(^|[[:space:]"=])-XX:UseAVX=[0-2]([[:space:]"]|$)'; then
    local avx_val
    avx_val="$(printf '%s' "$text" | grep -oE -- '-XX:UseAVX=[0-2]' | head -n1)"
    echo "CAPPED ($avx_val)"
  elif printf '%s' "$text" | grep -qE -- '(^|[[:space:]"=])-XX:\+UseBASE64Intrinsics([[:space:]"]|$)'; then
    echo "EXPLICITLY_ENABLED (-XX:+UseBASE64Intrinsics)"
  else
    echo "NOT_SET_ON_CMDLINE_OR_ENV"
  fi
}

query_live_jcmd() {
  local pid="$1"
  local java_bin="$2"
  local pid_dir="/proc/$pid"
  local jcmd_bin=""

  if [[ -n "$java_bin" ]] && [[ -x "$(dirname "$java_bin")/jcmd" ]]; then
    jcmd_bin="$(dirname "$java_bin")/jcmd"
  elif command -v jcmd >/dev/null 2>&1; then
    jcmd_bin="$(command -v jcmd)"
  fi

  if [[ -z "$jcmd_bin" ]]; then
    echo "jcmd-not-found"
    return
  fi

  local proc_owner vm_out=""
  proc_owner="$(stat -c '%U' "$pid_dir" 2>/dev/null || true)"

  if [[ -n "$proc_owner" ]] && [[ "$proc_owner" != "$(id -un)" ]] && [[ "$(id -u)" -ne 0 ]]; then
    echo "different-owner ($proc_owner); run as $proc_owner or root"
    return
  fi

  if [[ "$(id -u)" -eq 0 ]] && [[ -n "$proc_owner" ]] && [[ "$proc_owner" != "root" ]] && command -v runuser >/dev/null 2>&1; then
    vm_out="$(runuser -u "$proc_owner" -- "$jcmd_bin" "$pid" VM.flags -all 2>/dev/null || true)"
  else
    vm_out="$("$jcmd_bin" "$pid" VM.flags -all 2>/dev/null || true)"
  fi

  if [[ -z "$vm_out" ]]; then
    echo "jcmd-unavailable-or-restricted"
    return
  fi

  local b64_flag avx_flag
  b64_flag="$(printf '%s\n' "$vm_out" | grep -oE '(\+|-)?UseBASE64Intrinsics[^[:space:]]*' | head -n1 || true)"
  avx_flag="$(printf '%s\n' "$vm_out" | grep -oE 'UseAVX[[:space:]]*=[[:space:]]*[0-9]+' | head -n1 || true)"
  echo "jcmd: ${b64_flag:-n/a} | ${avx_flag:-n/a}"
}

inspect_proc_jvm() {
  local pid="$1"
  local scope="$2"
  local pid_dir="/proc/$pid"

  [[ -r "$pid_dir/maps" ]] || return 1
  grep -q 'libjvm\.so' "$pid_dir/maps" 2>/dev/null || return 1

  local jvm_path cmdline env_vars java_bin ver_summary cmd_env_state live_state
  jvm_path="$(awk '/libjvm\.so/{print $NF; exit}' "$pid_dir/maps")"
  cmdline="$(tr '\0' ' ' < "$pid_dir/cmdline" 2>/dev/null || true)"
  env_vars="$(tr '\0' '\n' < "$pid_dir/environ" 2>/dev/null | grep -E '^(JAVA_TOOL_OPTIONS|JDK_JAVA_OPTIONS|_JAVA_OPTIONS)=' || true)"

  java_bin=""
  if [[ "$jvm_path" == */lib/*/libjvm.so ]]; then
    local cand="${jvm_path%/lib/*/libjvm.so}/bin/java"
    [[ -x "$cand" ]] && java_bin="$cand"
  fi
  if [[ -z "$java_bin" ]]; then
    local argv0="${cmdline%% *}"
    [[ "$argv0" == *java* && -x "$argv0" ]] && java_bin="$argv0"
  fi

  ver_summary="version-not-directly-resolved"
  if [[ -n "$java_bin" ]]; then
    ver_summary="$("$java_bin" -version 2>&1 | head -n 2 | tr '\n' ' ' | sed 's/[[:space:]]\+/ /g')"
  fi

  cmd_env_state="$(classify_flag_text "$cmdline $env_vars")"
  live_state="$(query_live_jcmd "$pid" "$java_bin")"

  echo "  [JVM PID=$pid | Scope=$scope]"
  echo "    libjvm.so:    $jvm_path"
  echo "    Command:      ${cmdline:0:150}"
  [[ -n "$env_vars" ]] && echo "    JVM Env:      $(printf '%s' "$env_vars" | tr '\n' '; ')"
  echo "    Java Version: $ver_summary"
  echo "    Cmd/Env Flag: $cmd_env_state"
  echo "    Live VM Flag: $live_state"
  return 0
}

declare -A CONTAINER_PID_OWNER

echo "--- 1. Running Docker Containers ---"
if [[ "$CHECK_DOCKER" -eq 1 ]] && command -v docker >/dev/null 2>&1; then
  docker_cids="$(docker ps -q 2>/dev/null || true)"
  if [[ -z "$docker_cids" ]]; then
    echo "No running Docker containers found."
  else
    for cid in $docker_cids; do
      cname="$(docker inspect --format '{{.Name}}' "$cid" 2>/dev/null | sed 's|^/||')"
      cimage="$(docker inspect --format '{{.Config.Image}}' "$cid" 2>/dev/null || true)"
      cenv_flags="$(docker inspect --format '{{range .Config.Env}}{{println .}}{{end}}' "$cid" 2>/dev/null | grep -E '^(JAVA_TOOL_OPTIONS|JDK_JAVA_OPTIONS|_JAVA_OPTIONS)=' || true)"

      echo "Container: $cname ($cid) | Image: $cimage"
      [[ -n "$cenv_flags" ]] && echo "  Image/Spec Env: $(printf '%s' "$cenv_flags" | tr '\n' '; ')"

      cpids="$(docker top "$cid" -eo pid 2>/dev/null | tail -n +2 | tr -d ' ' || true)"
      jvm_in_container=0
      for cpid in $cpids; do
        [[ "$cpid" =~ ^[0-9]+$ ]] || continue
        CONTAINER_PID_OWNER["$cpid"]="docker:$cname"
        if inspect_proc_jvm "$cpid" "docker:$cname"; then
          jvm_in_container=1
        fi
      done
      if [[ "$jvm_in_container" -eq 0 ]]; then
        echo "  No libjvm.so process visible in /proc for container $cname."
      fi
    done
  fi
else
  echo "Docker inspection skipped or docker CLI unavailable."
fi

echo ""
echo "--- 2. Host & Remaining /proc JVM Processes ---"
host_jvm_count=0
for pid_dir in /proc/[0-9]*; do
  pid="${pid_dir##*/}"
  [[ -n "${CONTAINER_PID_OWNER[$pid]:-}" ]] && continue
  if inspect_proc_jvm "$pid" "host"; then
    ((host_jvm_count++))
  fi
done
if [[ "$host_jvm_count" -eq 0 ]]; then
  echo "No non-container host libjvm.so processes detected."
fi

if [[ "$CHECK_K8S" -eq 1 ]]; then
  echo ""
  echo "--- 3. Kubernetes Pods & Containers (Read-Only Spec/Status Inspection) ---"
  if ! command -v kubectl >/dev/null 2>&1; then
    echo "kubectl not found in PATH; skipping Kubernetes pod inspection."
  else
    ns_args=(-A)
    [[ -n "$K8S_NAMESPACE" ]] && ns_args=(-n "$K8S_NAMESPACE")
    sel_args=()
    [[ -n "$K8S_SELECTOR" ]] && sel_args=(-l "$K8S_SELECTOR")

    kubectl get pods "${ns_args[@]}" "${sel_args[@]}" -o json 2>/dev/null | python3 -c '
import json, re, sys

data = json.load(sys.stdin)
flag_re = re.compile(r"(?:-XX:-UseBASE64Intrinsics|-XX:UseAVX=[0-2])")

for pod in data.get("items", []):
    meta = pod.get("metadata", {})
    ns = meta.get("namespace", "default")
    name = meta.get("name", "<pod>")
    spec = pod.get("spec", {})
    statuses = {s.get("name"): s for s in pod.get("status", {}).get("containerStatuses", [])}

    for c in spec.get("containers", []) + spec.get("initContainers", []):
        cname = c.get("name", "<container>")
        image = c.get("image", "")
        st = statuses.get(cname, {})
        image_id = st.get("imageID", "")
        args_str = " ".join(c.get("args", []) + c.get("command", []))
        env_parts = []
        for e in c.get("env", []):
            ename = e.get("name", "")
            eval_s = e.get("value", "")
            if ename in ("JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "_JAVA_OPTIONS"):
                env_parts.append(f"{ename}={eval_s}")
        combined = f"{args_str} {\x27 \x27.join(env_parts)}"
        is_jvm_like = bool(re.search(r"(?:java|jdk|jvm|spring|tomcat|kafka|elasticsearch|keycloak|jenkins)", f"{image} {combined}", re.I))
        has_flag = bool(flag_re.search(combined))

        if is_jvm_like or env_parts or flag_re.search(combined):
            print(f"Pod: {ns}/{name} | Container: {cname} | Image: {image}")
            if image_id:
                print(f"  Resolved ImageID: {image_id}")
            if env_parts:
                print(f"  JVM Env:          {\"; \".join(env_parts)}")
            print(f"  Manifest Flag:    {\"PRESENT\" if has_flag else \"MISSING_OR_NOT_IN_SPEC\"}")
' 2>/dev/null || echo "Unable to query Kubernetes API via kubectl."
  fi
fi

if [[ "${#HEALTH_URLS[@]}" -gt 0 ]]; then
  echo ""
  echo "--- 4. Service Health Checks (GET Only) ---"
  for url in "${HEALTH_URLS[@]}"; do
    [[ -z "$url" ]] && continue
    code="$(curl -sS -m 5 -o /dev/null -w '%{http_code}' "$url" 2>/dev/null || echo "000")"
    echo "  $url -> HTTP $code"
  done
fi
