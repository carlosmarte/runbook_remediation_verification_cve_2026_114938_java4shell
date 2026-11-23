#!/usr/bin/env bash
# j4s_proc.sh - per-process investigation helpers for CVE-2026-114938 (Java4Shell). Linux /proc based.
# Self-contained (bash 3.2+; coreutils, grep, awk; optional jcmd). Source for functions or run as CLI.
#
#   source helpers/j4s_proc.sh
#   j4s_cpu_vbmi                 # 0 if this x86_64 host exposes avx512_vbmi
#   j4s_list_jvm_pids            # PIDs with libjvm.so mapped
#   j4s_pid_is_jvm PID | j4s_pid_cmdline PID | j4s_pid_jvm_env PID | j4s_pid_java_home PID
#   j4s_pid_version PID          # java -version of the exact runtime the process uses
#   j4s_pid_flag_state PID       # ACTIVE | CAPPED | EXPLICITLY_ENABLED | NOT_SET_ON_CMDLINE_OR_ENV
#   j4s_pid_live_flags PID       # from jcmd VM.flags -all (same user or root)
#   j4s_pid_report PID           # everything above, one block
#   j4s_container_pids CID       # host PIDs of a docker container
#
#   helpers/j4s_proc.sh cpu | list | report PID... | flags PID | version PID | env PID | home PID | container CID
set -u

j4s_cpu_vbmi() {
  [[ "$(uname -m)" == "x86_64" ]] && [[ -r /proc/cpuinfo ]] && grep -Eq '\bavx512_vbmi\b' /proc/cpuinfo
}

j4s_cpu_summary() {
  local arch; arch="$(uname -m)"
  if [[ "$arch" != "x86_64" ]]; then echo "arch=$arch vbmi=n/a (not x86_64: VBMI intrinsic not applicable)"; return; fi
  if [[ ! -r /proc/cpuinfo ]]; then echo "arch=$arch vbmi=unknown (/proc/cpuinfo unreadable)"; return; fi
  echo "arch=$arch vbmi=$(j4s_cpu_vbmi && echo true || echo false) avx512=[$(grep -oE '\bavx512[a-z0-9_]*\b' /proc/cpuinfo | sort -u | tr '\n' ' ')]"
}

j4s_pid_is_jvm() { [[ -r "/proc/$1/maps" ]] && grep -q 'libjvm\.so' "/proc/$1/maps" 2>/dev/null; }

j4s_list_jvm_pids() {
  local d
  for d in /proc/[0-9]*; do
    [[ -r "$d/maps" ]] || continue
    grep -q 'libjvm\.so' "$d/maps" 2>/dev/null && echo "${d##*/}"
  done
}

j4s_pid_cmdline() { tr '\0' ' ' < "/proc/$1/cmdline" 2>/dev/null; echo; }

j4s_pid_jvm_env() { tr '\0' '\n' < "/proc/$1/environ" 2>/dev/null | grep -E '^(JAVA_TOOL_OPTIONS|JDK_JAVA_OPTIONS|_JAVA_OPTIONS)=' || true; }

j4s_pid_libjvm() { awk '/libjvm\.so/{print $NF; exit}' "/proc/$1/maps" 2>/dev/null; }

j4s_pid_java_home() {
  local lib; lib="$(j4s_pid_libjvm "$1")"
  if [[ "$lib" == */lib/*/libjvm.so ]]; then
    local home="${lib%/lib/*/libjvm.so}"
    [[ -x "$home/bin/java" ]] && { echo "$home"; return 0; }
  fi
  local exe; exe="$(readlink -f "/proc/$1/exe" 2>/dev/null || true)"
  [[ "$exe" == */bin/java ]] && { echo "${exe%/bin/java}"; return 0; }
  return 1
}

j4s_pid_version() {
  local home; home="$(j4s_pid_java_home "$1")" || { echo "unknown (java home not resolved)"; return 1; }
  if [[ -r "$home/release" ]]; then
    local jv; jv="$(grep -E '^JAVA_VERSION=' "$home/release" | cut -d= -f2 | tr -d '"')"
    local impl; impl="$(grep -E '^IMPLEMENTOR=' "$home/release" | cut -d= -f2 | tr -d '"')"
    echo "${jv} ${impl:+(${impl})} [from $home/release]"
  else
    JAVA_TOOL_OPTIONS= "$home/bin/java" -version 2>&1 | head -n 2 | tr '\n' ' '
    echo
  fi
}

j4s_classify_flag_text() {
  local text=" ${1:-} "
  if printf '%s' "$text" | grep -qE -- '[[:space:]"=]-XX:-UseBASE64Intrinsics[[:space:]"]'; then echo "ACTIVE"
  elif printf '%s' "$text" | grep -qE -- '[[:space:]"=]-XX:UseAVX=[0-2][[:space:]"]'; then echo "CAPPED ($(printf '%s' "$text" | grep -oE -- '-XX:UseAVX=[0-2]' | head -n1))"
  elif printf '%s' "$text" | grep -qE -- '[[:space:]"=]-XX:\+UseBASE64Intrinsics[[:space:]"]'; then echo "EXPLICITLY_ENABLED"
  else echo "NOT_SET_ON_CMDLINE_OR_ENV"; fi
}

j4s_pid_flag_state() { j4s_classify_flag_text "$(j4s_pid_cmdline "$1") $(j4s_pid_jvm_env "$1" | tr '\n' ' ')"; }

j4s_pid_live_flags() {
  local pid="$1" home jcmd_bin=""
  home="$(j4s_pid_java_home "$pid" 2>/dev/null || true)"
  [[ -n "$home" && -x "$home/bin/jcmd" ]] && jcmd_bin="$home/bin/jcmd"
  [[ -z "$jcmd_bin" ]] && command -v jcmd >/dev/null 2>&1 && jcmd_bin="$(command -v jcmd)"
  [[ -z "$jcmd_bin" ]] && { echo "jcmd-not-found"; return 1; }
  local owner; owner="$(stat -c '%U' "/proc/$pid" 2>/dev/null || true)"
  local out=""
  if [[ "$(id -u)" -eq 0 && -n "$owner" && "$owner" != "root" ]] && command -v runuser >/dev/null 2>&1; then
    out="$(runuser -u "$owner" -- "$jcmd_bin" "$pid" VM.flags -all 2>/dev/null || true)"
  elif [[ -n "$owner" && "$owner" != "$(id -un)" && "$(id -u)" -ne 0 ]]; then
    echo "different-owner ($owner): run as $owner or root"; return 1
  else
    out="$("$jcmd_bin" "$pid" VM.flags -all 2>/dev/null || true)"
  fi
  [[ -z "$out" ]] && { echo "jcmd-unavailable-or-restricted"; return 1; }
  printf '%s\n' "$out" | grep -oE '(\+|-)UseBASE64Intrinsics|UseAVX[[:space:]]*=[[:space:]]*[0-9]+' | tr '\n' ' '
  echo
}

j4s_pid_report() {
  local pid="$1"
  j4s_pid_is_jvm "$pid" || { echo "PID $pid: not a JVM (no libjvm.so) or unreadable"; return 1; }
  echo "[PID $pid] owner=$(stat -c '%U' "/proc/$pid" 2>/dev/null) start=$(ps -o lstart= -p "$pid" 2>/dev/null | sed 's/^ *//')"
  echo "  cmd:       $(j4s_pid_cmdline "$pid" | cut -c1-160)"
  echo "  jvm env:   $(j4s_pid_jvm_env "$pid" | tr '\n' ';' | sed 's/;$//')"
  echo "  libjvm:    $(j4s_pid_libjvm "$pid")"
  echo "  java home: $(j4s_pid_java_home "$pid" 2>/dev/null || echo unresolved)"
  echo "  version:   $(j4s_pid_version "$pid" 2>/dev/null)"
  echo "  cmd/env:   $(j4s_pid_flag_state "$pid")"
  echo "  live:      $(j4s_pid_live_flags "$pid" 2>/dev/null)"
  local cg; cg="$(grep -oE '(docker|containerd|cri-containerd|kubepods)[^/]*/[0-9a-f]{12,64}' "/proc/$pid/cgroup" 2>/dev/null | head -n1)"
  [[ -n "$cg" ]] && echo "  container: $cg"
  return 0
}

j4s_container_pids() {
  command -v docker >/dev/null 2>&1 || { echo "docker not found" >&2; return 1; }
  docker top "$1" -eo pid 2>/dev/null | tail -n +2 | tr -d ' ' | grep -E '^[0-9]+$'
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  cmd="${1:-}"; shift || true
  case "$cmd" in
    cpu) j4s_cpu_summary ;;
    list) j4s_list_jvm_pids ;;
    report) if [[ $# -eq 0 ]]; then set -- $(j4s_list_jvm_pids); fi; [[ $# -eq 0 ]] && echo "no JVM processes found"; for p in "$@"; do j4s_pid_report "$p"; done ;;
    flags) echo "cmd/env: $(j4s_pid_flag_state "$1")"; echo "live:    $(j4s_pid_live_flags "$1")" ;;
    version) j4s_pid_version "$1" ;;
    env) j4s_pid_jvm_env "$1" ;;
    home) j4s_pid_java_home "$1" ;;
    container) j4s_container_pids "$1" ;;
    classify) j4s_classify_flag_text "${1:-}" ;;
    *) sed -n '2,16p' "$0"; exit 2 ;;
  esac
fi
