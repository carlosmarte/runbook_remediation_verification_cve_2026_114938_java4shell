#!/usr/bin/env bash
set -u
# Self-contained Linux host/container audit for CVE-2026-114938 (Java4Shell).
# Requires: bash 4+, coreutils, grep, awk; optional: docker, jcmd.

ARCH="$(uname -m)"
CPU_VBMI="false"
if [[ "$ARCH" == "x86_64" ]] && grep -Eq '\bavx512_vbmi\b' /proc/cpuinfo 2>/dev/null; then
  CPU_VBMI="true"
fi

echo "=== CVE-2026-114938 (Java4Shell) Host & Container Audit ==="
echo "Arch: $ARCH | Host AVX-512 VBMI (/proc/cpuinfo): $CPU_VBMI"
echo ""

# Returns 0 = potentially vulnerable, 1 = patched/unaffected, 2 = unparseable.
# Compares up to 5 numeric components lexicographically against the Nov 2026 baselines
# (17.0.21.0.3 / 21.0.13.1 / 25.0.5.1 / 27.0.1.1). Trailing "_N" / "+N" qualifiers are ignored.
version_ge() {
  # version_ge "a.b.c.d.e" "x.y.z.w.v"  -> 0 if first >= second
  local IFS='.' a b i
  read -r -a a <<< "$1"; read -r -a b <<< "$2"
  for i in 0 1 2 3 4; do
    local x="${a[i]:-0}" y="${b[i]:-0}"
    (( x > y )) && return 0
    (( x < y )) && return 1
  done
  return 0
}

is_version_potentially_vulnerable() {
  local ver_str="$1"
  if [[ "$ver_str" =~ 8u511b33-perf ]]; then
    return 0
  fi

  local core
  core="$(printf '%s' "$ver_str" | sed -E 's/[_+-].*$//' | grep -oE '^[0-9]+(\.[0-9]+){0,4}' || true)"
  [[ -z "$core" ]] && return 2

  local major minor patch
  IFS='.' read -r major minor patch _ <<< "$core"
  major="${major:-0}"; minor="${minor:-0}"; patch="${patch:-0}"

  if (( major <= 16 )); then
    return 1
  fi

  case "$major" in
    18|19|20|22|23|24|26) return 0 ;;
    17)
      if (( minor == 0 && patch < 6 )); then return 1; fi
      version_ge "$core" "17.0.21.0.3" && return 1
      return 0
      ;;
    21) version_ge "$core" "21.0.13.1" && return 1; return 0 ;;
    25) version_ge "$core" "25.0.5.1"  && return 1; return 0 ;;
    27) version_ge "$core" "27.0.1.1"  && return 1; return 0 ;;
    *)  return 0 ;;
  esac
}

check_cmdline_mitigation() {
  local cmdline="$1"
  if printf '%s' "$cmdline" | grep -qE -- '(-XX:-UseBASE64Intrinsics|-XX:UseAVX=[0-2])'; then
    echo "MITIGATED_FLAG"
  else
    echo "MISSING_FLAG"
  fi
}

echo "--- Running JVM Processes (via /proc/<pid>/maps -> libjvm.so) ---"
for pid_dir in /proc/[0-9]*; do
  pid="${pid_dir##*/}"
  [[ -r "$pid_dir/maps" ]] || continue
  if grep -q 'libjvm\.so' "$pid_dir/maps" 2>/dev/null; then
    cmdline="$(tr '\0' ' ' < "$pid_dir/cmdline" 2>/dev/null || true)"
    flag_status="$(check_cmdline_mitigation "$cmdline")"

    jvm_path="$(grep -m1 'libjvm\.so' "$pid_dir/maps" | awk '{print $NF}')"
    java_bin=""
    if [[ "$jvm_path" == */lib/server/libjvm.so || "$jvm_path" == */lib/*/libjvm.so ]]; then
      candidate="${jvm_path%/lib/*/libjvm.so}/bin/java"
      [[ -x "$candidate" ]] && java_bin="$candidate"
    fi
    if [[ -z "$java_bin" ]]; then
      argv0="${cmdline%% *}"
      [[ "$argv0" == *java* && -x "$argv0" ]] && java_bin="$argv0"
    fi

    ver_line="unknown"
    ver_status="UNKNOWN"
    if [[ -n "$java_bin" ]]; then
      ver_line="$("$java_bin" -version 2>&1 | head -n 2 | tr '\n' ' ' | sed 's/[[:space:]]\+/ /g')"
      ver_token="$(printf '%s' "$ver_line" | grep -oE '[0-9]+(\.[0-9]+){1,3}|8u[0-9a-zA-Z_-]+' | head -n1 || true)"
      if [[ -n "$ver_token" ]]; then
        if is_version_potentially_vulnerable "$ver_token"; then
          ver_status="VULN_RANGE"
        else
          ver_status="PATCHED_OR_UNAFFECTED"
        fi
      fi
    fi

    risk="LOW"
    if [[ "$CPU_VBMI" == "true" && "$ver_status" != "PATCHED_OR_UNAFFECTED" && "$flag_status" == "MISSING_FLAG" ]]; then
      risk="HIGH_EXPOSURE"
    elif [[ "$ver_status" == "VULN_RANGE" && "$flag_status" == "MISSING_FLAG" ]]; then
      risk="CHECK_CPU_AND_PATCH"
    fi

    printf "PID=%s | RISK=%s | VER_STATUS=%s | FLAG=%s | CMD=%s | VER=%s\n" \
      "$pid" "$risk" "$ver_status" "$flag_status" "${cmdline:0:120}" "$ver_line"
  fi
done

echo ""
echo "--- Docker Containers (Running) ---"
if command -v docker >/dev/null 2>&1; then
  while IFS= read -r cid; do
    [[ -z "$cid" ]] && continue
    cname="$(docker inspect --format '{{.Name}}' "$cid" 2>/dev/null | sed 's|^/||')"
    cimage="$(docker inspect --format '{{.Config.Image}}' "$cid" 2>/dev/null)"

    c_pids="$(docker top "$cid" -eo pid 2>/dev/null | tail -n +2 | tr -d ' ' || true)"
    has_jvm="false"
    missing_flag_count=0
    for cpid in $c_pids; do
      if [[ -r "/proc/$cpid/maps" ]] && grep -q 'libjvm\.so' "/proc/$cpid/maps" 2>/dev/null; then
        has_jvm="true"
        ccmd="$(tr '\0' ' ' < "/proc/$cpid/cmdline" 2>/dev/null || true)"
        if [[ "$(check_cmdline_mitigation "$ccmd")" == "MISSING_FLAG" ]]; then
          ((missing_flag_count++))
        fi
      fi
    done

    cver="$(docker exec "$cid" sh -c 'command -v java >/dev/null 2>&1 && java -version 2>&1 | head -n1 || echo "no-shell-or-java"' 2>/dev/null || echo "exec-unavailable")"

    echo "Container=$cname ($cid) | Image=$cimage | HasJVM=$has_jvm | MissingFlagProcs=$missing_flag_count | JavaCheck=$cver"
  done < <(docker ps -q 2>/dev/null || true)
else
  echo "Docker CLI not installed or daemon unreachable."
fi
