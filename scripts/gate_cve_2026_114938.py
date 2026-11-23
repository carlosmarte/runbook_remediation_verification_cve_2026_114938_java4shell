#!/usr/bin/env python3
"""CI/CD policy gate for CVE-2026-114938 (Java4Shell).

Self-contained: Python 3.10+, standard library only.

Deviations from the runbook text (see patterns/J4S-VER-01.md "Known gaps"):
  * JDK_VER_RE accepts up to 5 version components and a trailing "_N" build qualifier
    (e.g. Temurin tag 21.0.12_7, Liberica/Temurin baseline 17.0.21.0.3).
  * Baseline comparison is lexicographic over the full component tuple, so 17.0.21.0.3
    is PATCHED while 17.0.21.0.2 is VULNERABLE. The runbook's 4-field rule mis-reads
    17.0.21.0.3 as 17.0.21.0 and flags the fixed build.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

MITIGATION_FLAG_RE = re.compile(r"(?:-XX:-UseBASE64Intrinsics|-XX:UseAVX=[0-2])(?:\s|\"|'|\\|$)")
JDK_VER_RE = re.compile(
    r"(?:jdk|openjdk|temurin|corretto|zulu|liberica|sapmachine|java)?[-:_]?"
    r"(?<![\d.])(\d+(?:\.\d+){2,4})(?:_\d+)?(?![\d.])",
    re.I,
)
# Patched baselines (November 2026). Compared lexicographically against the parsed tuple.
PATCHED_BASELINES: dict[int, tuple[int, ...]] = {
    17: (17, 0, 21, 0, 3),
    21: (21, 0, 13, 1),
    25: (25, 0, 5, 1),
    27: (27, 0, 1, 1),
}
EOL_VULNERABLE_MAJORS = {18, 19, 20, 22, 23, 24, 26}
# J4S-FLAG-04: the intrinsic explicitly re-enabled (anti-pattern; defeats the mitigation)
EXPLICIT_ENABLE_RE = re.compile(r"-XX:\+UseBASE64Intrinsics")
# Java workload hint: runbook keywords plus vendor image names that contain neither "java" nor "jdk"
JAVA_HINT_RE = re.compile(
    r"\b(?:java|jdk|jre|jvm|openjdk|temurin|corretto|zulu|liberica|sapmachine|graalvm|"
    r"JAVA_TOOL_OPTIONS|JDK_JAVA_OPTIONS|_JAVA_OPTIONS)\b|-XX:",
    re.I,
)
JAVA8_PERF_RE = re.compile(r"8u511b33-perf", re.I)


def parse_version_tuple(ver: str) -> tuple[int, ...] | None:
    """Parse '17.0.21.0.3' or '21.0.12_7' into an int tuple (underscore qualifier dropped)."""
    core = ver.strip().split("_", 1)[0]
    parts = core.split(".")
    if not parts or not all(p.isdigit() for p in parts):
        return None
    return tuple(int(p) for p in parts[:5])


def _pad(t: tuple[int, ...], n: int) -> tuple[int, ...]:
    return tuple(list(t) + [0] * (n - len(t)))[:n]


def is_jdk_version_vulnerable(ver_str: str) -> tuple[bool, str]:
    if JAVA8_PERF_RE.search(ver_str):
        return True, f"Vulnerable Oracle Java SE build matched: {ver_str}"

    parsed = parse_version_tuple(ver_str)
    if not parsed:
        return False, f"Unparsed version string: {ver_str}"

    major = parsed[0]
    if major <= 16:
        return False, f"JDK {ver_str} (major <= 16, non-perf) is not in vulnerable HotSpot VBMI range"

    if major in EOL_VULNERABLE_MAJORS:
        return True, f"JDK {ver_str} is on an affected/EOL feature line (no patch; migrate to 21/25/27)"

    if major == 17:
        p5 = _pad(parsed, 5)
        if p5[1] == 0 and p5[2] < 6:
            return False, f"JDK {ver_str} (< 17.0.6) outside vulnerable range"
        if p5 >= PATCHED_BASELINES[17]:
            return False, f"JDK {ver_str} meets/exceeds 17.0.21.0.3 baseline"
        return True, f"JDK {ver_str} is in vulnerable 17.0.6..17.0.21.0.2 range"

    if major in PATCHED_BASELINES:
        base = PATCHED_BASELINES[major]
        if _pad(parsed, len(base)) >= base:
            return False, f"JDK {ver_str} meets/exceeds {'.'.join(map(str, base))} baseline"
        return True, f"JDK {ver_str} (< {'.'.join(map(str, base))}) is unpatched"

    return True, f"JDK {ver_str} on feature release {major} requires patch verification"


def check_dockerfile(path: Path) -> list[str]:
    violations: list[str] = []
    content = path.read_text(encoding="utf-8", errors="replace")
    has_flag = bool(MITIGATION_FLAG_RE.search(content))

    for m in JDK_VER_RE.finditer(content):
        ver = m.group(1)
        vuln, reason = is_jdk_version_vulnerable(ver)
        if vuln:
            violations.append(f"[Dockerfile:{path}] {reason}")

    if EXPLICIT_ENABLE_RE.search(content):
        violations.append(f"[Dockerfile:{path}] -XX:+UseBASE64Intrinsics explicitly re-enables the vulnerable intrinsic")

    if JAVA_HINT_RE.search(content) and not has_flag:
        violations.append(
            f"[Dockerfile:{path}] Missing -XX:-UseBASE64Intrinsics (or -XX:UseAVX=0..2) in ENV/ENTRYPOINT/CMD"
        )
    return violations


def check_k8s_manifest(path: Path) -> list[str]:
    violations: list[str] = []
    content = path.read_text(encoding="utf-8", errors="replace")
    if "kind:" not in content:
        return violations

    if not JAVA_HINT_RE.search(content):
        return violations

    if EXPLICIT_ENABLE_RE.search(content):
        violations.append(f"[Manifest:{path}] -XX:+UseBASE64Intrinsics explicitly re-enables the vulnerable intrinsic")

    for m in JDK_VER_RE.finditer(content):
        ver = m.group(1)
        vuln, reason = is_jdk_version_vulnerable(ver)
        if vuln:
            violations.append(f"[Manifest:{path}] {reason}")

    if not MITIGATION_FLAG_RE.search(content):
        violations.append(
            f"[Manifest:{path}] JVM workload missing -XX:-UseBASE64Intrinsics (e.g., via JAVA_TOOL_OPTIONS or container args)"
        )
    return violations


def check_reachability_json(path: Path) -> list[str]:
    violations: list[str] = []
    data: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    for f in data.get("findings", []):
        if f.get("verdict") == "REACHABLE_HIGH":
            violations.append(
                f"[Reachability:{path}] {f.get('finding_id')} is REACHABLE_HIGH in "
                f"{f.get('class_name')}.{f.get('method_name')} ({f.get('artifact_path')})"
            )
    return violations


def main() -> int:
    parser = argparse.ArgumentParser(description="Gate builds/deployments for CVE-2026-114938.")
    parser.add_argument("--jdk-version", type=str, default=os.environ.get("JDK_VERSION", ""), help="Explicit JDK version string")
    parser.add_argument("--jvm-opts", type=str, default=os.environ.get("JAVA_TOOL_OPTIONS", ""),
                        help="JVM flags / env string. Values start with '-', so write --jvm-opts=\"-XX:...\"")
    parser.add_argument("--scan-dir", type=Path, default=Path("."), help="Directory to scan for Dockerfiles & K8s manifests")
    parser.add_argument("--reachability-json", type=Path, default=None, help="Optional j4s-analyzer JSON report")
    parser.add_argument("--require-flag", action="store_true", help="Fail if -XX:-UseBASE64Intrinsics is absent even when version check runs")
    args = parser.parse_args()

    if EXPLICIT_ENABLE_RE.search(args.jvm_opts):
        print("POLICY GATE FAILED (CVE-2026-114938 / Java4Shell):\n  - [JVM_OPTS] -XX:+UseBASE64Intrinsics explicitly re-enables the vulnerable intrinsic", file=sys.stderr)
        return 1

    violations: list[str] = []

    if args.jdk_version:
        vuln, reason = is_jdk_version_vulnerable(args.jdk_version)
        if vuln:
            violations.append(f"[JDK_VERSION] {reason}")

    if args.require_flag and not MITIGATION_FLAG_RE.search(args.jvm_opts):
        violations.append("[JVM_OPTS] Missing -XX:-UseBASE64Intrinsics in JAVA_TOOL_OPTIONS / args")

    for root_dir, _, files in os.walk(args.scan_dir):
        if any(skip in root_dir for skip in (".git", "target", "node_modules", ".venv", "venv")):
            continue
        for fname in files:
            fpath = Path(root_dir) / fname
            lower = fname.lower()
            if lower == "dockerfile" or lower.startswith("dockerfile."):
                violations.extend(check_dockerfile(fpath))
            elif lower.endswith((".yaml", ".yml")):
                violations.extend(check_k8s_manifest(fpath))

    if args.reachability_json and args.reachability_json.exists():
        violations.extend(check_reachability_json(args.reachability_json))

    if violations:
        print("POLICY GATE FAILED (CVE-2026-114938 / Java4Shell):", file=sys.stderr)
        for v in violations:
            print(f"  - {v}", file=sys.stderr)
        return 1

    print("POLICY GATE PASSED (CVE-2026-114938 / Java4Shell).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
