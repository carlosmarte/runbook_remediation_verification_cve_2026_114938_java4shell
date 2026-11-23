#!/usr/bin/env python3
"""Audit Linux hosts and Docker containers for CVE-2026-114938 (Java4Shell).

Self-contained: Python 3.10+, standard library only. Linux /proc required for process
discovery; on other platforms only the CPU section is meaningful.

Deviation from the runbook text: version comparison is lexicographic over up to 5
components so the 17.0.21.0.3 baseline and Temurin "_N" tags are handled correctly.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import re
import shutil
import subprocess
from dataclasses import asdict, dataclass
from typing import Any


@dataclass
class JvmFinding:
    pid: int
    source: str
    jvm_lib_path: str
    java_binary: str | None
    version_output: str
    parsed_version: str | None
    version_status: str
    flag_status: str
    cmdline: str
    exposure_verdict: str


def detect_cpu_vbmi() -> dict[str, Any]:
    arch = platform.machine()
    flags: list[str] = []
    vbmi = False
    vbmi2 = False

    if arch == "x86_64" and os.path.isfile("/proc/cpuinfo"):
        try:
            with open("/proc/cpuinfo", "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    if line.lower().startswith("flags"):
                        tokens = line.split(":", 1)[1].strip().split()
                        flags = sorted(set(t for t in tokens if "avx512" in t))
                        vbmi = "avx512_vbmi" in tokens
                        vbmi2 = "avx512_vbmi2" in tokens
                        break
        except OSError:
            pass

    return {
        "arch": arch,
        "avx512_vbmi": vbmi,
        "avx512_vbmi2": vbmi2,
        "avx512_flags_sample": flags[:20],
    }


PATCHED_BASELINES: dict[int, tuple[int, ...]] = {
    17: (17, 0, 21, 0, 3),
    21: (21, 0, 13, 1),
    25: (25, 0, 5, 1),
    27: (27, 0, 1, 1),
}
EOL_VULNERABLE_MAJORS = {18, 19, 20, 22, 23, 24, 26}


def _parse_numeric_tuple(ver_str: str) -> tuple[int, ...] | None:
    core = ver_str.strip().split("_", 1)[0].split("+", 1)[0].split("-", 1)[0]
    parts = core.split(".")
    if not parts or not all(p.isdigit() for p in parts):
        return None
    return tuple(int(p) for p in parts[:5])


def _pad(t: tuple[int, ...], n: int) -> tuple[int, ...]:
    return tuple(list(t) + [0] * (n - len(t)))[:n]


def classify_java_version(version_output: str) -> tuple[str | None, str]:
    if not version_output or version_output.startswith(("no-shell", "exec-unavailable", "unknown")):
        return None, "UNKNOWN"

    if "8u511b33-perf" in version_output:
        return "8u511b33-perf", "VULN_RANGE"

    m = re.search(r'"([^"]+)"', version_output)
    candidate = m.group(1) if m else ""
    if not candidate:
        m2 = re.search(r"\b(\d+(?:\.\d+){1,4})\b", version_output)
        candidate = m2.group(1) if m2 else ""

    parsed = _parse_numeric_tuple(candidate)
    if not parsed:
        return candidate or None, "UNKNOWN"

    major = parsed[0]
    if major <= 16:
        return candidate, "PATCHED_OR_UNAFFECTED"
    if major in EOL_VULNERABLE_MAJORS:
        return candidate, "VULN_RANGE"
    if major == 17:
        p5 = _pad(parsed, 5)
        if p5[1] == 0 and p5[2] < 6:
            return candidate, "PATCHED_OR_UNAFFECTED"
        return candidate, "PATCHED_OR_UNAFFECTED" if p5 >= PATCHED_BASELINES[17] else "VULN_RANGE"
    if major in PATCHED_BASELINES:
        base = PATCHED_BASELINES[major]
        return candidate, "PATCHED_OR_UNAFFECTED" if _pad(parsed, len(base)) >= base else "VULN_RANGE"
    return candidate, "VULN_RANGE"


def check_cmdline_flags(cmdline: str) -> str:
    if re.search(r"(?:-XX:-UseBASE64Intrinsics|-XX:UseAVX=[0-2])(?:\s|$)", cmdline):
        return "MITIGATED_FLAG"
    return "MISSING_FLAG"


def run_java_version(java_bin: str, timeout: float = 3.0) -> str:
    try:
        proc = subprocess.run(
            [java_bin, "-version"],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        combined = (proc.stderr or proc.stdout or "").strip()
        lines = [line.strip() for line in combined.splitlines() if line.strip()]
        return " | ".join(lines[:2]) if lines else "unknown"
    except Exception as exc:
        return f"error:{exc}"


def inspect_pid(pid: int, source: str, cpu_vbmi: bool) -> JvmFinding | None:
    maps_path = f"/proc/{pid}/maps"
    cmdline_path = f"/proc/{pid}/cmdline"
    try:
        with open(maps_path, "r", encoding="utf-8", errors="replace") as f:
            maps_text = f.read()
    except OSError:
        return None

    jvm_match = re.search(r"(\S*libjvm\.so\S*)", maps_text)
    if not jvm_match:
        return None

    jvm_lib_path = jvm_match.group(1)
    try:
        with open(cmdline_path, "rb") as f:
            raw_cmd = f.read().split(b"\x00")
        cmdline = " ".join(part.decode("utf-8", errors="replace") for part in raw_cmd if part)
    except OSError:
        cmdline = ""

    java_bin: str | None = None
    m_home = re.match(r"^(.+?)/lib/[^/]+/libjvm\.so$", jvm_lib_path)
    if m_home:
        candidate = f"{m_home.group(1)}/bin/java"
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            java_bin = candidate

    if not java_bin and cmdline:
        argv0 = cmdline.split(" ", 1)[0]
        if os.path.basename(argv0).startswith("java") and os.path.isfile(argv0) and os.access(argv0, os.X_OK):
            java_bin = argv0

    ver_output = run_java_version(java_bin) if java_bin else "unknown (no java binary resolved)"
    parsed_ver, ver_status = classify_java_version(ver_output)
    flag_status = check_cmdline_flags(cmdline)

    if ver_status == "PATCHED_OR_UNAFFECTED":
        verdict = "PATCHED_OR_SAFE_VERSION"
    elif flag_status == "MITIGATED_FLAG":
        verdict = "MITIGATED_BY_FLAG"
    elif cpu_vbmi:
        verdict = "EXPOSED_ON_VBMI_HOST"
    else:
        verdict = "UNVERIFIED_ON_HOST"

    return JvmFinding(
        pid=pid,
        source=source,
        jvm_lib_path=jvm_lib_path,
        java_binary=java_bin,
        version_output=ver_output,
        parsed_version=parsed_ver,
        version_status=ver_status,
        flag_status=flag_status,
        cmdline=cmdline,
        exposure_verdict=verdict,
    )


def scan_host_and_containers(cpu_vbmi: bool) -> dict[str, Any]:
    findings: list[JvmFinding] = []
    container_pid_map: dict[int, str] = {}
    containers_summary: list[dict[str, Any]] = []

    docker_bin = shutil.which("docker")
    if docker_bin:
        try:
            ps_out = subprocess.check_output([docker_bin, "ps", "-q"], text=True, stderr=subprocess.DEVNULL)
            cids = [line.strip() for line in ps_out.splitlines() if line.strip()]
            for cid in cids:
                cname = cid
                cimage = ""
                try:
                    insp = subprocess.check_output(
                        [docker_bin, "inspect", cid], text=True, stderr=subprocess.DEVNULL
                    )
                    data = json.loads(insp)
                    if data:
                        cname = data[0].get("Name", cid).lstrip("/")
                        cimage = data[0].get("Config", {}).get("Image", "")
                except Exception:
                    pass

                cpids: list[int] = []
                try:
                    top_out = subprocess.check_output(
                        [docker_bin, "top", cid, "-eo", "pid"], text=True, stderr=subprocess.DEVNULL
                    )
                    for line in top_out.splitlines()[1:]:
                        s = line.strip()
                        if s.isdigit():
                            pid_int = int(s)
                            cpids.append(pid_int)
                            container_pid_map[pid_int] = f"container:{cname}"
                except Exception:
                    pass

                containers_summary.append(
                    {
                        "id": cid,
                        "name": cname,
                        "image": cimage,
                        "pids": cpids,
                    }
                )
        except Exception:
            pass

    proc_entries = sorted(os.listdir("/proc"), key=lambda x: int(x) if x.isdigit() else -1) if os.path.isdir("/proc") else []
    for entry in proc_entries:
        if not entry.isdigit():
            continue
        pid = int(entry)
        source = container_pid_map.get(pid, "host")
        finding = inspect_pid(pid, source, cpu_vbmi)
        if finding:
            findings.append(finding)

    return {
        "jvm_processes": [asdict(item) for item in findings],
        "containers": containers_summary,
        "notes": [] if os.path.isdir("/proc") else ["/proc not available on this platform; process discovery skipped (Linux required)"],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Audit host and containers for CVE-2026-114938.")
    parser.add_argument("--pretty", action="store_true", help="Pretty-print JSON output")
    args = parser.parse_args()

    cpu_info = detect_cpu_vbmi()
    scan_data = scan_host_and_containers(cpu_vbmi=bool(cpu_info["avx512_vbmi"]))

    report = {
        "cve": "CVE-2026-114938",
        "alias": "Java4Shell",
        "cpu": cpu_info,
        "summary": {
            "total_jvms_found": len(scan_data["jvm_processes"]),
            "exposed_on_vbmi_host": sum(
                1 for j in scan_data["jvm_processes"] if j["exposure_verdict"] == "EXPOSED_ON_VBMI_HOST"
            ),
            "missing_mitigation_flag": sum(
                1 for j in scan_data["jvm_processes"] if j["flag_status"] == "MISSING_FLAG"
            ),
        },
        **scan_data,
    }

    if args.pretty:
        print(json.dumps(report, indent=2))
    else:
        print(json.dumps(report))


if __name__ == "__main__":
    main()
