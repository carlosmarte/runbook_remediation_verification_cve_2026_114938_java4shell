#!/usr/bin/env python3
"""Triage HotSpot crash files (hs_err_pid*.log) for CVE-2026-114938 (Java4Shell). Library + CLI.

Answers "was this JVM crash plausibly Java4Shell?" from evidence in the file: signal type, problematic
frame and stack (Base64 decoder / base64 stub routine), JVM version vs. patched baselines, CPU features
(avx512_vbmi), and whether -XX:-UseBASE64Intrinsics / -XX:UseAVX=0..2 was in the JVM args.

    from j4s_hs_err import triage
    triage(open("hs_err_pid123.log").read()).verdict  -> 'LIKELY' | 'POSSIBLE' | 'UNLIKELY'

    j4s_hs_err.py hs_err_pid123.log [more files...] [--json]
    find /var/log -name 'hs_err_pid*.log' -print0 | xargs -0 j4s_hs_err.py --json > crashes.json
Exit codes: 0 = no LIKELY/POSSIBLE, 2 = at least one LIKELY or POSSIBLE.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass, field

SIGNAL_RE = re.compile(r"^#\s+(SIGSEGV|SIGBUS|EXCEPTION_ACCESS_VIOLATION|Internal Error|SIGILL|SIGFPE)\b.*$", re.M)
PROBLEM_FRAME_RE = re.compile(r"^#\s+Problematic frame:\s*\n#\s+(.*)$", re.M)
JRE_RE = re.compile(r"^#\s+JRE version:.*?\((\d+(?:\.\d+)+)(?:[+_-][\w.]+)?\)", re.M)
JRE_RE_ALT = re.compile(r"^#\s+JRE version:\s*(?:OpenJDK Runtime Environment|Java\(TM\) SE Runtime Environment)\s*(?:\S+\s+)?\(?(\d+(?:\.\d+)+)", re.M)
JVM_ARGS_RE = re.compile(r"^jvm_args:\s*(.*)$", re.M)
CPU_RE = re.compile(r"^CPU:.*$", re.M)
STACK_RE = re.compile(r"^(?:Native frames|Java frames):.*?\n(.*?)(?:\n\n|\Z)", re.S | re.M)
BASE64_FRAME_RE = re.compile(r"(StubRoutines::base64_(?:decode|encode)Block|java\.util\.Base64\$(?:Decoder|Encoder)\.(?:decode|encode)\w*|Base64\$Decoder|base64_decode)", re.I)
GC_HEAP_CORRUPTION_RE = re.compile(r"(guarantee\(|assert\(|heap corruption|invalid klass|bad oop|VerifyHeap|oop verification)", re.I)
MITIGATION_RE = re.compile(r"(?:^|\s)-XX:-UseBASE64Intrinsics(?:\s|$)|(?:^|\s)-XX:UseAVX=[0-2](?:\s|$)")
EXPLICIT_RE = re.compile(r"-XX:\+UseBASE64Intrinsics")

PATCHED = {17: (17, 0, 21, 0, 3), 21: (21, 0, 13, 1), 25: (25, 0, 5, 1), 27: (27, 0, 1, 1)}
EOL = {18, 19, 20, 22, 23, 24, 26}


def _ver_status(ver: str | None) -> str:
    if not ver:
        return "UNKNOWN"
    parts = tuple(int(p) for p in ver.split(".") if p.isdigit())
    if not parts:
        return "UNKNOWN"
    major = parts[0]
    if major <= 16:
        return "UNAFFECTED"
    if major in EOL:
        return "VULN_RANGE"
    if major in PATCHED:
        base = PATCHED[major]
        p = tuple(list(parts) + [0] * 5)[: len(base)]
        if major == 17 and p[1] == 0 and p[2] < 6:
            return "UNAFFECTED"
        return "PATCHED" if p >= base else "VULN_RANGE"
    return "VULN_RANGE"


@dataclass
class Triage:
    file: str
    signal: str | None
    problematic_frame: str | None
    jre_version: str | None
    version_status: str
    jvm_args: str | None
    mitigation_present: bool
    explicitly_enabled: bool
    cpu_avx512_vbmi: bool | None
    base64_frames: list[str] = field(default_factory=list)
    heap_corruption_markers: list[str] = field(default_factory=list)
    verdict: str = "UNLIKELY"
    score: int = 0
    reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


def triage(text: str, name: str = "<stdin>") -> Triage:
    sig = SIGNAL_RE.search(text)
    pf = PROBLEM_FRAME_RE.search(text)
    jre = JRE_RE.search(text) or JRE_RE_ALT.search(text)
    args = JVM_ARGS_RE.search(text)
    cpu = CPU_RE.search(text)
    ver = jre.group(1) if jre else None
    t = Triage(
        file=name,
        signal=sig.group(1) if sig else None,
        problematic_frame=pf.group(1).strip() if pf else None,
        jre_version=ver,
        version_status=_ver_status(ver),
        jvm_args=args.group(1).strip() if args else None,
        mitigation_present=bool(args and MITIGATION_RE.search(" " + args.group(1) + " ")),
        explicitly_enabled=bool(args and EXPLICIT_RE.search(args.group(1))),
        cpu_avx512_vbmi=("avx512_vbmi" in cpu.group(0).lower() or "avx512vbmi" in cpu.group(0).lower()) if cpu else None,
        base64_frames=sorted({m.group(1) for m in BASE64_FRAME_RE.finditer(text)}),
        heap_corruption_markers=sorted({m.group(1) for m in GC_HEAP_CORRUPTION_RE.finditer(text)}),
    )

    score = 0
    if t.base64_frames:
        score += 4; t.reasons.append(f"Base64 decoder/stub frames on stack: {', '.join(t.base64_frames)}")
    if t.problematic_frame and BASE64_FRAME_RE.search(t.problematic_frame):
        score += 3; t.reasons.append("Problematic frame is the Base64 intrinsic/decoder")
    if t.signal in ("SIGSEGV", "SIGBUS", "EXCEPTION_ACCESS_VIOLATION"):
        score += 1; t.reasons.append(f"Memory-access signal {t.signal}")
    if t.heap_corruption_markers:
        score += 2; t.reasons.append(f"Heap corruption markers: {', '.join(t.heap_corruption_markers)}")
    if t.version_status == "VULN_RANGE":
        score += 2; t.reasons.append(f"JRE {ver} is in the vulnerable range")
    elif t.version_status in ("PATCHED", "UNAFFECTED"):
        score -= 4; t.reasons.append(f"JRE {ver} is {t.version_status.lower()}: intrinsic bug not present")
    if t.cpu_avx512_vbmi is True:
        score += 1; t.reasons.append("CPU exposes avx512_vbmi (hardware in scope)")
    elif t.cpu_avx512_vbmi is False:
        score -= 3; t.reasons.append("CPU lacks avx512_vbmi: VBMI intrinsic never selected")
    if t.mitigation_present and not t.explicitly_enabled:
        score -= 4; t.reasons.append("Mitigation flag present in jvm_args: intrinsic disabled")
    if t.explicitly_enabled:
        score += 1; t.reasons.append("-XX:+UseBASE64Intrinsics explicitly set")

    t.score = score
    t.verdict = "LIKELY" if score >= 6 else "POSSIBLE" if score >= 3 else "UNLIKELY"
    return t


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("files", nargs="+", help="hs_err_pid*.log files ('-' = stdin)")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    results = []
    for f in a.files:
        text = sys.stdin.read() if f == "-" else open(f, encoding="utf-8", errors="replace").read()
        results.append(triage(text, f))
    if a.json:
        print(json.dumps([r.to_dict() for r in results], indent=2))
    else:
        for r in results:
            print(f"{r.verdict:8} score={r.score:>2} {r.file}")
            print(f"         signal={r.signal} jre={r.jre_version} ({r.version_status}) vbmi={r.cpu_avx512_vbmi} mitigated={r.mitigation_present}")
            if r.problematic_frame:
                print(f"         frame: {r.problematic_frame[:120]}")
            for why in r.reasons:
                print(f"         - {why}")
    return 2 if any(r.verdict != "UNLIKELY" for r in results) else 0


if __name__ == "__main__":
    raise SystemExit(main())
