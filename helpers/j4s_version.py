#!/usr/bin/env python3
"""JDK version classification for CVE-2026-114938 (Java4Shell). Library + CLI.

Self-contained (Python 3.10+, stdlib). Import it or call it:

    from j4s_version import classify, baseline_for, from_java_version_output
    classify("21.0.12_7")   -> Verdict(status='VULN_RANGE', baseline='21.0.13.1', ...)

    j4s_version.py classify 17.0.21.0.3 21.0.12_7 8u511b33-perf
    java -version 2>&1 | j4s_version.py parse-output
    j4s_version.py baseline 21
    j4s_version.py table

Baselines (runbook §1): 17.0.21.0.3+, 21.0.13.1+, 25.0.5.1+, 27.0.1.1+. EOL lines 18-20, 22-24, 26 have
no patch. Oracle 8u511b33-perf is vulnerable; standard 8 and 11 are not. Versions compare lexicographically
over up to five components; "_N" / "+N" / "-suffix" qualifiers are ignored.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass

CVE = "CVE-2026-114938"
PATCHED_BASELINES: dict[int, tuple[int, ...]] = {
    17: (17, 0, 21, 0, 3),
    21: (21, 0, 13, 1),
    25: (25, 0, 5, 1),
    27: (27, 0, 1, 1),
}
EOL_VULNERABLE_MAJORS = frozenset({18, 19, 20, 22, 23, 24, 26})
MIGRATION_TARGET = {18: 21, 19: 21, 20: 21, 22: 25, 23: 25, 24: 25, 26: 27}
JAVA8_PERF_RE = re.compile(r"8u511b33-perf", re.I)
VERSION_TOKEN_RE = re.compile(r"(?<![\d.])(\d+(?:\.\d+){1,4})(?:_\d+)?(?![\d.])")
LEGACY_1X_RE = re.compile(r"\b1\.(\d)\.0(?:_(\d+))?\b")  # 1.8.0_392 style


@dataclass
class Verdict:
    input: str
    normalized: str | None
    major: int | None
    status: str  # VULN_RANGE | PATCHED_OR_UNAFFECTED | UNKNOWN
    reason: str
    baseline: str | None
    action: str

    def to_dict(self) -> dict:
        return asdict(self)


def parse_version(ver: str) -> tuple[int, ...] | None:
    """'17.0.21.0.3' -> (17,0,21,0,3); '21.0.12_7' -> (21,0,12); '1.8.0_392' -> (8,0,392); '8u511' -> (8,0,511)."""
    v = ver.strip().strip('"')
    m = LEGACY_1X_RE.search(v)
    if m:
        return (int(m.group(1)), 0, int(m.group(2) or 0))
    m8 = re.fullmatch(r"8u(\d+)[a-z0-9-]*", v, re.I)
    if m8:
        return (8, 0, int(m8.group(1)))
    core = re.split(r"[_+\-]", v, 1)[0]
    parts = core.split(".")
    if not parts or not all(p.isdigit() for p in parts):
        return None
    return tuple(int(p) for p in parts[:5])


def _pad(t: tuple[int, ...], n: int) -> tuple[int, ...]:
    return tuple(list(t) + [0] * (n - len(t)))[:n]


def fmt(t: tuple[int, ...]) -> str:
    return ".".join(map(str, t))


def baseline_for(major: int) -> str | None:
    b = PATCHED_BASELINES.get(major)
    return fmt(b) if b else None


def classify(ver: str) -> Verdict:
    if JAVA8_PERF_RE.search(ver):
        return Verdict(ver, "8u511b33-perf", 8, "VULN_RANGE", "Oracle Java SE 8u511b33-perf build is affected",
                       None, "Replace with a standard (non-perf) JDK 8 build or move to a patched LTS")
    parsed = parse_version(ver)
    if not parsed:
        return Verdict(ver, None, None, "UNKNOWN", "Could not parse a numeric version", None, "Resolve the exact JDK version (java -version, $JAVA_HOME/release)")
    major = parsed[0]
    norm = fmt(parsed)
    if major <= 16:
        return Verdict(ver, norm, major, "PATCHED_OR_UNAFFECTED", f"JDK {major} (non-perf) does not contain the affected VBMI intrinsic", None, "None required for this CVE")
    if major in EOL_VULNERABLE_MAJORS:
        tgt = MIGRATION_TARGET[major]
        return Verdict(ver, norm, major, "VULN_RANGE", f"JDK {major} is an EOL feature line with no patch", baseline_for(tgt),
                       f"Apply -XX:-UseBASE64Intrinsics now; migrate to JDK {tgt} ({baseline_for(tgt)}+)")
    if major == 17:
        p5 = _pad(parsed, 5)
        if p5[1] == 0 and p5[2] < 6:
            return Verdict(ver, norm, 17, "PATCHED_OR_UNAFFECTED", "17.0.x before 17.0.6 predates the affected intrinsic", baseline_for(17), "Upgrade anyway for other fixes; not required for this CVE")
        if p5 >= PATCHED_BASELINES[17]:
            return Verdict(ver, norm, 17, "PATCHED_OR_UNAFFECTED", "Meets or exceeds 17.0.21.0.3 baseline", baseline_for(17), "None required; the flag may be removed")
        return Verdict(ver, norm, 17, "VULN_RANGE", "In 17.0.6 .. 17.0.21.0.2 vulnerable range", baseline_for(17), "Apply -XX:-UseBASE64Intrinsics; upgrade to 17.0.21.0.3+ (or vendor equivalent)")
    if major in PATCHED_BASELINES:
        base = PATCHED_BASELINES[major]
        if _pad(parsed, len(base)) >= base:
            return Verdict(ver, norm, major, "PATCHED_OR_UNAFFECTED", f"Meets or exceeds {fmt(base)} baseline", fmt(base), "None required; the flag may be removed")
        return Verdict(ver, norm, major, "VULN_RANGE", f"Below {fmt(base)} baseline", fmt(base), f"Apply -XX:-UseBASE64Intrinsics; upgrade to {fmt(base)}+")
    return Verdict(ver, norm, major, "VULN_RANGE", f"JDK {major} is newer than the runbook's table; verify vendor advisory", None, "Apply -XX:-UseBASE64Intrinsics until the vendor confirms a fix")


def from_java_version_output(text: str) -> Verdict:
    """Classify from `java -version` stderr. Prefers the quoted token, handles 1.8.0_x and 8u-perf builds."""
    if JAVA8_PERF_RE.search(text):
        return classify("8u511b33-perf")
    m = re.search(r'version\s+"([^"]+)"', text) or re.search(r'"([^"]+)"', text)
    if m:
        return classify(m.group(1))
    m2 = VERSION_TOKEN_RE.search(text)
    return classify(m2.group(1)) if m2 else classify(text.strip())


def table() -> list[dict]:
    rows = []
    for major in sorted(set(PATCHED_BASELINES) | EOL_VULNERABLE_MAJORS | {8, 11, 17}):
        if major in PATCHED_BASELINES:
            rows.append({"major": major, "status": "patchable", "baseline": baseline_for(major), "note": "17 line vulnerable only from 17.0.6" if major == 17 else ""})
        elif major in EOL_VULNERABLE_MAJORS:
            rows.append({"major": major, "status": "EOL - migrate", "baseline": f"-> {MIGRATION_TARGET[major]}", "note": "no patch"})
        else:
            rows.append({"major": major, "status": "unaffected", "baseline": "", "note": "except Oracle 8u511b33-perf" if major == 8 else ""})
    return rows


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("classify", help="Classify one or more version strings"); c.add_argument("versions", nargs="+"); c.add_argument("--json", action="store_true")
    po = sub.add_parser("parse-output", help="Classify `java -version` output from stdin or a file"); po.add_argument("file", nargs="?"); po.add_argument("--json", action="store_true")
    b = sub.add_parser("baseline", help="Print the patched baseline for a major version"); b.add_argument("major", type=int)
    t = sub.add_parser("table", help="Print the baseline table"); t.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)

    if a.cmd == "classify":
        vs = [classify(v) for v in a.versions]
        if a.json:
            print(json.dumps([v.to_dict() for v in vs], indent=2))
        else:
            for v in vs:
                print(f"{v.input:20} {v.status:22} {v.reason}" + (f" [baseline {v.baseline}]" if v.baseline else ""))
        return 2 if any(v.status == "VULN_RANGE" for v in vs) else 0
    if a.cmd == "parse-output":
        text = open(a.file, encoding="utf-8", errors="replace").read() if a.file else sys.stdin.read()
        v = from_java_version_output(text)
        print(json.dumps(v.to_dict(), indent=2) if a.json else f"{v.normalized or v.input} {v.status} - {v.reason}. {v.action}")
        return 2 if v.status == "VULN_RANGE" else 0
    if a.cmd == "baseline":
        bl = baseline_for(a.major)
        if bl:
            print(bl); return 0
        if a.major in EOL_VULNERABLE_MAJORS:
            print(f"EOL: migrate to {MIGRATION_TARGET[a.major]} ({baseline_for(MIGRATION_TARGET[a.major])})"); return 2
        print("unaffected" if a.major <= 16 else "unknown"); return 0
    if a.cmd == "table":
        rows = table()
        if a.json:
            print(json.dumps(rows, indent=2))
        else:
            print(f"{'major':>5}  {'status':14} {'baseline':12} note")
            for r in rows:
                print(f"{r['major']:>5}  {r['status']:14} {r['baseline']:12} {r['note']}")
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
