#!/usr/bin/env python3
"""Fleet inventory for CVE-2026-114938 (Java4Shell): merge, rank, and diff host audit JSON files.

Input: one or more JSON files produced by scripts/audit_java4shell.py (one per host). The host name is
taken from the file name (audit-<host>.json -> host) unless the JSON carries a "host" key.

    j4s_inventory.py merge audits/*.json [--csv out.csv] [--json out.json]     # one row per JVM process
    j4s_inventory.py rank  audits/*.json [--top 20]                            # worst first
    j4s_inventory.py diff  before/*.json after/*.json --split                  # progress between two runs
    j4s_inventory.py summary audits/*.json                                     # counts by verdict / host

Library: from j4s_inventory import load_audits, rows_from_audits, rank_rows, diff_rows
Exit codes: 0 ok; 2 = at least one EXPOSED_ON_VBMI_HOST row remains (merge/rank/summary) or regressions (diff).
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import sys
from collections import Counter

RISK_ORDER = {"EXPOSED_ON_VBMI_HOST": 0, "UNVERIFIED_ON_HOST": 1, "MITIGATED_BY_FLAG": 2, "PATCHED_OR_SAFE_VERSION": 3, "UNKNOWN": 4}
COLUMNS = ["host", "arch", "avx512_vbmi", "pid", "source", "parsed_version", "version_status", "flag_status",
           "exposure_verdict", "java_binary", "jvm_lib_path", "cmdline"]


def host_from_filename(path: str) -> str:
    base = os.path.basename(path)
    base = re.sub(r"\.json$", "", base, flags=re.I)
    base = re.sub(r"^(audit|java4shell|j4s)[-_]*", "", base, flags=re.I)
    return base or os.path.basename(path)


def load_audits(paths: list[str]) -> list[dict]:
    out = []
    for p in paths:
        try:
            with open(p, encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, json.JSONDecodeError) as exc:
            print(f"warn: skipping {p}: {exc}", file=sys.stderr)
            continue
        data.setdefault("host", host_from_filename(p))
        data["_file"] = p
        out.append(data)
    return out


def rows_from_audits(audits: list[dict]) -> list[dict]:
    rows = []
    for a in audits:
        cpu = a.get("cpu", {})
        procs = a.get("jvm_processes", [])
        if not procs:
            rows.append({"host": a["host"], "arch": cpu.get("arch"), "avx512_vbmi": cpu.get("avx512_vbmi"), "pid": None, "source": "host",
                         "parsed_version": None, "version_status": "N/A", "flag_status": "N/A", "exposure_verdict": "NO_JVM_FOUND",
                         "java_binary": None, "jvm_lib_path": None, "cmdline": ""})
        for j in procs:
            rows.append({
                "host": a["host"], "arch": cpu.get("arch"), "avx512_vbmi": cpu.get("avx512_vbmi"), "pid": j.get("pid"),
                "source": j.get("source"), "parsed_version": j.get("parsed_version"), "version_status": j.get("version_status"),
                "flag_status": j.get("flag_status"), "exposure_verdict": j.get("exposure_verdict", "UNKNOWN"),
                "java_binary": j.get("java_binary"), "jvm_lib_path": j.get("jvm_lib_path"), "cmdline": (j.get("cmdline") or "")[:200],
            })
    return rows


def rank_rows(rows: list[dict]) -> list[dict]:
    return sorted(rows, key=lambda r: (RISK_ORDER.get(r["exposure_verdict"], 9), not r.get("avx512_vbmi"), r["host"], r.get("pid") or 0))


def workload_id(cmdline: str) -> str:
    """Stable identity for a JVM across restarts and flag changes: the -jar path, else the main class/first non-option token."""
    toks = (cmdline or "").split()
    for i, t in enumerate(toks):
        if t == "-jar" and i + 1 < len(toks):
            return f"jar:{toks[i + 1]}"
    for t in toks[1:]:
        if not t.startswith("-") and not t.startswith("@"):
            return f"main:{t}"
    return "cmd:" + " ".join(toks[:1])


def key_of(r: dict) -> tuple:
    # pid changes across restarts and flags change on remediation; identify by host + source + java binary + workload
    return (r["host"], r.get("source"), r.get("java_binary") or r.get("jvm_lib_path"), workload_id(r.get("cmdline") or ""))


def diff_rows(before: list[dict], after: list[dict]) -> dict:
    b = {key_of(r): r for r in before}
    a = {key_of(r): r for r in after}
    improved, regressed, unchanged, new, gone = [], [], [], [], []
    for k, r in a.items():
        if k not in b:
            new.append(r); continue
        rb, ra = RISK_ORDER.get(b[k]["exposure_verdict"], 9), RISK_ORDER.get(r["exposure_verdict"], 9)
        (improved if ra > rb else regressed if ra < rb else unchanged).append({**r, "before": b[k]["exposure_verdict"]})
    for k, r in b.items():
        if k not in a:
            gone.append(r)
    return {"improved": improved, "regressed": regressed, "unchanged": unchanged, "new": new, "gone": gone}


def write_csv(rows: list[dict], path: str) -> None:
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=COLUMNS, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)


def print_table(rows: list[dict], cols: list[str]) -> None:
    widths = {c: max(len(c), *(len(str(r.get(c, ""))) for r in rows)) if rows else len(c) for c in cols}
    print("  ".join(c.ljust(widths[c]) for c in cols))
    for r in rows:
        print("  ".join(str(r.get(c, "") if r.get(c) is not None else "-").ljust(widths[c]) for c in cols))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    m = sub.add_parser("merge"); m.add_argument("files", nargs="+"); m.add_argument("--csv"); m.add_argument("--json")
    r = sub.add_parser("rank"); r.add_argument("files", nargs="+"); r.add_argument("--top", type=int, default=50)
    s = sub.add_parser("summary"); s.add_argument("files", nargs="+"); s.add_argument("--json", action="store_true")
    d = sub.add_parser("diff"); d.add_argument("files", nargs="+", help="before files, then --split, then after files"); d.add_argument("--split", action="store_true", help="(marker; files after the literal '--split' are 'after')"); d.add_argument("--json", action="store_true")
    argv = list(sys.argv[1:] if argv is None else argv)

    if argv and argv[0] == "diff" and "--split" in argv:
        i = argv.index("--split")
        before_files, after_files = argv[1:i], [x for x in argv[i + 1:] if not x.startswith("--")]
        want_json = "--json" in argv
        before = rows_from_audits(load_audits(before_files))
        after = rows_from_audits(load_audits(after_files))
        res = diff_rows(before, after)
        if want_json:
            print(json.dumps(res, indent=2))
        else:
            for k in ("regressed", "improved", "new", "gone", "unchanged"):
                print(f"== {k} ({len(res[k])})")
                if res[k]:
                    print_table(res[k], ["host", "pid", "source", "parsed_version", "exposure_verdict"] + (["before"] if k in ("improved", "regressed", "unchanged") else []))
        return 2 if res["regressed"] else 0

    a = ap.parse_args(argv)
    rows = rows_from_audits(load_audits(a.files))
    exposed = sum(1 for x in rows if x["exposure_verdict"] == "EXPOSED_ON_VBMI_HOST")

    if a.cmd == "merge":
        if a.csv:
            write_csv(rows, a.csv)
        if a.json:
            with open(a.json, "w", encoding="utf-8") as fh:
                json.dump(rows, fh, indent=2)
        if not a.csv and not a.json:
            print_table(rank_rows(rows), ["host", "pid", "source", "parsed_version", "version_status", "flag_status", "exposure_verdict"])
        print(f"-- {len(rows)} row(s) from {len(a.files)} file(s); exposed={exposed}", file=sys.stderr)
    elif a.cmd == "rank":
        print_table(rank_rows(rows)[: a.top], ["host", "avx512_vbmi", "pid", "source", "parsed_version", "flag_status", "exposure_verdict", "cmdline"])
    elif a.cmd == "summary":
        by_verdict = Counter(x["exposure_verdict"] for x in rows)
        by_host = {}
        for x in rows:
            by_host.setdefault(x["host"], Counter())[x["exposure_verdict"]] += 1
        vbmi_hosts = sorted({x["host"] for x in rows if x.get("avx512_vbmi")})
        out = {"hosts": len({x['host'] for x in rows}), "jvm_rows": len(rows), "by_verdict": dict(by_verdict), "vbmi_hosts": vbmi_hosts,
               "by_host": {h: dict(c) for h, c in sorted(by_host.items())}}
        if a.json:
            print(json.dumps(out, indent=2))
        else:
            print(f"hosts={out['hosts']} jvm_rows={out['jvm_rows']} vbmi_hosts={len(vbmi_hosts)}")
            for k, v in sorted(by_verdict.items(), key=lambda kv: RISK_ORDER.get(kv[0], 9)):
                print(f"  {k:26} {v}")
            print("per host:")
            for h, c in sorted(by_host.items()):
                print(f"  {h:30} " + ", ".join(f"{k}={v}" for k, v in sorted(c.items())))
    return 2 if exposed else 0


if __name__ == "__main__":
    raise SystemExit(main())
