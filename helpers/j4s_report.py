#!/usr/bin/env python3
"""Consolidated status report for CVE-2026-114938 (Java4Shell). Library + CLI.

Merges whatever evidence you have into one Markdown (default), JSON, or HTML report:
  --audit   scripts/audit_java4shell.py JSON (repeatable; one per host)
  --jars    scripts/scan_java4shell_jars.py JSONL
  --source  scripts/scan_java4shell_source.py --json output
  --gate    saved stdout/stderr of scripts/gate_cve_2026_114938.py
  --crashes helpers/j4s_hs_err.py --json output
  --b64     helpers/j4s_b64check.py scan --json output

    j4s_report.py --audit audit-*.json --jars findings.jsonl --source src.json -o java4shell-status.md
    j4s_report.py --audit audit.json --format json | jq .summary
    j4s_report.py --audit audit.json --format html -o status.html

Library: from j4s_report import build_report, render_markdown
Exit codes: 0 = overall status GREEN/AMBER, 2 = RED (exposed JVMs or REACHABLE untrusted decode on unmitigated host).
"""

from __future__ import annotations

import argparse
import datetime as dt
import html
import json
import os
import sys
from collections import Counter

CVE = "CVE-2026-114938"
BASELINES = "17.0.21.0.3+ / 21.0.13.1+ / 25.0.5.1+ / 27.0.1.1+"


def _load_json(p: str):
    with open(p, encoding="utf-8") as fh:
        return json.load(fh)


def _load_jsonl(p: str) -> list[dict]:
    out = []
    with open(p, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                out.append(json.loads(line))
    return out


def build_report(audits: list[str], jars: str | None, source: str | None, gate: str | None, crashes: str | None, b64: str | None) -> dict:
    rep: dict = {"cve": CVE, "alias": "Java4Shell", "generated": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
                 "baselines": BASELINES, "sections": {}, "summary": {}, "actions": []}

    # Hosts / JVMs
    hosts = []
    jvms = []
    for p in audits:
        try:
            a = _load_json(p)
        except (OSError, json.JSONDecodeError) as exc:
            rep.setdefault("warnings", []).append(f"audit {p}: {exc}"); continue
        host = a.get("host") or os.path.splitext(os.path.basename(p))[0]
        cpu = a.get("cpu", {})
        hosts.append({"host": host, "arch": cpu.get("arch"), "avx512_vbmi": cpu.get("avx512_vbmi"), "jvms": len(a.get("jvm_processes", [])),
                      "exposed": sum(1 for j in a.get("jvm_processes", []) if j.get("exposure_verdict") == "EXPOSED_ON_VBMI_HOST"),
                      "containers": len(a.get("containers", [])), "notes": a.get("notes", [])})
        for j in a.get("jvm_processes", []):
            jvms.append({"host": host, **{k: j.get(k) for k in ("pid", "source", "parsed_version", "version_status", "flag_status", "exposure_verdict")},
                         "cmdline": (j.get("cmdline") or "")[:120]})
    verdicts = Counter(j["exposure_verdict"] for j in jvms)
    rep["sections"]["hosts"] = hosts
    rep["sections"]["jvms"] = sorted(jvms, key=lambda j: ({"EXPOSED_ON_VBMI_HOST": 0, "UNVERIFIED_ON_HOST": 1, "MITIGATED_BY_FLAG": 2}.get(j["exposure_verdict"], 3), j["host"]))
    rep["summary"]["hosts"] = len(hosts)
    rep["summary"]["vbmi_hosts"] = sum(1 for h in hosts if h["avx512_vbmi"])
    rep["summary"]["jvms"] = len(jvms)
    rep["summary"]["jvm_verdicts"] = dict(verdicts)

    # Artifacts
    if jars:
        recs = _load_jsonl(jars)
        by_artifact = Counter(r["artifact_path"] for r in recs)
        rep["sections"]["artifacts"] = {"total_classes": len(recs), "shaded": sum(1 for r in recs if r.get("is_shaded")),
                                        "test": sum(1 for r in recs if r.get("is_test_artifact")), "artifacts": by_artifact.most_common(),
                                        "top_classes": [{"class": r["class_name"], "artifact": r["artifact_path"], "shaded": r.get("is_shaded"), "test": r.get("is_test_artifact")} for r in recs[:50]]}
        rep["summary"]["artifact_classes"] = len(recs)

    # Source
    if source:
        s = _load_json(source)
        kinds = Counter(f["input_kind"] for f in s.get("findings", []))
        rep["sections"]["source"] = {"root": s.get("root"), "total": s.get("total"), "by_kind": dict(kinds),
                                     "untrusted": [{"file": f["file"], "line": f["line"], "call": f["call"], "sources": f["sources"], "preauth": f.get("preauth_context")}
                                                   for f in s.get("findings", []) if f["input_kind"] == "DYNAMIC_UNTRUSTED"]}
        rep["summary"]["source_untrusted"] = kinds.get("DYNAMIC_UNTRUSTED", 0)

    # Gate
    if gate:
        text = open(gate, encoding="utf-8", errors="replace").read()
        viol = [ln.strip()[2:] for ln in text.splitlines() if ln.strip().startswith("- ")]
        rep["sections"]["gate"] = {"passed": "POLICY GATE PASSED" in text, "violations": viol}
        rep["summary"]["gate_violations"] = len(viol)

    # Crashes
    if crashes:
        cr = _load_json(crashes)
        rep["sections"]["crashes"] = [{"file": c["file"], "verdict": c["verdict"], "score": c["score"], "jre": c.get("jre_version"), "frame": c.get("problematic_frame")} for c in cr]
        rep["summary"]["crashes_likely"] = sum(1 for c in cr if c["verdict"] == "LIKELY")
        rep["summary"]["crashes_possible"] = sum(1 for c in cr if c["verdict"] == "POSSIBLE")

    # Base64 probes
    if b64:
        hits = _load_json(b64)
        rep["sections"]["b64_probes"] = {"suspicious": sum(1 for h in hits if h.get("suspicious")), "sample": hits[:20]}
        rep["summary"]["b64_suspicious"] = rep["sections"]["b64_probes"]["suspicious"]

    # Status + actions
    exposed = verdicts.get("EXPOSED_ON_VBMI_HOST", 0)
    unverified = verdicts.get("UNVERIFIED_ON_HOST", 0)
    untrusted = rep["summary"].get("source_untrusted", 0)
    status = "GREEN"
    if exposed or rep["summary"].get("crashes_likely"):
        status = "RED"
    elif unverified or untrusted or rep["summary"].get("gate_violations") or rep["summary"].get("crashes_possible") or rep["summary"].get("b64_suspicious"):
        status = "AMBER"
    rep["summary"]["status"] = status

    if exposed:
        rep["actions"].append(f"Apply -XX:-UseBASE64Intrinsics to {exposed} exposed JVM(s) on VBMI hosts now (JAVA_TOOL_OPTIONS or launch args), then verify with jcmd.")
    if unverified:
        rep["actions"].append(f"{unverified} JVM(s) run vulnerable versions without the flag on non-VBMI CPUs: schedule the patch before workloads move hardware.")
    if verdicts.get("MITIGATED_BY_FLAG"):
        rep["actions"].append(f"{verdicts['MITIGATED_BY_FLAG']} JVM(s) rely on the flag: plan upgrade to {BASELINES}.")
    if untrusted:
        rep["actions"].append(f"{untrusted} source call site(s) decode untrusted Base64: add strict length/padding validation before decode.")
    if rep["summary"].get("gate_violations"):
        rep["actions"].append("Resolve CI gate violations (unpatched image tags / missing flag) before next deploy.")
    if rep["summary"].get("crashes_likely") or rep["summary"].get("crashes_possible"):
        rep["actions"].append("Treat LIKELY/POSSIBLE crash files as exploitation attempts: preserve logs, rotate secrets resident in those JVMs, review edge hits for the same window.")
    if rep["summary"].get("b64_suspicious"):
        rep["actions"].append("Suspicious malformed-Base64 tokens seen in traffic: move edge rules from count to block for the affected routes.")
    if not rep["actions"]:
        rep["actions"].append("No open actions from the supplied evidence. Keep the fleet audit on a schedule until all JDKs are patched.")
    return rep


def render_markdown(rep: dict) -> str:
    s = rep["summary"]
    out = [f"# {CVE} (Java4Shell) Status Report", "", f"**Generated:** {rep['generated']}  ", f"**Overall status:** **{s['status']}**  ", f"**Patched baselines:** {rep['baselines']}", ""]
    out += ["## Summary", "", "| Metric | Value |", "| :--- | ---: |"]
    for k in ("hosts", "vbmi_hosts", "jvms", "artifact_classes", "source_untrusted", "gate_violations", "crashes_likely", "crashes_possible", "b64_suspicious"):
        if k in s:
            out.append(f"| {k.replace('_', ' ')} | {s[k]} |")
    for k, v in sorted(s.get("jvm_verdicts", {}).items()):
        out.append(f"| JVMs {k} | {v} |")
    out += ["", "## Actions", ""] + [f"{i}. {a}" for i, a in enumerate(rep["actions"], 1)] + [""]
    sec = rep["sections"]
    if sec.get("hosts"):
        out += ["## Hosts", "", "| Host | Arch | avx512_vbmi | JVMs | Exposed | Containers |", "| :--- | :--- | :---: | ---: | ---: | ---: |"]
        out += [f"| {h['host']} | {h['arch']} | {h['avx512_vbmi']} | {h['jvms']} | {h['exposed']} | {h['containers']} |" for h in sec["hosts"]] + [""]
    if sec.get("jvms"):
        out += ["## JVM processes", "", "| Host | PID | Source | Version | Version status | Flag | Verdict |", "| :--- | ---: | :--- | :--- | :--- | :--- | :--- |"]
        out += [f"| {j['host']} | {j['pid']} | {j['source']} | {j['parsed_version'] or '-'} | {j['version_status']} | {j['flag_status']} | {j['exposure_verdict']} |" for j in sec["jvms"]] + [""]
    if sec.get("artifacts"):
        a = sec["artifacts"]
        out += ["## Built artifacts referencing java.util.Base64 decoding", "", f"Classes: {a['total_classes']} (shaded {a['shaded']}, test {a['test']})", "", "| Artifact | Classes |", "| :--- | ---: |"]
        out += [f"| {p} | {n} |" for p, n in a["artifacts"][:30]] + [""]
    if sec.get("source"):
        src = sec["source"]
        out += ["## Source call sites", "", f"Root: `{src['root']}` — total {src['total']}; " + ", ".join(f"{k} {v}" for k, v in sorted(src["by_kind"].items())), ""]
        if src["untrusted"]:
            out += ["| File | Line | Call | Sources | Pre-auth |", "| :--- | ---: | :--- | :--- | :---: |"]
            out += [f"| {u['file']} | {u['line']} | `{u['call'][:70]}` | {', '.join(u['sources'])} | {'yes' if u['preauth'] else ''} |" for u in src["untrusted"]] + [""]
    if sec.get("gate"):
        g = sec["gate"]
        out += ["## CI gate", "", f"Result: **{'PASSED' if g['passed'] else 'FAILED'}**", ""] + [f"- {v}" for v in g["violations"]] + [""]
    if sec.get("crashes"):
        out += ["## Crash file triage", "", "| File | Verdict | Score | JRE | Frame |", "| :--- | :--- | ---: | :--- | :--- |"]
        out += [f"| {c['file']} | {c['verdict']} | {c['score']} | {c['jre'] or '-'} | {(c['frame'] or '-')[:60]} |" for c in sec["crashes"]] + [""]
    if sec.get("b64_probes"):
        out += ["## Malformed Base64 in traffic", "", f"Suspicious tokens: {sec['b64_probes']['suspicious']}", ""]
    if rep.get("warnings"):
        out += ["## Warnings", ""] + [f"- {w}" for w in rep["warnings"]] + [""]
    return "\n".join(out)


def render_html(rep: dict) -> str:
    md = render_markdown(rep)
    body = []
    in_table = False
    for line in md.splitlines():
        if line.startswith("|"):
            cells = [c.strip() for c in line.strip("|").split("|")]
            if all(set(c) <= set(":- ") for c in cells):
                continue
            tag = "th" if not in_table else "td"
            if not in_table:
                body.append("<table>"); in_table = True
            body.append("<tr>" + "".join(f"<{tag}>{html.escape(c)}</{tag}>" for c in cells) + "</tr>")
            continue
        if in_table:
            body.append("</table>"); in_table = False
        if line.startswith("# "):
            body.append(f"<h1>{html.escape(line[2:])}</h1>")
        elif line.startswith("## "):
            body.append(f"<h2>{html.escape(line[3:])}</h2>")
        elif line.strip():
            body.append(f"<p>{html.escape(line).replace('**', '')}</p>")
    if in_table:
        body.append("</table>")
    color = {"RED": "#b00020", "AMBER": "#b36b00", "GREEN": "#1b7f3b"}[rep["summary"]["status"]]
    return ("<!doctype html><html><head><meta charset='utf-8'><title>Java4Shell Status</title><style>body{font-family:system-ui;margin:2rem;max-width:1100px}"
            "table{border-collapse:collapse;margin:1rem 0}td,th{border:1px solid #ccc;padding:4px 8px;font-size:14px}th{background:#f2f2f2}"
            f"h1{{border-bottom:4px solid {color}}}</style></head><body>" + "\n".join(body) + "</body></html>")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--audit", nargs="*", default=[], help="audit JSON file(s)")
    ap.add_argument("--jars"); ap.add_argument("--source"); ap.add_argument("--gate"); ap.add_argument("--crashes"); ap.add_argument("--b64")
    ap.add_argument("--format", choices=["md", "json", "html"], default="md")
    ap.add_argument("-o", "--output")
    a = ap.parse_args(argv)
    rep = build_report(a.audit, a.jars, a.source, a.gate, a.crashes, a.b64)
    text = json.dumps(rep, indent=2) if a.format == "json" else render_html(rep) if a.format == "html" else render_markdown(rep)
    if a.output:
        with open(a.output, "w", encoding="utf-8") as fh:
            fh.write(text + ("\n" if not text.endswith("\n") else ""))
        print(f"wrote {a.output} (status {rep['summary']['status']})", file=sys.stderr)
    else:
        print(text)
    return 2 if rep["summary"]["status"] == "RED" else 0


if __name__ == "__main__":
    raise SystemExit(main())
