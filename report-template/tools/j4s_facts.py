#!/usr/bin/env python3
"""j4s_facts.py - turn CVE-2026-114938 (Java4Shell) scanner evidence into one facts.json for the report templates.

Every input is optional; the facts file records which sections are available so templates can hide the rest.

    j4s_facts.py \
      --audit audits/*.json                 # scripts/audit_java4shell.py --pretty           (one per host)
      --audit-before audits-before/*.json   # earlier run of the same, for the trend section
      --gh-scan acme.json                   # github/gh_j4s_scan.py --format json
      --actions posture.tsv                 # github/gh_j4s_actions.sh --format tsv
      --source src.json                     # scripts/scan_java4shell_source.py --json
      --jars findings.jsonl                 # scripts/scan_java4shell_jars.py --jsonl
      --gate gate.log                       # saved stdout+stderr of scripts/gate_cve_2026_114938.py
      --crashes crashes.json                # helpers/j4s_hs_err.py --json
      --b64 traffic.json                    # helpers/j4s_b64check.py scan --json
      --meta org="Acme Corp" --meta owner="Platform Security" --meta scope="Payments BU"
      --extra narrative.json                # free-form organisation data merged under "extra" (business units, decisions, exceptions)
      --sla-mitigate-days 2 --sla-patch-days 30
      -o facts.json

Derived insights (see ../DATA-DICTIONARY.md): exposure_rate, mitigation_coverage, patch_coverage, gate_adoption,
floating-pin rate, pre-auth decode sites, RAG status, SLA due dates and days since disclosure.
Python 3.9+, standard library only.
"""

from __future__ import annotations

import argparse
import csv
import glob
import json
import os
import re
import sys
from collections import Counter
from datetime import date, datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

CVE = "CVE-2026-114938"
ALIAS = "Java4Shell"
UPSTREAM = "JDK-8393212"
DISCLOSURE = date(2026, 11, 17)
BASELINES = "17.0.21.0.3+ / 21.0.13.1+ / 25.0.5.1+ / 27.0.1.1+"
RISK_ORDER = ["EXPOSED_ON_VBMI_HOST", "UNVERIFIED_ON_HOST", "MITIGATED_BY_FLAG", "PATCHED_OR_SAFE_VERSION"]
REPO_ORDER = ["EXPOSED", "EXPLICITLY_ENABLED", "MITIGATED_FLAG", "UNVERIFIED_FLOATING", "UNVERIFIED_NO_PIN", "PATCHED", "NOT_JAVA", "ERROR"]


def _load(path: str) -> Any:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def _expand(paths: List[str]) -> List[str]:
    out: List[str] = []
    for p in paths:
        hits = sorted(glob.glob(p))
        out.extend(hits if hits else [p])
    return out


def ratio(a: int, b: int) -> float:
    return round(a / b, 4) if b else 0.0


# ---------------------------------------------------------------- fleet (audit_java4shell.py)
def fleet_facts(paths: List[str]) -> Dict[str, Any]:
    hosts: List[Dict[str, Any]] = []
    jvms: List[Dict[str, Any]] = []
    for p in _expand(paths):
        try:
            d = _load(p)
        except (OSError, ValueError) as e:
            sys.stderr.write(f"[facts] skip {p}: {e}\n")
            continue
        host = d.get("host") or os.path.basename(p).replace("audit-", "").replace(".json", "")
        cpu = d.get("cpu", {})
        procs = d.get("jvm_processes", [])
        c = Counter(j.get("exposure_verdict", "UNKNOWN") for j in procs)
        hosts.append({
            "host": host, "arch": cpu.get("arch", "?"), "vbmi": bool(cpu.get("avx512_vbmi")), "jvms": len(procs),
            "exposed": c["EXPOSED_ON_VBMI_HOST"], "unverified": c["UNVERIFIED_ON_HOST"], "mitigated": c["MITIGATED_BY_FLAG"],
            "patched": c["PATCHED_OR_SAFE_VERSION"], "containers": len(d.get("containers", [])),
            "status": "RED" if c["EXPOSED_ON_VBMI_HOST"] else "AMBER" if (c["UNVERIFIED_ON_HOST"] or c["MITIGATED_BY_FLAG"]) else "GREEN" if procs else "NONE",
        })
        for j in procs:
            jvms.append({"host": host, "pid": j.get("pid"), "source": j.get("source", "host"), "version": j.get("parsed_version") or "-",
                         "version_status": j.get("version_status", "UNKNOWN"), "flag_status": j.get("flag_status", "?"),
                         "verdict": j.get("exposure_verdict", "UNKNOWN"), "cmd": (j.get("cmdline") or "")[:90], "vbmi": bool(cpu.get("avx512_vbmi"))})
    by = Counter(j["verdict"] for j in jvms)
    n = len(jvms)
    jvms.sort(key=lambda j: (RISK_ORDER.index(j["verdict"]) if j["verdict"] in RISK_ORDER else 9, j["host"], j["pid"] or 0))
    return {
        "available": bool(hosts), "hosts": len(hosts), "hosts_vbmi": sum(1 for h in hosts if h["vbmi"]), "jvms": n,
        "jvms_vbmi": sum(1 for j in jvms if j["vbmi"]), "exposed_vbmi": by["EXPOSED_ON_VBMI_HOST"], "unverified": by["UNVERIFIED_ON_HOST"],
        "mitigated_flag": by["MITIGATED_BY_FLAG"], "patched": by["PATCHED_OR_SAFE_VERSION"],
        "unknown": n - sum(by[k] for k in RISK_ORDER), "missing_flag": sum(1 for j in jvms if j["flag_status"] == "MISSING_FLAG"),
        "vulnerable_versions": sum(1 for j in jvms if j["version_status"] == "VULN_RANGE"),
        "exposure_rate": ratio(by["EXPOSED_ON_VBMI_HOST"], n), "mitigation_coverage": ratio(by["MITIGATED_BY_FLAG"] + by["PATCHED_OR_SAFE_VERSION"], n),
        "patch_coverage": ratio(by["PATCHED_OR_SAFE_VERSION"], n), "vbmi_host_share": ratio(sum(1 for h in hosts if h["vbmi"]), len(hosts)),
        "hosts_red": sum(1 for h in hosts if h["status"] == "RED"), "by_verdict": dict(by),
        "hosts_rows": sorted(hosts, key=lambda h: ({"RED": 0, "AMBER": 1, "GREEN": 2, "NONE": 3}[h["status"]], h["host"])),
        "jvms_rows": jvms, "exposed_rows": [j for j in jvms if j["verdict"] == "EXPOSED_ON_VBMI_HOST"],
        "unverified_rows": [j for j in jvms if j["verdict"] == "UNVERIFIED_ON_HOST"],
    }


def trend_facts(before_paths: List[str], after_paths: List[str]) -> Dict[str, Any]:
    def rows(paths: List[str]) -> Dict[Any, Dict[str, Any]]:
        f = fleet_facts(paths)
        return {(j["host"], j["cmd"][:60]): j for j in f["jvms_rows"]}
    if not before_paths or not after_paths:
        return {"available": False}
    b, a = rows(before_paths), rows(after_paths)
    improved, regressed, unchanged, new, gone = [], [], [], [], []
    for k, r in a.items():
        if k not in b:
            new.append(r)
            continue
        rb = RISK_ORDER.index(b[k]["verdict"]) if b[k]["verdict"] in RISK_ORDER else 9
        ra = RISK_ORDER.index(r["verdict"]) if r["verdict"] in RISK_ORDER else 9
        row = dict(r, before=b[k]["verdict"])
        (improved if ra > rb else regressed if ra < rb else unchanged).append(row)
    for k, r in b.items():
        if k not in a:
            gone.append(r)
    fb, fa = fleet_facts(before_paths), fleet_facts(after_paths)
    return {"available": True, "improved": len(improved), "regressed": len(regressed), "unchanged": len(unchanged), "new": len(new), "gone": len(gone),
            "improved_rows": improved, "regressed_rows": regressed, "new_rows": new,
            "exposed_before": fb["exposed_vbmi"], "exposed_after": fa["exposed_vbmi"],
            "mitigation_before": fb["mitigation_coverage"], "mitigation_after": fa["mitigation_coverage"],
            "patch_before": fb["patch_coverage"], "patch_after": fa["patch_coverage"]}


# ---------------------------------------------------------------- repositories (gh_j4s_scan.py)
def repo_facts(path: Optional[str]) -> Dict[str, Any]:
    if not path:
        return {"available": False}
    d = _load(path)
    repos = d.get("repos", [])
    by = Counter(r.get("verdict", "ERROR") for r in repos)
    rows = []
    for r in repos:
        rt = [v for v in r.get("versions", []) if v.get("scope") == "runtime" and v.get("kind") in ("EXACT", "FLOATING")]
        pins = ", ".join(dict.fromkeys(f"{v.get('normalized') or v.get('raw')} ({v['status']})" for v in rt)) or "-"
        flags = sorted({f["state"] for f in r.get("flags", []) if f.get("scope") == "runtime" and f.get("state") != "MENTION"})
        gate = bool(r.get("gate_ci", {}).get("github_workflows") or r.get("gate_ci", {}).get("gitlab_ci"))
        hits = r.get("source_hits", [])
        rows.append({"repo": r["repo"], "url": r.get("html_url", ""), "verdict": r.get("verdict"), "pins": pins, "flag": ",".join(flags) or "MISSING",
                     "gate": gate, "hits": len(hits), "preauth": sum(1 for h in hits if h.get("pre_auth_context")),
                     "reason": (r.get("reasons") or [""])[0][:160], "actions": r.get("actions", []), "language": r.get("primary_language") or "-",
                     "pushed_at": (r.get("pushed_at") or "")[:10], "archived": r.get("archived", False), "is_java": r.get("is_java", False)})
    rows.sort(key=lambda x: (REPO_ORDER.index(x["verdict"]) if x["verdict"] in REPO_ORDER else 9, x["repo"]))
    java = [x for x in rows if x["is_java"]]
    with_gate = sum(1 for x in java if x["gate"])
    return {
        "available": True, "scope": d.get("scope", ""), "generated_at": d.get("generated_at", "")[:19], "total": len(rows), "java": len(java),
        "by_verdict": {k: by[k] for k in REPO_ORDER if by[k]},
        "exposed": by["EXPOSED"], "explicitly_enabled": by["EXPLICITLY_ENABLED"], "mitigated_flag": by["MITIGATED_FLAG"],
        "unverified_floating": by["UNVERIFIED_FLOATING"], "unverified_no_pin": by["UNVERIFIED_NO_PIN"], "patched": by["PATCHED"],
        "not_java": by["NOT_JAVA"], "error": by["ERROR"], "blocking": by["EXPOSED"] + by["EXPLICITLY_ENABLED"],
        "with_gate": with_gate, "gate_adoption": ratio(with_gate, len(java)), "exposed_share": ratio(by["EXPOSED"] + by["EXPLICITLY_ENABLED"], len(java)),
        "floating_share": ratio(by["UNVERIFIED_FLOATING"], len(java)), "unverified_share": ratio(by["UNVERIFIED_FLOATING"] + by["UNVERIFIED_NO_PIN"], len(java)),
        "rows": [x for x in rows if x["verdict"] != "NOT_JAVA"], "exposed_rows": [x for x in rows if x["verdict"] in ("EXPOSED", "EXPLICITLY_ENABLED")],
        "unverified_rows": [x for x in rows if x["verdict"].startswith("UNVERIFIED")], "mitigated_rows": [x for x in rows if x["verdict"] == "MITIGATED_FLAG"],
        "without_gate": [x["repo"] for x in java if not x["gate"]],
        "source_hits": sum(x["hits"] for x in rows), "preauth_hits": sum(x["preauth"] for x in rows),
        "repos_with_preauth": [x["repo"] for x in rows if x["preauth"]],
    }


# ---------------------------------------------------------------- posture (gh_j4s_actions.sh --format tsv)
def posture_facts(path: Optional[str]) -> Dict[str, Any]:
    if not path:
        return {"available": False}
    with open(path, encoding="utf-8") as fh:
        rows = [{k.lower(): v for k, v in r.items()} for r in csv.DictReader(fh, delimiter="\t")]
    def num(v: str) -> int:
        return int(v) if v.isdigit() else 0
    return {
        "available": True, "repos": len(rows),
        "with_gate": sum(1 for r in rows if r.get("gate_workflow", "none") != "none"),
        "gate_required": sum(1 for r in rows if r.get("gate_required") == "yes"),
        "gate_passing": sum(1 for r in rows if r.get("gate_last_run", "").startswith("success")),
        "gate_failing": sum(1 for r in rows if r.get("gate_last_run", "").startswith("failure")),
        "var_active": sum(1 for r in rows if r.get("var_flag", "").startswith(("ACTIVE", "CAPPED"))),
        "var_reenabled": sum(1 for r in rows if r.get("var_flag", "").startswith("EXPLICITLY_ENABLED")),
        "cs_alerts": sum(num(r.get("code_scanning", "0")) for r in rows), "dependabot": sum(num(r.get("dependabot", "0")) for r in rows),
        "rows": rows, "without_gate": [r["repo"] for r in rows if r.get("gate_workflow", "none") == "none"],
    }


# ---------------------------------------------------------------- source (scan_java4shell_source.py --json)
def source_facts(path: Optional[str]) -> Dict[str, Any]:
    if not path:
        return {"available": False}
    d = _load(path)
    f = d.get("findings", [])
    kinds = Counter(x.get("input_kind", "UNKNOWN") for x in f)
    prod = [x for x in f if not x.get("is_test")]
    rows = sorted(f, key=lambda x: ({"DYNAMIC_UNTRUSTED": 0, "DYNAMIC_INTERNAL": 1, "UNKNOWN": 2, "CONSTANT": 3}.get(x.get("input_kind"), 4),
                                    0 if x.get("preauth_context") else 1, x.get("file", ""), x.get("line", 0)))
    return {"available": True, "root": d.get("root", ""), "total": len(f), "untrusted": kinds["DYNAMIC_UNTRUSTED"], "internal": kinds["DYNAMIC_INTERNAL"],
            "constant": kinds["CONSTANT"], "unknown": kinds["UNKNOWN"], "preauth": sum(1 for x in f if x.get("preauth_context")),
            "test": len(f) - len(prod), "prod": len(prod), "files": len({x.get("file") for x in f}),
            "untrusted_prod": sum(1 for x in prod if x.get("input_kind") == "DYNAMIC_UNTRUSTED"),
            "rows": rows, "untrusted_rows": [x for x in rows if x.get("input_kind") == "DYNAMIC_UNTRUSTED"],
            "review_rows": [x for x in rows if x.get("input_kind") != "DYNAMIC_UNTRUSTED" and not x.get("is_test")],
            "test_rows": [x for x in rows if x.get("is_test")],
            "preauth_rows": [x for x in rows if x.get("preauth_context")]}


# ---------------------------------------------------------------- jars (scan_java4shell_jars.py JSONL)
def jar_facts(path: Optional[str]) -> Dict[str, Any]:
    if not path:
        return {"available": False}
    recs = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                recs.append(json.loads(line))
    arts = Counter(r.get("artifact_path") for r in recs)
    prod = [r for r in recs if not r.get("is_test_artifact")]
    rows = sorted(recs, key=lambda r: (1 if r.get("is_test_artifact") else 0, 0 if r.get("is_shaded") else 1, r.get("artifact_path", ""), r.get("class_name", "")))
    return {"available": True, "classes": len(recs), "artifacts": len(arts), "shaded": sum(1 for r in recs if r.get("is_shaded")),
            "test": len(recs) - len(prod), "prod": len(prod), "rows": rows,
            "artifact_rows": [{"artifact": a, "classes": n, "shaded": sum(1 for r in recs if r.get("artifact_path") == a and r.get("is_shaded")),
                               "test": any(r.get("is_test_artifact") for r in recs if r.get("artifact_path") == a)} for a, n in arts.most_common()]}


# ---------------------------------------------------------------- gate (gate_cve_2026_114938.py log)
def gate_facts(path: Optional[str]) -> Dict[str, Any]:
    if not path:
        return {"available": False}
    with open(path, encoding="utf-8", errors="replace") as fh:
        text = fh.read()
    passed = "POLICY GATE PASSED" in text
    viol = [ln.strip()[2:].strip() for ln in text.splitlines() if ln.strip().startswith("- ")]
    kinds = Counter((re.match(r"\[(\w+)", v) or re.match(r"(\w+)", v)).group(1) if re.match(r"\[?(\w+)", v) else "other" for v in viol)
    return {"available": True, "status": "PASSED" if passed else "FAILED", "passed": passed, "failed": not passed, "count": len(viol),
            "by_kind": dict(kinds), "violations": viol,
            "version_violations": [v for v in viol if "JDK" in v or "Java SE" in v or "version" in v.lower()],
            "flag_violations": [v for v in viol if "Missing" in v or "re-enable" in v.lower()],
            "reachability_violations": [v for v in viol if v.startswith("[Reachability")]}


# ---------------------------------------------------------------- crashes (j4s_hs_err.py --json)
def crash_facts(path: Optional[str]) -> Dict[str, Any]:
    if not path:
        return {"available": False}
    d = _load(path)
    rows = d if isinstance(d, list) else d.get("results", d.get("files", []))
    by = Counter(r.get("verdict", "UNLIKELY") for r in rows)
    rows = sorted(rows, key=lambda r: ({"LIKELY": 0, "POSSIBLE": 1}.get(r.get("verdict"), 2), -int(r.get("score", 0))))
    return {"available": True, "files": len(rows), "likely": by["LIKELY"], "possible": by["POSSIBLE"], "unlikely": by["UNLIKELY"], "rows": rows,
            "flagged_rows": [r for r in rows if r.get("verdict") in ("LIKELY", "POSSIBLE")],
            "hosts_unmitigated": sum(1 for r in rows if r.get("verdict") in ("LIKELY", "POSSIBLE") and not r.get("mitigation_present"))}


# ---------------------------------------------------------------- traffic (j4s_b64check.py scan --json)
def traffic_facts(path: Optional[str]) -> Dict[str, Any]:
    if not path:
        return {"available": False}
    d = _load(path)
    items = d if isinstance(d, list) else d.get("results", d.get("tokens", d.get("hits", [])))
    norm = []
    for it in items:
        a = it.get("analysis", it) if isinstance(it, dict) else {}
        norm.append({"line": it.get("line", a.get("line", "")), "token": (a.get("token") or "")[:40] + ("…" if len(a.get("token") or "") > 40 else ""),
                     "length": a.get("length"), "pad_count": a.get("pad_count"), "edge_rules": ", ".join(a.get("edge_rules_hit", [])),
                     "anomalies": ", ".join(a.get("anomalies", [])), "suspicious": bool(a.get("suspicious")), "jwt": bool(a.get("looks_like_jwt"))})
    rules = Counter(r for it in norm for r in it["edge_rules"].split(", ") if r)
    return {"available": True, "tokens": len(norm), "suspicious": sum(1 for x in norm if x["suspicious"]), "jwt_like": sum(1 for x in norm if x["jwt"]),
            "edge_rule_counts": dict(rules), "rows": [x for x in norm if x["suspicious"]][:200],
            "edge01": rules.get("J4S-EDGE-01", 0), "edge02": rules.get("J4S-EDGE-02", 0), "edge03": rules.get("J4S-EDGE-03", 0)}


# ---------------------------------------------------------------- status, actions, meta
def rag(f: Dict[str, Any]) -> Dict[str, Any]:
    reasons: List[str] = []
    red = amber = False
    fl, rp, src, gt, cr, tr, po = f["fleet"], f["repos"], f["source"], f["gate"], f["crashes"], f["traffic"], f["posture"]
    if fl.get("exposed_vbmi"):
        red = True; reasons.append(f"{fl['exposed_vbmi']} JVM(s) exposed on AVX-512 VBMI hosts without patch or flag")
    if rp.get("blocking"):
        red = True; reasons.append(f"{rp['blocking']} repositor(ies) deploy a vulnerable JDK without the mitigation flag or re-enable the intrinsic")
    if cr.get("likely"):
        red = True; reasons.append(f"{cr['likely']} crash file(s) triaged LIKELY Java4Shell")
    if po.get("var_reenabled"):
        red = True; reasons.append(f"{po['var_reenabled']} repositor(ies) re-enable the intrinsic through Actions variables")
    if fl.get("unverified") or fl.get("mitigated_flag"):
        amber = True; reasons.append(f"{fl.get('unverified', 0)} unverified and {fl.get('mitigated_flag', 0)} flag-mitigated JVM(s) still on vulnerable versions")
    if rp.get("unverified_floating") or rp.get("unverified_no_pin") or rp.get("mitigated_flag"):
        amber = True; reasons.append(f"{rp.get('unverified_floating', 0) + rp.get('unverified_no_pin', 0)} repositor(ies) unverified, {rp.get('mitigated_flag', 0)} mitigated by flag only")
    if src.get("untrusted_prod"):
        amber = True; reasons.append(f"{src['untrusted_prod']} production call site(s) decode untrusted Base64")
    if gt.get("failed"):
        amber = True; reasons.append(f"CI gate failing with {gt.get('count', 0)} violation(s)")
    if cr.get("possible"):
        amber = True; reasons.append(f"{cr['possible']} crash file(s) triaged POSSIBLE")
    if tr.get("suspicious"):
        amber = True; reasons.append(f"{tr['suspicious']} suspicious malformed-Base64 token(s) in traffic")
    status = "RED" if red else "AMBER" if amber else "GREEN"
    if status == "GREEN" and not reasons:
        reasons.append("No exposed runtime, no vulnerable pin without mitigation, no untrusted decode on unmitigated hosts in the supplied evidence")
    return {"rag": status, "red": status == "RED", "amber": status == "AMBER", "green": status == "GREEN", "reasons": reasons}


def consolidated_actions(f: Dict[str, Any]) -> List[str]:
    a: List[str] = []
    fl, rp, src, gt, cr, tr, po = f["fleet"], f["repos"], f["source"], f["gate"], f["crashes"], f["traffic"], f["posture"]
    if fl.get("exposed_vbmi"):
        a.append(f"Apply -XX:-UseBASE64Intrinsics to {fl['exposed_vbmi']} exposed JVM(s) on VBMI hosts now (JAVA_TOOL_OPTIONS or launch args) and confirm with jcmd VM.flags.")
    if rp.get("exposed"):
        a.append(f"Set JAVA_TOOL_OPTIONS=-XX:-UseBASE64Intrinsics in the runtime definition of {rp['exposed']} repositor(ies) and open upgrade PRs to {BASELINES}.")
    if rp.get("explicitly_enabled") or po.get("var_reenabled"):
        a.append("Remove every -XX:+UseBASE64Intrinsics (J4S-FLAG-04) from manifests, start scripts and Actions variables.")
    if fl.get("unverified"):
        a.append(f"Patch {fl['unverified']} JVM(s) on vulnerable versions that sit on non-VBMI CPUs before workloads move to Ice Lake / Zen 4 class hardware.")
    if fl.get("mitigated_flag") or rp.get("mitigated_flag"):
        a.append(f"Schedule JDK upgrades for the {fl.get('mitigated_flag', 0)} JVM(s) and {rp.get('mitigated_flag', 0)} repositor(ies) that rely on the flag; keep the flag until java -version shows the baseline.")
    if rp.get("unverified_floating"):
        a.append(f"Resolve {rp['unverified_floating']} floating image/package pin(s) to exact versions (docker run IMAGE java -version) and pin digests.")
    if rp.get("unverified_no_pin"):
        a.append(f"Locate the runtime for {rp['unverified_no_pin']} Java repositor(ies) without a pin (platform image, host JDK, Helm values repo) and audit it with verify_java4shell_runtime.sh.")
    if src.get("untrusted_prod"):
        a.append(f"Add strict Base64 validation (length multiple of 4, no mid-string '=', at most two pads) before the {src['untrusted_prod']} untrusted decode call site(s).")
    if rp.get("without_gate") or po.get("without_gate"):
        n = len(rp.get("without_gate") or po.get("without_gate") or [])
        a.append(f"Add gate_cve_2026_114938.py to the pipelines of {n} Java repositor(ies) and make the check required on the default branch.")
    if gt.get("failed"):
        a.append(f"Resolve {gt.get('count', 0)} CI gate violation(s) before the next release.")
    if cr.get("likely") or cr.get("possible"):
        a.append("Treat LIKELY/POSSIBLE crash files as exploitation attempts: preserve hs_err and heap dumps, rotate secrets resident in those JVMs, correlate with edge hits.")
    if tr.get("suspicious"):
        a.append("Move edge rules J4S-EDGE-01/02 from count to block for routes that received suspicious tokens; keep EDGE-03 in count mode until false positives are tuned.")
    if not a:
        a.append("No open actions from the supplied evidence; keep the fleet audit and repository scan on a schedule until every JDK is at the baseline, then remove the flag.")
    return a


def meta_facts(meta: Dict[str, str], sla_m: int, sla_p: int) -> Dict[str, Any]:
    today = date.fromisoformat(meta["report_date"]) if meta.get("report_date") else date.today()
    m = {
        "org": "Organisation", "scope": "all Java workloads", "report_id": f"J4S-{today.strftime('%Y%m%d')}", "report_date": today.isoformat(),
        "period": f"{(today - timedelta(days=7)).isoformat()} to {today.isoformat()}", "prepared_by": "Security Engineering", "owner": "CISO",
        "distribution": "Internal", "classification": "Internal / Confidential", "next_review": (today + timedelta(days=7)).isoformat(),
        "cve": CVE, "alias": ALIAS, "upstream_id": UPSTREAM, "cwe": "CWE-122 / CWE-787", "cvss31": "8.1 High", "cvss40": "9.2 Critical",
        "disclosure_date": DISCLOSURE.isoformat(), "days_since_disclosure": (today - DISCLOSURE).days, "baselines": BASELINES,
        "mitigation_flag": "-XX:-UseBASE64Intrinsics", "sla_mitigate_days": sla_m, "sla_patch_days": sla_p,
        "sla_mitigate_due": (DISCLOSURE + timedelta(days=sla_m)).isoformat(), "sla_patch_due": (DISCLOSURE + timedelta(days=sla_p)).isoformat(),
        "sla_mitigate_breached": today > DISCLOSURE + timedelta(days=sla_m), "sla_patch_breached": today > DISCLOSURE + timedelta(days=sla_p),
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
    }
    m.update({k: v for k, v in meta.items() if v != ""})
    return m


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--audit", nargs="*", default=[], metavar="JSON")
    ap.add_argument("--audit-before", nargs="*", default=[], metavar="JSON")
    ap.add_argument("--gh-scan", metavar="JSON")
    ap.add_argument("--actions", metavar="TSV")
    ap.add_argument("--source", metavar="JSON")
    ap.add_argument("--jars", metavar="JSONL")
    ap.add_argument("--gate", metavar="LOG")
    ap.add_argument("--crashes", metavar="JSON")
    ap.add_argument("--b64", metavar="JSON")
    ap.add_argument("--meta", action="append", default=[], metavar="KEY=VALUE", help="org, scope, report_date, period, prepared_by, owner, distribution, next_review, ...")
    ap.add_argument("--extra", metavar="JSON", help="free-form JSON merged under 'extra' (business units, decisions, exceptions, service details)")
    ap.add_argument("--sla-mitigate-days", type=int, default=2)
    ap.add_argument("--sla-patch-days", type=int, default=30)
    ap.add_argument("-o", "--out")
    a = ap.parse_args(argv)

    meta = {}
    for kv in a.meta:
        k, _, v = kv.partition("=")
        meta[k.strip()] = v.strip()
    facts: Dict[str, Any] = {
        "meta": meta_facts(meta, a.sla_mitigate_days, a.sla_patch_days),
        "fleet": fleet_facts(a.audit) if a.audit else {"available": False},
        "trend": trend_facts(a.audit_before, a.audit),
        "repos": repo_facts(a.gh_scan),
        "posture": posture_facts(a.actions),
        "source": source_facts(a.source),
        "jars": jar_facts(a.jars),
        "gate": gate_facts(a.gate),
        "crashes": crash_facts(a.crashes),
        "traffic": traffic_facts(a.b64),
        "extra": _load(a.extra) if a.extra else {},
    }
    facts["status"] = rag(facts)
    facts["actions"] = consolidated_actions(facts)
    facts["inputs"] = {k: v for k, v in {"audit": _expand(a.audit), "audit_before": _expand(a.audit_before), "gh_scan": a.gh_scan, "actions": a.actions,
                                         "source": a.source, "jars": a.jars, "gate": a.gate, "crashes": a.crashes, "b64": a.b64, "extra": a.extra}.items() if v}
    text = json.dumps(facts, indent=2, default=str)
    if a.out:
        with open(a.out, "w", encoding="utf-8") as fh:
            fh.write(text)
        sys.stderr.write(f"[facts] {a.out}: status {facts['status']['rag']}, sections: " +
                         ", ".join(k for k in ("fleet", "trend", "repos", "posture", "source", "jars", "gate", "crashes", "traffic") if facts[k].get("available")) + "\n")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
