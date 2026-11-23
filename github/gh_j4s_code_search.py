#!/usr/bin/env python3
"""GitHub Code Search sweep for CVE-2026-114938 ("Java4Shell") across a user, organization or repo set.

Runs the runbook's search patterns (../patterns/SPEC.md) as GitHub code-search queries, then fetches
each matched file and applies the exact regexes locally so every hit has a line number and a label:

  pattern set   query terms                                 local regex / label
  decoder       Base64 getDecoder|getUrlDecoder|getMimeDecoder   J4S-SRC-01 decoder call (+ J4S-SRC-04 if auth context on the line)
  auth          Authorization|Bearer|Basic|jwt|saml + Base64     J4S-SRC-04 pre-auth decode context
  flags         UseBASE64Intrinsics, UseAVX, JAVA_TOOL_OPTIONS, JDK_JAVA_OPTIONS
                                                                 J4S-FLAG-02 ACTIVE / -03 CAPPED / -04 EXPLICITLY_ENABLED / -01 MENTION
  oracle8       8u511b33                                         J4S-VER-02
  images        FROM temurin|corretto|openjdk|zulu|liberica|sapmachine|graalvm (Dockerfiles)
                                                                 J4S-VER-05 version verdict for the image tag
  setup-java    java-version in .github/workflows                J4S-VER-05 verdict for the CI JDK pin
  gate          gate_cve_2026_114938 / CVE-2026-114938          J4S-ID-01 existing remediation references

Code search needs an authenticated token, only indexes default branches and files < 384 KB, and is
limited to 10 requests/minute; the script paces itself. Scope qualifiers: --user, --org, --repo
(repeatable) or none for all of GitHub (public code; noisy, use --max-hits).

Examples:
  gh_j4s_code_search.py --org acme
  gh_j4s_code_search.py --user octocat --set flags --set images --format json --out hits.json
  gh_j4s_code_search.py --org acme --set decoder --set auth --format repos | gh_j4s_scan.py - --source
  gh_j4s_code_search.py --repo acme/api --repo acme/web --no-fetch   # text-match fragments only, no line numbers
  gh_j4s_code_search.py --self-test

Exit codes: 0 only REVIEW/INFO hits, 2 at least one MITIGATE/BLOCK hit (vulnerable image/JDK pin,
explicit re-enable, Oracle 8u511b33-perf, pre-auth decode context), 1 execution error.
Python 3.9+, standard library only.
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Iterator, List, Optional, Tuple

CVE = "CVE-2026-114938"
ALIAS = "Java4Shell"
TOOL_VERSION = "1.0.0"
SOURCE_EXT = (".java", ".kt", ".kts", ".scala", ".groovy", ".clj", ".jsp", ".jspx")

# ---- version logic (identical to helpers/j4s_version.py) --------------------------------------
PATCHED_BASELINES: Dict[int, Tuple[int, ...]] = {17: (17, 0, 21, 0, 3), 21: (21, 0, 13, 1), 25: (25, 0, 5, 1), 27: (27, 0, 1, 1)}
EOL_VULNERABLE_MAJORS = frozenset({18, 19, 20, 22, 23, 24, 26})
JAVA8_PERF_RE = re.compile(r"8u511b33-perf", re.I)


def parse_version(ver: str) -> Optional[Tuple[int, ...]]:
    v = ver.strip().strip("\"'")
    m = re.match(r"^1\.(\d)(?:\.0(?:_(\d+))?)?$", v)
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


def _pad(t: Tuple[int, ...], n: int) -> Tuple[int, ...]:
    return tuple(list(t) + [0] * (n - len(t)))[:n]


def classify(ver: str) -> Tuple[str, str]:
    """-> (status, note). status: VULN_RANGE | PATCHED_OR_UNAFFECTED | FLOATING_PATCHABLE | UNKNOWN."""
    if JAVA8_PERF_RE.search(ver):
        return "VULN_RANGE", "Oracle 8u511b33-perf"
    parsed = parse_version(ver)
    if not parsed:
        return "UNKNOWN", "unparsed"
    major = parsed[0]
    if major <= 16:
        return "PATCHED_OR_UNAFFECTED", f"JDK {major} unaffected"
    if major in EOL_VULNERABLE_MAJORS:
        return "VULN_RANGE", f"JDK {major} EOL, no patch"
    if len(parsed) == 1:
        return "FLOATING_PATCHABLE", f"floating JDK {major}; verify resolved build >= {'.'.join(map(str, PATCHED_BASELINES.get(major, ())))}"
    if major == 17 and _pad(parsed, 5)[1] == 0 and _pad(parsed, 5)[2] < 6:
        return "PATCHED_OR_UNAFFECTED", "17.0.x before 17.0.6"
    base = PATCHED_BASELINES.get(major)
    if base is None:
        return "VULN_RANGE", f"JDK {major} newer than runbook table; verify vendor advisory"
    if _pad(parsed, len(base)) >= base:
        return "PATCHED_OR_UNAFFECTED", f">= {'.'.join(map(str, base))}"
    return "VULN_RANGE", f"< {'.'.join(map(str, base))}"


# ---- patterns ---------------------------------------------------------------------------------
_LEAD = r'(?:^|[\s"\'=,;(])'
_TRAIL = r'(?=$|[\s"\'\\,;)])'
FLAG_ACTIVE_RE = re.compile(_LEAD + r"-XX:-UseBASE64Intrinsics" + _TRAIL)
FLAG_CAP_RE = re.compile(_LEAD + r"-XX:UseAVX=([0-2])" + _TRAIL)
FLAG_REENABLE_RE = re.compile(_LEAD + r"-XX:\+UseBASE64Intrinsics" + _TRAIL)
FLAG_MENTION_RE = re.compile(r"(-XX:[+-]?UseBASE64Intrinsics|-XX:UseAVX=\d|JAVA_TOOL_OPTIONS|JDK_JAVA_OPTIONS|_JAVA_OPTIONS)")
DECODER_RE = re.compile(r"\b(Base64\.(getDecoder|getUrlDecoder|getMimeDecoder)|getDecoder\(\)|getUrlDecoder\(\)|getMimeDecoder\(\))")
AUTH_CONTEXT_RE = re.compile(r"\b(Authorization|Proxy-Authorization|Basic\s+[A-Za-z0-9+/=_-]+|jwt|jws|saml|bearer)\b.{0,120}\b(Base64|decode|getDecoder)\b", re.I)
ORACLE8_RE = re.compile(r"8u511b33(?:-perf)?", re.I)
CVE_RE = re.compile(r"CVE-2026-114938|Java4Shell|JDK-8393212|gate_cve_2026_114938|UseBASE64Intrinsics", re.I)
FROM_RE = re.compile(r"^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)", re.I)
JDK_IMAGE_RE = re.compile(r"(?i)(?:^|/)(eclipse-temurin|temurin|openjdk|amazoncorretto|corretto|zulu[\w-]*|liberica[\w-]*|sapmachine|semeru[\w-]*|ibm-semeru-runtimes|graalvm[\w-]*|jdk[\w-]*|jre[\w-]*|java)$")
JVM_APP_IMAGE_RE = re.compile(r"(?i)(?:^|/)(maven|gradle|tomcat|tomee|jetty|jenkins|keycloak|wildfly|payara|sonarqube|elasticsearch|kafka)$")
TAG_EXACT_RE = re.compile(r"(?i)^(?:jdk-?|jre-?|openjdk-?|open-|v)?(\d+(?:\.\d+){1,4})(?:[_+]\d+(?:\.\d+)*)?(?![\d.])")
TAG_MAJOR_RE = re.compile(r"(?i)^(?:jdk-?|jre-?|openjdk-?|open-|v)?(\d{1,2})(?![\d.])")
TAG_EMBEDDED_MAJOR_RE = re.compile(r"(?i)(?:^|[-_.])(?:jdk|jre|java|openjdk|temurin|corretto|zulu|liberica|graalvm(?:-ce|-community)?|semeru)-?(\d{1,2})(?=$|[-_.])")
SETUP_JAVA_RE = re.compile(r"""^\s*(?:-\s*)?java-version:\s*["']?([^"'#\n]+?)["']?\s*(?:#.*)?$""", re.I)

SEVERITY = {"BLOCK": 3, "MITIGATE": 2, "REVIEW": 1, "INFO": 0}

# pattern set -> list of (query terms, extra qualifiers)
QUERY_SETS: Dict[str, List[Tuple[str, str]]] = {
    "decoder": [("Base64 getDecoder", ""), ("getUrlDecoder", ""), ("getMimeDecoder", "")],
    "auth": [("Authorization Base64", ""), ("Bearer Base64 decode", ""), ("jwt Base64 decode", ""), ("saml Base64 decode", "")],
    "flags": [("UseBASE64Intrinsics", ""), ("JAVA_TOOL_OPTIONS", ""), ("JDK_JAVA_OPTIONS", ""), ("UseAVX", "")],
    "oracle8": [("8u511b33", "")],
    "images": [("FROM temurin", "filename:Dockerfile"), ("FROM corretto", "filename:Dockerfile"), ("FROM openjdk", "filename:Dockerfile"),
               ("FROM zulu", "filename:Dockerfile"), ("FROM liberica", "filename:Dockerfile"), ("FROM sapmachine", "filename:Dockerfile"),
               ("FROM graalvm", "filename:Dockerfile")],
    "setup-java": [("setup-java java-version", "path:.github/workflows")],
    "gate": [("gate_cve_2026_114938", ""), ("CVE-2026-114938", "")],
}
DEFAULT_SETS = ["decoder", "flags", "oracle8", "images", "setup-java", "gate"]


class GitHubError(Exception):
    def __init__(self, status: int, message: str, url: str = ""):
        super().__init__(f"HTTP {status}: {message} ({url})")
        self.status = status
        self.message = message


def resolve_token(explicit: Optional[str]) -> Optional[str]:
    for cand in (explicit, os.environ.get("GH_TOKEN"), os.environ.get("GITHUB_TOKEN")):
        if cand:
            return cand.strip()
    gh = shutil.which("gh")
    if gh:
        try:
            p = subprocess.run([gh, "auth", "token"], capture_output=True, text=True, timeout=15, check=False)
            if p.returncode == 0 and p.stdout.strip():
                return p.stdout.strip()
        except (OSError, subprocess.SubprocessError):
            pass
    return None


class GitHub:
    def __init__(self, token: Optional[str], api_url: str, timeout: float = 30.0, max_wait: float = 300.0, verbose: bool = False, search_interval: float = 6.5):
        self.token, self.api_url, self.timeout, self.max_wait, self.verbose = token, api_url.rstrip("/"), timeout, max_wait, verbose
        self.requests = 0
        self.lock = threading.Lock()
        self._cs_last = 0.0
        self._cs_interval = search_interval
        self.rate: Dict[str, str] = {}

    def log(self, msg: str) -> None:
        if self.verbose:
            sys.stderr.write(f"[gh] {msg}\n")

    def request(self, path: str, params: Optional[Dict[str, Any]] = None, accept: str = "application/vnd.github+json") -> Tuple[int, Dict[str, str], bytes]:
        url = path if path.startswith("http") else f"{self.api_url}/{path.lstrip('/')}"
        if params:
            url += ("&" if "?" in url else "?") + urllib.parse.urlencode(params, doseq=True)
        is_search = "/search/code" in url
        attempts = 0
        while True:
            attempts += 1
            if is_search:
                with self.lock:
                    wait = self._cs_last + self._cs_interval - time.monotonic()
                    if wait > 0:
                        time.sleep(wait)
                    self._cs_last = time.monotonic()
            req = urllib.request.Request(url, headers={"Accept": accept, "User-Agent": f"gh_j4s_code_search/{TOOL_VERSION} (+{CVE})", "X-GitHub-Api-Version": "2022-11-28"})
            if self.token:
                req.add_header("Authorization", f"Bearer {self.token}")
            with self.lock:
                self.requests += 1
            self.log(f"GET {url}")
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    headers = {k.lower(): v for k, v in resp.headers.items()}
                    if is_search:
                        self.rate["code_search"] = f"{headers.get('x-ratelimit-remaining', '?')}/{headers.get('x-ratelimit-limit', '?')}"
                    else:
                        self.rate["core"] = f"{headers.get('x-ratelimit-remaining', '?')}/{headers.get('x-ratelimit-limit', '?')}"
                    return resp.status, headers, resp.read()
            except urllib.error.HTTPError as e:
                headers = {k.lower(): v for k, v in e.headers.items()} if e.headers else {}
                body = e.read() if e.fp else b""
                if e.code in (403, 429) and attempts <= 4:
                    wait = None
                    if headers.get("retry-after"):
                        wait = float(headers["retry-after"])
                    elif headers.get("x-ratelimit-remaining") == "0" and headers.get("x-ratelimit-reset"):
                        wait = max(0.0, int(headers["x-ratelimit-reset"]) - time.time())
                    elif is_search and b"secondary rate limit" in body.lower():
                        wait = 60.0
                    if wait is not None:
                        if wait > self.max_wait:
                            raise GitHubError(e.code, f"rate limited; reset in {int(wait)}s exceeds --max-wait", url)
                        sys.stderr.write(f"[gh] rate limited; sleeping {int(wait) + 1}s\n")
                        time.sleep(wait + 1)
                        continue
                if e.code >= 500 and attempts <= 3:
                    time.sleep(2 * attempts)
                    continue
                try:
                    msg = json.loads(body.decode("utf-8", "replace")).get("message", e.reason)
                except (ValueError, AttributeError):
                    msg = e.reason
                raise GitHubError(e.code, str(msg), url)
            except (urllib.error.URLError, TimeoutError, OSError) as e:
                if attempts <= 3:
                    time.sleep(2 * attempts)
                    continue
                raise GitHubError(0, f"network error: {e}", url)

    def search_code(self, q: str, max_hits: int, text_match: bool) -> Iterator[Dict[str, Any]]:
        accept = "application/vnd.github.text-match+json" if text_match else "application/vnd.github+json"
        page, got = 1, 0
        while got < max_hits:
            per_page = min(100, max_hits - got)
            _, _, body = self.request("search/code", {"q": q, "per_page": per_page, "page": page}, accept=accept)
            data = json.loads(body.decode("utf-8", "replace"))
            items = data.get("items", [])
            if data.get("incomplete_results"):
                self.log(f"incomplete_results for {q!r} page {page}")
            for it in items:
                yield it
                got += 1
                if got >= max_hits:
                    return
            if len(items) < per_page or page >= 10:
                return
            page += 1

    def get_raw(self, url: str) -> str:
        _, _, body = self.request(url, accept="application/vnd.github.raw+json")
        return body.decode("utf-8", "replace")


@dataclass
class Hit:
    repo: str
    path: str
    line: int
    pattern_id: str
    label: str
    severity: str        # BLOCK | MITIGATE | REVIEW | INFO
    snippet: str
    url: str
    pattern_set: str
    query: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def parse_image_ref(ref: str) -> Tuple[str, Optional[str], Optional[str]]:
    digest = None
    if "@" in ref:
        ref, digest = ref.split("@", 1)
    name, tag = ref, None
    i = ref.rfind(":")
    if i > ref.rfind("/"):
        name, tag = ref[:i], ref[i + 1:]
    return name, tag, digest


def classify_image_ref(ref: str) -> Optional[Tuple[str, str, str]]:
    """-> (version_text, status, note) for JDK / JVM-app images, else None."""
    name, tag, digest = parse_image_ref(ref)
    is_jdk = bool(JDK_IMAGE_RE.search(name))
    if not is_jdk and not JVM_APP_IMAGE_RE.search(name):
        return None
    tag = tag or ""
    if is_jdk:
        m = TAG_EXACT_RE.match(tag)
        if m:
            st, note = classify(m.group(1))
            return m.group(1), st, note
        m = TAG_MAJOR_RE.match(tag)
        if m and int(m.group(1)) < 8:
            m = re.match(r"(?i)^\d+[-_](\d{1,2})(?![\d.])", tag)
        if m:
            major = int(m.group(1))
            if name.rstrip("/").endswith("openjdk") and major == 17:
                return tag, "PATCHED_OR_UNAFFECTED", "deprecated openjdk:17 image resolves to 17.0.2"
            st, note = classify(str(major))
            return tag, st, note
    m = TAG_EMBEDDED_MAJOR_RE.search(tag)
    if m:
        st, note = classify(m.group(1))
        return tag, st, note
    if is_jdk:
        return tag or "(digest)", "UNKNOWN", "tag does not encode a version"
    return None


def severity_for_version(status: str) -> str:
    return {"VULN_RANGE": "BLOCK", "FLOATING_PATCHABLE": "REVIEW", "UNKNOWN": "REVIEW"}.get(status, "INFO")


def analyze_text(repo: str, path: str, text: str, pattern_set: str, query: str, html_url: str) -> List[Hit]:
    """Apply the local regexes of one pattern set to a fetched file."""
    hits: List[Hit] = []
    lower = path.lower()

    def add(line: int, pid: str, label: str, sev: str, snippet: str) -> None:
        hits.append(Hit(repo, path, line, pid, label, sev, snippet.strip()[:200], f"{html_url}#L{line}" if line else html_url, pattern_set, query))

    lines = text.splitlines()
    if pattern_set in ("decoder", "auth"):
        if "Base64" not in text and "Decoder" not in text:
            return hits
        for n, line in enumerate(lines, 1):
            dec = DECODER_RE.search(line)
            auth = AUTH_CONTEXT_RE.search(line)
            if dec and auth:
                add(n, "J4S-SRC-04", "DECODER_IN_AUTH_CONTEXT", "MITIGATE", line)
            elif dec and pattern_set == "decoder":
                add(n, "J4S-SRC-01", "DECODER_CALL", "REVIEW", line)
            elif auth and pattern_set == "auth":
                add(n, "J4S-SRC-04", "AUTH_DECODE_CONTEXT", "MITIGATE", line)
    elif pattern_set == "flags":
        for n, line in enumerate(lines, 1):
            if FLAG_REENABLE_RE.search(line):
                add(n, "J4S-FLAG-04", "EXPLICITLY_ENABLED", "BLOCK", line)
            elif FLAG_ACTIVE_RE.search(line):
                add(n, "J4S-FLAG-02", "ACTIVE", "INFO", line)
            elif FLAG_CAP_RE.search(line):
                add(n, "J4S-FLAG-03", "CAPPED", "INFO", line)
            elif FLAG_MENTION_RE.search(line):
                add(n, "J4S-FLAG-01", "MENTION", "REVIEW", line)
    elif pattern_set == "oracle8":
        for n, line in enumerate(lines, 1):
            if ORACLE8_RE.search(line):
                add(n, "J4S-VER-02", "ORACLE_8U511B33_PERF", "BLOCK" if "perf" in line.lower() else "REVIEW", line)
    elif pattern_set == "images":
        for n, line in enumerate(lines, 1):
            m = FROM_RE.match(line)
            if not m:
                continue
            res = classify_image_ref(m.group(1))
            if res:
                ver, st, note = res
                add(n, "J4S-VER-05", f"{st}:{ver}", severity_for_version(st), f"{line.strip()}  # {note}")
    elif pattern_set == "setup-java":
        for n, line in enumerate(lines, 1):
            m = SETUP_JAVA_RE.match(line)
            if not m:
                continue
            val = m.group(1).strip().strip("\"'")
            if val.startswith("${{"):
                add(n, "J4S-VER-05", "MATRIX:" + val, "INFO", line)
                continue
            if re.fullmatch(r"\d{1,2}(?:\.x)?(?:-ea)?", val):
                st, note = classify(val.split(".")[0].split("-")[0])
            elif re.fullmatch(r"\d+(?:\.\d+){1,4}(?:[_+]\d+)?", val):
                st, note = classify(val)
            else:
                continue
            sev = severity_for_version(st)
            add(n, "J4S-VER-05", f"{st}:{val}", "REVIEW" if sev == "BLOCK" else sev, f"{line.strip()}  # CI runner JDK; {note}")
    elif pattern_set == "gate":
        for n, line in enumerate(lines, 1):
            if CVE_RE.search(line):
                add(n, "J4S-ID-01", "CVE_REFERENCE", "INFO", line)
    return hits


def fragments_to_hits(repo: str, path: str, item: Dict[str, Any], pattern_set: str, query: str) -> List[Hit]:
    """--no-fetch mode: use the API's text-match fragments; no line numbers."""
    hits: List[Hit] = []
    for tm in item.get("text_matches", []) or []:
        frag = tm.get("fragment", "")
        for h in analyze_text(repo, path, frag, pattern_set, query, item.get("html_url", "")):
            h.line = 0
            h.url = item.get("html_url", "")
            hits.append(h)
    if not hits:
        hits.append(Hit(repo, path, 0, "J4S-SEARCH", "SEARCH_MATCH", "INFO", (item.get("text_matches") or [{}])[0].get("fragment", "")[:200], item.get("html_url", ""), pattern_set, query))
    return hits


def build_queries(opts: argparse.Namespace) -> List[Tuple[str, str, str]]:
    scope_quals: List[str] = []
    for u in opts.user:
        scope_quals.append(f"user:{u}")
    for o in opts.org:
        scope_quals.append(f"org:{o}")
    for r in opts.repo:
        scope_quals.append(f"repo:{r}")
    # GitHub ORs repeated user:/org:/repo: qualifiers (verified 2026-11-20: repo:a repo:b returned the sum of
    # the two single-repo counts), so scopes are packed into as few queries as the 256-character limit allows.
    chunks: List[str] = []
    cur = ""
    for sq in scope_quals:
        if cur and len(cur) + 1 + len(sq) > 180:
            chunks.append(cur)
            cur = sq
        else:
            cur = f"{cur} {sq}".strip()
    if cur:
        chunks.append(cur)
    out: List[Tuple[str, str, str]] = []
    sets = opts.set or DEFAULT_SETS
    for s in sets:
        for terms, quals in QUERY_SETS[s]:
            for chunk in (chunks or [""]):
                out.append((s, terms, " ".join(x for x in (terms, quals, chunk, opts.extra_qualifiers) if x)))
    return out


def run(opts: argparse.Namespace, gh: GitHub) -> Tuple[List[Hit], Dict[str, Any]]:
    queries = build_queries(opts)
    sys.stderr.write(f"[gh] {len(queries)} code-search queries (~{int(len(queries) * gh._cs_interval)}s minimum at 10/min)\n")
    hits: List[Hit] = []
    files_seen: set = set()
    stats = {"queries": len(queries), "search_results": 0, "files_fetched": 0, "errors": []}
    cache: Dict[str, str] = {}
    for pattern_set, terms, q in queries:
        try:
            for item in gh.search_code(q, opts.max_hits, text_match=opts.no_fetch):
                stats["search_results"] += 1
                repo = item.get("repository", {}).get("full_name", "?")
                path = item.get("path", "")
                if pattern_set in ("decoder", "auth") and not path.lower().endswith(SOURCE_EXT):
                    continue
                key = (repo, path, pattern_set)
                if key in files_seen:
                    continue
                files_seen.add(key)
                if opts.no_fetch:
                    hits.extend(fragments_to_hits(repo, path, item, pattern_set, terms))
                    continue
                blob_url = item.get("git_url") or item.get("url")
                try:
                    if blob_url not in cache:
                        cache[blob_url] = gh.get_raw(blob_url)
                        stats["files_fetched"] += 1
                    hits.extend(analyze_text(repo, path, cache[blob_url], pattern_set, terms, item.get("html_url", "")))
                except GitHubError as e:
                    stats["errors"].append(f"{repo}/{path}: {e.message}")
        except GitHubError as e:
            stats["errors"].append(f"query {q!r}: {e.message}")
            sys.stderr.write(f"[gh] query failed: {q!r}: {e.message}\n")
            if e.status in (401, 422) and "search" in str(e).lower() and not gh.token:
                break
    return hits, stats


def rollup(hits: List[Hit]) -> Dict[str, Dict[str, Any]]:
    by_repo: Dict[str, Dict[str, Any]] = {}
    for h in hits:
        r = by_repo.setdefault(h.repo, {"hits": 0, "max_severity": "INFO", "labels": {}, "files": set()})
        r["hits"] += 1
        r["files"].add(h.path)
        r["labels"][h.label.split(":")[0]] = r["labels"].get(h.label.split(":")[0], 0) + 1
        if SEVERITY[h.severity] > SEVERITY[r["max_severity"]]:
            r["max_severity"] = h.severity
    for r in by_repo.values():
        r["files"] = sorted(r["files"])
    return by_repo


def render_table(hits: List[Hit]) -> str:
    rows = [("SEV", "REPO", "FILE:LINE", "PATTERN", "LABEL", "SNIPPET")]
    for h in sorted(hits, key=lambda h: (-SEVERITY[h.severity], h.repo, h.path, h.line)):
        rows.append((h.severity, h.repo, f"{h.path}:{h.line}" if h.line else h.path, h.pattern_id, h.label[:34], h.snippet[:70]))
    widths = [min(max(len(r[i]) for r in rows), 70) for i in range(len(rows[0]))]
    out = []
    for i, r in enumerate(rows):
        out.append("  ".join(c[:widths[j]].ljust(widths[j]) for j, c in enumerate(r)).rstrip())
        if i == 0:
            out.append("  ".join("-" * w for w in widths))
    return "\n".join(out)


def render_md(hits: List[Hit], by_repo: Dict[str, Dict[str, Any]], scope: str, stats: Dict[str, Any]) -> str:
    out = [f"# {CVE} ({ALIAS}) GitHub code-search sweep", "", f"Scope: `{scope}` · {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')} · {stats['queries']} queries · {stats['search_results']} search results · {len(hits)} verified hits in {len(by_repo)} repositories", ""]
    out += ["| Repository | Max severity | Hits | Labels |", "| :--- | :--- | ---: | :--- |"]
    for repo, r in sorted(by_repo.items(), key=lambda kv: (-SEVERITY[kv[1]["max_severity"]], kv[0])):
        out.append(f"| {repo} | `{r['max_severity']}` | {r['hits']} | {', '.join(f'{k}×{v}' for k, v in sorted(r['labels'].items()))} |")
    out += ["", "## Hits (BLOCK and MITIGATE first)", "", "| Sev | Repository | File | Pattern | Label | Snippet |", "| :--- | :--- | :--- | :--- | :--- | :--- |"]
    for h in sorted(hits, key=lambda h: (-SEVERITY[h.severity], h.repo, h.path, h.line))[:500]:
        loc = f"[{h.path}:{h.line}]({h.url})" if h.url else f"{h.path}:{h.line}"
        out.append(f"| `{h.severity}` | {h.repo} | {loc} | {h.pattern_id} | {h.label} | `{h.snippet[:90].replace('|', '/').replace('`', '')}` |")
    if stats["errors"]:
        out += ["", "## Errors", ""] + [f"- {e}" for e in stats["errors"][:50]]
    return "\n".join(out) + "\n"


def render_csv(hits: List[Hit]) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["severity", "repo", "path", "line", "pattern_id", "label", "pattern_set", "query", "url", "snippet"])
    for h in hits:
        w.writerow([h.severity, h.repo, h.path, h.line, h.pattern_id, h.label, h.pattern_set, h.query, h.url, h.snippet])
    return buf.getvalue()


def self_test() -> int:
    fails: List[str] = []

    def check(c: bool, label: str) -> None:
        if not c:
            fails.append(label)
    for ref, want in [("eclipse-temurin:21.0.12_7-jre", "VULN_RANGE"), ("eclipse-temurin:21.0.13.1_9-jre", "PATCHED_OR_UNAFFECTED"), ("amazoncorretto:21", "FLOATING_PATCHABLE"),
                      ("openjdk:19-jdk", "VULN_RANGE"), ("openjdk:17", "PATCHED_OR_UNAFFECTED"), ("maven:3.9-eclipse-temurin-21", "FLOATING_PATCHABLE"),
                      ("sapmachine:17.0.21.0.3", "PATCHED_OR_UNAFFECTED"), ("azul/zulu-openjdk:17.0.9-17.46", "VULN_RANGE")]:
        res = classify_image_ref(ref)
        check(res is not None and res[1] == want, f"image {ref} -> {res}, want {want}")
    check(classify_image_ref("python:3.12") is None, "python image ignored")
    hits = analyze_text("a/b", "src/Auth.java", 'String h = req.getHeader("X-Trace");\nString t = authorization.substring(6); byte[] b = Base64.getDecoder().decode(t);\nString s = Base64.getUrlDecoder().decode(x);\n', "decoder", "q", "u")
    check([(h.line, h.pattern_id, h.severity) for h in hits] == [(2, "J4S-SRC-04", "MITIGATE"), (3, "J4S-SRC-01", "REVIEW")], f"decoder hits {[(h.line, h.pattern_id) for h in hits]}")
    hits = analyze_text("a/b", "Dockerfile", 'ENV JAVA_TOOL_OPTIONS="-XX:-UseBASE64Intrinsics"\nCMD java -XX:+UseBASE64Intrinsics -jar app.jar\nENV X=JAVA_OPTS\nENV JDK_JAVA_OPTIONS=-XX:UseAVX=2\n', "flags", "q", "u")
    check([h.label for h in hits] == ["ACTIVE", "EXPLICITLY_ENABLED", "CAPPED"], f"flag labels {[h.label for h in hits]}")
    hits = analyze_text("a/b", "Dockerfile", "FROM maven:3.9.9-eclipse-temurin-21 AS build\nFROM eclipse-temurin:21.0.12_7-jre-jammy\n", "images", "q", "u")
    check([h.severity for h in hits] == ["REVIEW", "BLOCK"], f"image severities {[(h.label, h.severity) for h in hits]}")
    hits = analyze_text("a/b", ".github/workflows/ci.yml", "      with:\n        java-version: '17'\n        java-version: 21.0.12\n        java-version: ${{ matrix.java }}\n", "setup-java", "q", "u")
    check([h.label.split(":")[0] for h in hits] == ["FLOATING_PATCHABLE", "VULN_RANGE", "MATRIX"], f"setup-java {[h.label for h in hits]}")
    hits = analyze_text("a/b", "README.md", "Use Oracle 8u511b33-perf\n", "oracle8", "q", "u")
    check(hits and hits[0].severity == "BLOCK", "oracle8 block")
    ns = argparse.Namespace(user=["u1"], org=["o1"], repo=[], set=["flags"], extra_qualifiers="")
    qs = build_queries(ns)
    check(len(qs) == 4 and qs[0][2] == "UseBASE64Intrinsics user:u1 org:o1", f"queries {qs[:2]}")
    ns = argparse.Namespace(user=[], org=[], repo=[f"org/repository-number-{i:03d}" for i in range(20)], set=["oracle8"], extra_qualifiers="")
    qs = build_queries(ns)
    check(2 <= len(qs) <= 4 and all(len(q[2]) <= 256 for q in qs) and sum(q[2].count("repo:") for q in qs) == 20, f"chunked queries {len(qs)} {[len(q[2]) for q in qs]}")
    if fails:
        print("SELF-TEST FAILED:")
        for f in fails:
            print("  -", f)
        return 1
    print("SELF-TEST PASSED (gh_j4s_code_search.py)")
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sc = ap.add_argument_group("scope")
    sc.add_argument("--user", action="append", default=[], metavar="LOGIN")
    sc.add_argument("--org", action="append", default=[], metavar="ORG")
    sc.add_argument("--repo", action="append", default=[], metavar="OWNER/REPO")
    sc.add_argument("--extra-qualifiers", default="", help="appended to every query, e.g. 'language:Java' or 'fork:true'")
    an = ap.add_argument_group("patterns")
    an.add_argument("--set", action="append", choices=sorted(QUERY_SETS), help=f"pattern set to run (repeatable; default {','.join(DEFAULT_SETS)})")
    an.add_argument("--max-hits", type=int, default=200, help="search results consumed per query (max 1000; 100 per request)")
    an.add_argument("--no-fetch", action="store_true", help="do not download matched files; use the search API's text fragments (no line numbers)")
    ou = ap.add_argument_group("output")
    ou.add_argument("--format", choices=["table", "json", "ndjson", "csv", "md", "repos"], default="table", help="repos = owner/repo list for piping into gh_j4s_scan.py")
    ou.add_argument("--out", metavar="FILE")
    ou.add_argument("--min-severity", choices=["INFO", "REVIEW", "MITIGATE", "BLOCK"], default="INFO", help="drop hits below this severity from the output")
    cn = ap.add_argument_group("connection")
    cn.add_argument("--token")
    cn.add_argument("--api-url", default=os.environ.get("GITHUB_API_URL", "https://api.github.com"))
    cn.add_argument("--search-interval", type=float, default=6.5, help="seconds between code-search requests (10/min limit)")
    cn.add_argument("--max-wait", type=float, default=300)
    cn.add_argument("--timeout", type=float, default=30)
    ap.add_argument("-v", "--verbose", action="store_true")
    ap.add_argument("--self-test", action="store_true")
    opts = ap.parse_args(argv)
    if opts.self_test:
        return self_test()

    token = resolve_token(opts.token)
    if not token:
        sys.stderr.write("error: GitHub code search requires authentication (--token, $GH_TOKEN, $GITHUB_TOKEN or `gh auth login`)\n")
        return 1
    gh = GitHub(token, opts.api_url, timeout=opts.timeout, max_wait=opts.max_wait, verbose=opts.verbose, search_interval=opts.search_interval)
    scope = " ".join([f"user:{u}" for u in opts.user] + [f"org:{o}" for o in opts.org] + [f"repo:{r}" for r in opts.repo]) or "all of GitHub"
    if scope == "all of GitHub":
        sys.stderr.write("[gh] no --user/--org/--repo given: searching all public code (noisy; consider --max-hits and --set)\n")

    hits, stats = run(opts, gh)
    hits = [h for h in hits if SEVERITY[h.severity] >= SEVERITY[opts.min_severity]]
    by_repo = rollup(hits)

    if opts.format == "json":
        text = json.dumps({"cve": CVE, "alias": ALIAS, "tool": "gh_j4s_code_search", "tool_version": TOOL_VERSION, "generated_at": datetime.now(timezone.utc).isoformat(),
                           "scope": scope, "stats": stats, "repos": by_repo, "hits": [h.to_dict() for h in hits]}, indent=2)
    elif opts.format == "ndjson":
        text = "\n".join(json.dumps(h.to_dict()) for h in hits) + ("\n" if hits else "")
    elif opts.format == "csv":
        text = render_csv(hits)
    elif opts.format == "md":
        text = render_md(hits, by_repo, scope, stats)
    elif opts.format == "repos":
        text = "\n".join(sorted(by_repo)) + ("\n" if by_repo else "")
    else:
        text = render_table(hits) + "\n\n" + f"{len(hits)} hits in {len(by_repo)} repositories; " + " ".join(f"{k}={sum(1 for h in hits if h.severity == k)}" for k in ("BLOCK", "MITIGATE", "REVIEW", "INFO")) + "\n"
    if opts.out:
        with open(opts.out, "w", encoding="utf-8") as fh:
            fh.write(text)
        sys.stderr.write(f"[gh] written to {opts.out}\n")
    else:
        sys.stdout.write(text)
    sys.stderr.write(f"[gh] requests={gh.requests} " + " ".join(f"{k}={v}" for k, v in gh.rate.items()) + (f" errors={len(stats['errors'])}" if stats["errors"] else "") + "\n")
    if any(h.severity in ("BLOCK", "MITIGATE") for h in hits):
        return 2
    if stats["errors"] and not hits:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
