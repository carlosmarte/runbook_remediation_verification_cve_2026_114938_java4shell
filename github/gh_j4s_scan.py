#!/usr/bin/env python3
"""Remote GitHub repository scanner for CVE-2026-114938 ("Java4Shell"). No clone needed.

Walks each repository's default-branch tree through the GitHub REST API, fetches only the
files that pin a JDK or set JVM options (Dockerfiles, compose/Kubernetes/Helm/Actions YAML,
.java-version, .sdkmanrc, .tool-versions, system.properties, pom.xml, Gradle files, service
units, start scripts, Terraform), and applies the runbook's checks:

  * JDK version pins          -> VULN_RANGE / PATCHED_OR_UNAFFECTED / FLOATING   (J4S-VER-01/01b/02/05)
  * mitigation flag presence  -> ACTIVE / CAPPED / EXPLICITLY_ENABLED            (J4S-FLAG-02/03/04/06)
  * Java workload evidence    -> tree + content                                  (J4S-RT-05)
  * CI gate presence          -> .github/workflows / .gitlab-ci.yml referencing the gate (runbook §7.2)
  * optional source hits      -> java.util.Base64 decode call sites + pre-auth context (J4S-SRC-01/04)

Scope: --user U | --org O | --me | explicit owner/repo arguments | --repos-file | stdin (-).
Auth:  --token, $GH_TOKEN, $GITHUB_TOKEN, or `gh auth token`; unauthenticated works for public repos
       at 60 requests/hour. $GITHUB_API_URL / --api-url for GitHub Enterprise Server.

Examples:
  gh_j4s_scan.py --user octocat
  gh_j4s_scan.py --org acme --pushed-since 2025-01-01 --format json --out acme-java4shell.json
  gh_j4s_repos.sh --org acme --language java,kotlin | gh_j4s_scan.py - --source --sarif-dir sarif/
  gh_j4s_scan.py acme/payments-api acme/auth-gateway --format md
  gh_j4s_scan.py --self-test

Exit codes: 0 nothing EXPOSED, 2 at least one repo EXPOSED or EXPLICITLY_ENABLED (with --strict also
UNVERIFIED_*), 1 execution error. Python 3.9+, standard library only.
"""

from __future__ import annotations

import argparse
import concurrent.futures
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
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, Iterator, List, Optional, Tuple

CVE = "CVE-2026-114938"
ALIAS = "Java4Shell"
DISCLOSURE_DATE = "2026-11-17"
TOOL_VERSION = "1.0.0"

# --------------------------------------------------------------------------------------------
# Version logic (same rule as helpers/j4s_version.py and scripts/*: lexicographic over up to five
# components, baselines 17.0.21.0.3 / 21.0.13.1 / 25.0.5.1 / 27.0.1.1, EOL 18-20/22-24/26, 8u511b33-perf)
# --------------------------------------------------------------------------------------------
PATCHED_BASELINES: Dict[int, Tuple[int, ...]] = {17: (17, 0, 21, 0, 3), 21: (21, 0, 13, 1), 25: (25, 0, 5, 1), 27: (27, 0, 1, 1)}
EOL_VULNERABLE_MAJORS = frozenset({18, 19, 20, 22, 23, 24, 26})
MIGRATION_TARGET = {18: 21, 19: 21, 20: 21, 22: 25, 23: 25, 24: 25, 26: 27}
JVM_LANGUAGES = {"java", "kotlin", "scala", "groovy", "clojure"}
JAVA8_PERF_RE = re.compile(r"8u511b33-perf", re.I)
LEGACY_1X_RE = re.compile(r"^1\.(\d)(?:\.0(?:_(\d+))?)?$")


def fmt(t: Tuple[int, ...]) -> str:
    return ".".join(map(str, t))


def _pad(t: Tuple[int, ...], n: int) -> Tuple[int, ...]:
    return tuple(list(t) + [0] * (n - len(t)))[:n]


def parse_version(ver: str) -> Optional[Tuple[int, ...]]:
    """'17.0.21.0.3' -> (17,0,21,0,3); '21.0.12_7' -> (21,0,12); '1.8.0_392' -> (8,0,392); '21' -> (21,)."""
    v = ver.strip().strip('"\'')
    m = LEGACY_1X_RE.match(v)
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


def baseline_for(major: int) -> Optional[str]:
    b = PATCHED_BASELINES.get(major)
    return fmt(b) if b else None


def classify_exact(ver: str) -> Dict[str, Any]:
    """Classify a fully pinned version string. Returns status/reason/baseline/action/major/normalized."""
    if JAVA8_PERF_RE.search(ver):
        return dict(normalized="8u511b33-perf", major=8, status="VULN_RANGE", baseline=None,
                    reason="Oracle Java SE 8u511b33-perf build is affected",
                    action="Replace with a standard (non-perf) JDK 8 build or a patched LTS")
    parsed = parse_version(ver)
    if not parsed:
        return dict(normalized=None, major=None, status="UNKNOWN", baseline=None,
                    reason="Could not parse a numeric version", action="Resolve the exact JDK version")
    major = parsed[0]
    norm = fmt(parsed)
    if len(parsed) == 1:
        return classify_major(major, norm)
    if major <= 16:
        return dict(normalized=norm, major=major, status="PATCHED_OR_UNAFFECTED", baseline=None,
                    reason=f"JDK {major} (non-perf) does not contain the affected VBMI intrinsic", action="None required for this CVE")
    if major in EOL_VULNERABLE_MAJORS:
        tgt = MIGRATION_TARGET[major]
        return dict(normalized=norm, major=major, status="VULN_RANGE", baseline=baseline_for(tgt),
                    reason=f"JDK {major} is an EOL feature line with no patch",
                    action=f"Apply -XX:-UseBASE64Intrinsics now; migrate to JDK {tgt} ({baseline_for(tgt)}+)")
    if major == 17:
        p5 = _pad(parsed, 5)
        if p5[1] == 0 and p5[2] < 6:
            return dict(normalized=norm, major=17, status="PATCHED_OR_UNAFFECTED", baseline=baseline_for(17),
                        reason="17.0.x before 17.0.6 predates the affected intrinsic", action="Not required for this CVE; upgrade for other fixes")
        if p5 >= PATCHED_BASELINES[17]:
            return dict(normalized=norm, major=17, status="PATCHED_OR_UNAFFECTED", baseline=baseline_for(17),
                        reason="Meets or exceeds 17.0.21.0.3 baseline", action="None required")
        return dict(normalized=norm, major=17, status="VULN_RANGE", baseline=baseline_for(17),
                    reason="In 17.0.6 .. 17.0.21.0.2 vulnerable range",
                    action="Apply -XX:-UseBASE64Intrinsics; upgrade to 17.0.21.0.3+ (or vendor equivalent)")
    if major in PATCHED_BASELINES:
        base = PATCHED_BASELINES[major]
        if _pad(parsed, len(base)) >= base:
            return dict(normalized=norm, major=major, status="PATCHED_OR_UNAFFECTED", baseline=fmt(base),
                        reason=f"Meets or exceeds {fmt(base)} baseline", action="None required")
        return dict(normalized=norm, major=major, status="VULN_RANGE", baseline=fmt(base),
                    reason=f"Below {fmt(base)} baseline", action=f"Apply -XX:-UseBASE64Intrinsics; upgrade to {fmt(base)}+")
    return dict(normalized=norm, major=major, status="VULN_RANGE", baseline=None,
                reason=f"JDK {major} is newer than the runbook's table; verify vendor advisory",
                action="Apply -XX:-UseBASE64Intrinsics until the vendor confirms a fix")


def classify_major(major: int, raw: str = "") -> Dict[str, Any]:
    """Classify a floating (major-only) pin: image tag `21`, package `openjdk-21-jdk`, setup-java `21`."""
    norm = raw or str(major)
    if major <= 16:
        return dict(normalized=norm, major=major, status="PATCHED_OR_UNAFFECTED", baseline=None,
                    reason=f"JDK {major} line is not affected (unless Oracle 8u511b33-perf)", action="None required for this CVE")
    if major in EOL_VULNERABLE_MAJORS:
        tgt = MIGRATION_TARGET[major]
        return dict(normalized=norm, major=major, status="VULN_RANGE", baseline=baseline_for(tgt),
                    reason=f"JDK {major} is an EOL line; every build is vulnerable and no patch exists",
                    action=f"Apply -XX:-UseBASE64Intrinsics now; migrate to JDK {tgt} ({baseline_for(tgt)}+)")
    if major in PATCHED_BASELINES:
        return dict(normalized=norm, major=major, status="FLOATING_PATCHABLE", baseline=baseline_for(major),
                    reason=f"Floating JDK {major} pin resolves at build/deploy time; patched only if built after {DISCLOSURE_DATE} patch publication",
                    action=f"Rebuild and verify the resolved runtime is {baseline_for(major)}+; pin the digest or exact tag")
    return dict(normalized=norm, major=major, status="FLOATING_PATCHABLE", baseline=None,
                reason=f"Floating JDK {major} pin; verify the vendor's fixed build", action="Pin a patched build and verify with java -version")


# --------------------------------------------------------------------------------------------
# Patterns (IDs reference ../patterns/SPEC.md). Leading delimiter class carries the `=` fix (J4S-FLAG-02 note).
# --------------------------------------------------------------------------------------------
_LEAD = r'(?:^|[\s"\'=,;(])'
_TRAIL = r'(?=$|[\s"\'\\,;)])'
FLAG_ACTIVE_RE = re.compile(_LEAD + r"-XX:-UseBASE64Intrinsics" + _TRAIL)          # J4S-FLAG-02
FLAG_CAP_RE = re.compile(_LEAD + r"-XX:UseAVX=([0-2])" + _TRAIL)                    # J4S-FLAG-03
FLAG_REENABLE_RE = re.compile(_LEAD + r"-XX:\+UseBASE64Intrinsics" + _TRAIL)        # J4S-FLAG-04
FLAG_MENTION_RE = re.compile(r"(-XX:[+-]?UseBASE64Intrinsics|-XX:UseAVX=\d|JAVA_TOOL_OPTIONS|JDK_JAVA_OPTIONS|_JAVA_OPTIONS|JAVA_OPTS)")  # J4S-FLAG-01
JAVA_EVIDENCE_RE = re.compile(                                                       # J4S-RT-05 (extended)
    r"\b(java|jdk|jre|jvm|openjdk|temurin|corretto|zulu|liberica|sapmachine|graalvm|semeru|hotspot|maven|gradle|"
    r"spring[- ]?boot|tomcat|jetty|quarkus|micronaut|keycloak|JAVA_TOOL_OPTIONS|JDK_JAVA_OPTIONS|_JAVA_OPTIONS|JAVA_OPTS|setup-java)\b", re.I)
JAVA_LINE_RE = re.compile(r"(?i)\b(java|jdk|jre|openjdk|temurin|corretto|zulu|liberica|sapmachine|graalvm|semeru|hotspot|JAVA_[A-Z_]+|JDK_[A-Z_]+)\b")
VERSION_TOKEN_RE = re.compile(r"(?<![\d.])(\d+(?:\.\d+){2,4})(?:[_+]\d+(?:\.\d+)*)?(?![\d.])")   # J4S-VER-01b (3-5 components; 22.3 is a GraalVM/doc number, not a JDK)
ENV_MAJOR_RE = re.compile(r"(?i)\b((?:JAVA|JDK|OPENJDK|TEMURIN|CORRETTO|JRE)_?(?:VERSION|MAJOR|RELEASE))\s*[=:]\s*[\"']?(\d{1,2})(?![\d.])")
CVE_MENTION_RE = re.compile(r"CVE-2026-114938|Java4Shell|JDK-8393212|gate_cve_2026_114938", re.I)  # J4S-ID-01
DECODER_RE = re.compile(r"\b(Base64\.(getDecoder|getUrlDecoder|getMimeDecoder)|getDecoder\(\)|getUrlDecoder\(\)|getMimeDecoder\(\))")  # J4S-SRC-01
AUTH_CONTEXT_RE = re.compile(r"\b(Authorization|Proxy-Authorization|Basic\s+[A-Za-z0-9+/=_-]+|jwt|jws|saml|bearer)\b.{0,120}\b(Base64|decode|getDecoder)\b", re.I)  # J4S-SRC-04
AUTHY_PATH_RE = re.compile(r"(?i)(auth|security|token|jwt|saml|oauth|login|basic|credential|filter|interceptor|base64|decod|crypto|signature|session|cookie|header)")

FROM_RE = re.compile(r"^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?\s*$", re.I)
ARG_ENV_RE = re.compile(r"^\s*(?:ARG|ENV)\s+([A-Za-z_][A-Za-z0-9_]*)(?:=|\s+)(\S+)", re.I)
IMAGE_LINE_RE = re.compile(r"""(?ix)^\s*(?:-\s*)?(?:image|container_image|image_name|FROM)\s*[:=]\s*["']?([A-Za-z0-9][\w./:@\-${}]*)["']?""")
JDK_IMAGE_RE = re.compile(r"(?i)(?:^|/)(eclipse-temurin|temurin|openjdk|amazoncorretto|corretto|zulu[\w-]*|liberica[\w-]*|sapmachine|semeru[\w-]*|"
                          r"ibm-semeru-runtimes|graalvm[\w-]*|native-image[\w-]*|adoptopenjdk|ibmjava|jdk[\w-]*|jre[\w-]*|java)$")
JVM_APP_IMAGE_RE = re.compile(r"(?i)(?:^|/)(maven|gradle|tomcat|tomee|jetty|jenkins|keycloak|wildfly|payara|glassfish|sonarqube|nexus3|"
                              r"elasticsearch|logstash|kafka|cp-kafka|zookeeper|cassandra|solr|neo4j|flink|spark|hadoop|nifi|open-liberty|websphere-liberty)$")
TAG_EXACT_RE = re.compile(r"(?i)^(?:jdk-?|jre-?|openjdk-?|open-|v)?(\d+(?:\.\d+){1,4})(?:[_+]\d+(?:\.\d+)*)?(?![\d.])")
TAG_MAJOR_RE = re.compile(r"(?i)^(?:jdk-?|jre-?|openjdk-?|open-|v)?(\d{1,2})(?![\d.])")
TAG_EMBEDDED_MAJOR_RE = re.compile(r"(?i)(?:^|[-_.])(?:jdk|jre|java|openjdk|temurin|corretto|zulu|liberica|graalvm(?:-ce|-community)?|semeru)-?(\d{1,2})(?=$|[-_.])")
PKG_MAJOR_RE = re.compile(r"(?i)(?<![\w/\\])(?:openjdk-?(\d{1,2})(?:-(?:jdk|jre)[\w-]*|-headless)?|java-(\d{1,2})-(?:amazon-corretto|openjdk)[\w-]*|temurin-(\d{1,2})-(?:jdk|jre)|"
                          r"zulu-?(\d{1,2})-(?:jdk|jre)[\w-]*|bellsoft-java(\d{1,2})|adoptium-temurin-(\d{1,2}))(?![\w.])")
SDKMAN_RE = re.compile(r"(?im)^\s*java\s*=\s*([\w.+-]+)")
TOOL_VERSIONS_RE = re.compile(r"(?im)^\s*java\s+([\w.+-]+)")
MISE_RE = re.compile(r"""(?im)^\s*java\s*=\s*["']([\w.+-]+)["']""")
SYSPROP_RE = re.compile(r"(?im)^\s*java\.runtime\.version\s*=\s*([\w.+-]+)")
SETUP_JAVA_RE = re.compile(r"""(?im)^\s*(?:-\s*)?java-version:\s*["']?([^"'#\n]+?)["']?\s*(?:#.*)?$""")
TRAVIS_JDK_RE = re.compile(r"(?im)^\s*(?:-\s*)?(?:jdk:\s*)?(?:openjdk|oraclejdk)(\d{1,2})\s*$")
POM_LEVEL_RE = re.compile(r"<(maven\.compiler\.(?:release|source|target)|java\.version|release|jdk\.version|javaVersion)>\s*([\d.]+)\s*</")
GRADLE_LEVEL_RE = re.compile(r"(?:JavaLanguageVersion\.of\(\s*(\d{1,2})\s*\)|jvmToolchain\(\s*(\d{1,2})\s*\)|JavaVersion\.VERSION_(\d{1,2}|1_\d)|"
                             r"(?:sourceCompatibility|targetCompatibility|jvmTarget)\s*=?\s*['\"]?(1\.\d|\d{1,2})['\"]?)")
BUILD_SCOPE_RE = re.compile(r"(?i)(^|/)(\.devcontainer/|\.github/workflows/|\.gitlab-ci|Jenkinsfile|pom\.xml$|build\.gradle|settings\.gradle|gradle\.properties$|\.mvn/|"
                            r"\.travis\.yml$|azure-pipelines|bitbucket-pipelines|\.circleci/|cloudbuild\.ya?ml$|buildspec\.ya?ml$|\.drone\.yml$)")
SKIP_DIR_RE = re.compile(r"(^|/)(node_modules|vendor|target|build|dist|out|\.gradle|\.idea|third_party|bower_components|\.terraform)(/|$)")
SOURCE_EXT = (".java", ".kt", ".kts", ".scala", ".groovy", ".clj", ".jsp")
SOURCE_LANG_BY_EXT = {".java": "java", ".kt": "kotlin", ".kts": "kotlin", ".scala": "scala", ".groovy": "groovy", ".clj": "clojure", ".jsp": "java"}

VERDICT_ORDER = ["EXPOSED", "EXPLICITLY_ENABLED", "MITIGATED_FLAG", "UNVERIFIED_FLOATING", "UNVERIFIED_NO_PIN", "PATCHED", "NOT_JAVA", "ERROR"]
BLOCKING_VERDICTS = {"EXPOSED", "EXPLICITLY_ENABLED"}
STRICT_VERDICTS = BLOCKING_VERDICTS | {"UNVERIFIED_FLOATING", "UNVERIFIED_NO_PIN"}


# --------------------------------------------------------------------------------------------
# GitHub client (urllib; token from flag/env/gh; Link pagination; primary + secondary rate-limit handling)
# --------------------------------------------------------------------------------------------
class GitHubError(Exception):
    def __init__(self, status: int, message: str, url: str = ""):
        super().__init__(f"HTTP {status}: {message} ({url})")
        self.status = status
        self.message = message
        self.url = url


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
    def __init__(self, token: Optional[str], api_url: str, timeout: float = 30.0, max_wait: float = 300.0,
                 verbose: bool = False, code_search_interval: float = 6.5):
        self.token = token
        self.api_url = api_url.rstrip("/")
        self.timeout = timeout
        self.max_wait = max_wait
        self.verbose = verbose
        self.requests = 0
        self.lock = threading.Lock()
        self.rate: Dict[str, Dict[str, int]] = {}
        self._cs_lock = threading.Lock()
        self._cs_last = 0.0
        self._cs_interval = code_search_interval

    def log(self, msg: str) -> None:
        if self.verbose:
            sys.stderr.write(f"[gh] {msg}\n")

    def _bucket(self, url: str) -> str:
        path = urllib.parse.urlparse(url).path
        if path.startswith("/search/code"):
            return "code_search"
        if path.startswith("/search/"):
            return "search"
        return "core"

    def request(self, path: str, params: Optional[Dict[str, Any]] = None, accept: str = "application/vnd.github+json",
                allow_404: bool = False) -> Tuple[int, Dict[str, str], bytes]:
        url = path if path.startswith("http") else f"{self.api_url}/{path.lstrip('/')}"
        if params:
            sep = "&" if "?" in url else "?"
            url = url + sep + urllib.parse.urlencode(params, doseq=True)
        bucket = self._bucket(url)
        attempts = 0
        while True:
            attempts += 1
            if bucket == "code_search":
                with self._cs_lock:
                    wait = self._cs_last + self._cs_interval - time.monotonic()
                    if wait > 0:
                        time.sleep(wait)
                    self._cs_last = time.monotonic()
            req = urllib.request.Request(url, headers={
                "Accept": accept, "User-Agent": f"gh_j4s_scan/{TOOL_VERSION} (+{CVE})", "X-GitHub-Api-Version": "2022-11-28"})
            if self.token:
                req.add_header("Authorization", f"Bearer {self.token}")
            with self.lock:
                self.requests += 1
            self.log(f"GET {url}")
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    headers = {k.lower(): v for k, v in resp.headers.items()}
                    body = resp.read()
                    self._record_rate(bucket, headers)
                    return resp.status, headers, body
            except urllib.error.HTTPError as e:
                headers = {k.lower(): v for k, v in e.headers.items()} if e.headers else {}
                body = e.read() if e.fp else b""
                self._record_rate(bucket, headers)
                if e.code == 404 and allow_404:
                    return 404, headers, body
                if e.code in (403, 429) and attempts <= 3:
                    wait = self._rate_wait(headers)
                    if wait is not None:
                        if wait > self.max_wait:
                            raise GitHubError(e.code, f"rate limited; reset in {int(wait)}s exceeds --max-wait {int(self.max_wait)}s", url)
                        sys.stderr.write(f"[gh] rate limited on {bucket}; sleeping {int(wait) + 1}s\n")
                        time.sleep(wait + 1)
                        continue
                if e.code >= 500 and attempts <= 3:
                    time.sleep(2 * attempts)
                    continue
                msg = self._err_message(body) or e.reason
                raise GitHubError(e.code, str(msg), url)
            except (urllib.error.URLError, TimeoutError, OSError) as e:
                if attempts <= 3:
                    time.sleep(2 * attempts)
                    continue
                raise GitHubError(0, f"network error: {e}", url)

    @staticmethod
    def _err_message(body: bytes) -> str:
        try:
            return str(json.loads(body.decode("utf-8", "replace")).get("message", ""))
        except (ValueError, AttributeError):
            return ""

    def _record_rate(self, bucket: str, headers: Dict[str, str]) -> None:
        try:
            rem = int(headers.get("x-ratelimit-remaining", "-1"))
            lim = int(headers.get("x-ratelimit-limit", "-1"))
            reset = int(headers.get("x-ratelimit-reset", "0"))
        except ValueError:
            return
        if rem >= 0:
            with self.lock:
                self.rate[bucket] = {"remaining": rem, "limit": lim, "reset": reset}

    @staticmethod
    def _rate_wait(headers: Dict[str, str]) -> Optional[float]:
        if headers.get("retry-after"):
            try:
                return float(headers["retry-after"])
            except ValueError:
                pass
        if headers.get("x-ratelimit-remaining") == "0" and headers.get("x-ratelimit-reset"):
            try:
                return max(0.0, int(headers["x-ratelimit-reset"]) - time.time())
            except ValueError:
                pass
        return None

    def get_json(self, path: str, params: Optional[Dict[str, Any]] = None, allow_404: bool = False) -> Any:
        status, _, body = self.request(path, params, allow_404=allow_404)
        if status == 404:
            return None
        return json.loads(body.decode("utf-8", "replace")) if body else None

    def get_raw(self, path: str, params: Optional[Dict[str, Any]] = None) -> bytes:
        _, _, body = self.request(path, params, accept="application/vnd.github.raw+json")
        return body

    def paginate(self, path: str, params: Optional[Dict[str, Any]] = None, key: Optional[str] = None, limit: int = 0) -> Iterator[Any]:
        params = dict(params or {})
        params.setdefault("per_page", 100)
        url: Optional[str] = path
        count = 0
        first = True
        while url:
            status, headers, body = self.request(url, params if first else None)
            first = False
            data = json.loads(body.decode("utf-8", "replace")) if body else []
            items = data.get(key, []) if (key and isinstance(data, dict)) else data
            for item in items:
                yield item
                count += 1
                if limit and count >= limit:
                    return
            url = self._next_link(headers.get("link", ""))

    @staticmethod
    def _next_link(link: str) -> Optional[str]:
        for part in link.split(","):
            seg = part.strip().split(";")
            if len(seg) >= 2 and 'rel="next"' in seg[1]:
                return seg[0].strip().strip("<>")
        return None

    def rate_summary(self) -> str:
        parts = [f"requests={self.requests}"]
        for b, r in sorted(self.rate.items()):
            parts.append(f"{b}={r['remaining']}/{r['limit']}")
        return " ".join(parts)


# --------------------------------------------------------------------------------------------
# Findings
# --------------------------------------------------------------------------------------------
@dataclass
class VersionFinding:
    path: str
    line: int
    source: str          # dockerfile-from | image-ref | dockerfile-arg-env | setup-java | travis-jdk | sdkmanrc | java-version-file | tool-versions | mise | system-properties | package-manager | pom-language-level | gradle-language-level | generic
    raw: str
    kind: str            # EXACT | FLOATING | LANGUAGE_LEVEL | UNKNOWN
    status: str          # VULN_RANGE | PATCHED_OR_UNAFFECTED | FLOATING_PATCHABLE | UNKNOWN | LANGUAGE_LEVEL
    normalized: Optional[str]
    major: Optional[int]
    baseline: Optional[str]
    reason: str
    action: str
    scope: str           # runtime | build


@dataclass
class FlagFinding:
    path: str
    line: int
    state: str           # ACTIVE | CAPPED | EXPLICITLY_ENABLED | MENTION
    text: str
    scope: str           # runtime | build


@dataclass
class SourceHit:
    path: str
    line: int
    pattern_id: str      # J4S-SRC-01 | J4S-SRC-04
    snippet: str
    pre_auth_context: bool


@dataclass
class RepoResult:
    repo: str
    html_url: str = ""
    default_branch: str = ""
    archived: bool = False
    fork: bool = False
    private: bool = False
    pushed_at: str = ""
    primary_language: Optional[str] = None
    languages: Dict[str, int] = field(default_factory=dict)
    source_files: Dict[str, int] = field(default_factory=dict)
    build_files: List[str] = field(default_factory=list)
    tree_truncated: bool = False
    files_candidates: int = 0
    files_skipped: int = 0
    files_fetched: List[str] = field(default_factory=list)
    java_evidence: List[str] = field(default_factory=list)
    versions: List[VersionFinding] = field(default_factory=list)
    flags: List[FlagFinding] = field(default_factory=list)
    source_hits: List[SourceHit] = field(default_factory=list)
    source_mode: str = ""
    gate_ci: Dict[str, Any] = field(default_factory=lambda: {"github_workflows": [], "gitlab_ci": False})
    cve_mentions: List[str] = field(default_factory=list)
    tracking: Dict[str, Any] = field(default_factory=dict)
    is_java: bool = False
    verdict: str = "ERROR"
    reasons: List[str] = field(default_factory=list)
    actions: List[str] = field(default_factory=list)
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# --------------------------------------------------------------------------------------------
# File selection
# --------------------------------------------------------------------------------------------
def file_priority(path: str) -> int:
    """Lower = fetched first. Returns 99 for files we do not want."""
    p = path.lower()
    base = p.rsplit("/", 1)[-1]
    if SKIP_DIR_RE.search(p):
        return 99
    if base == "dockerfile" or base.startswith("dockerfile.") or base.endswith(".dockerfile") or base == "containerfile":
        return 0
    if base in (".java-version", ".sdkmanrc", ".tool-versions", "system.properties", ".mise.toml", "mise.toml", ".jabbarc"):
        return 1
    if base.startswith("docker-compose") or base.startswith("compose") and base.endswith((".yml", ".yaml")):
        return 2
    if p.startswith(".github/workflows/") and base.endswith((".yml", ".yaml")):
        return 3
    if base in (".gitlab-ci.yml", ".travis.yml", "jenkinsfile", "procfile", "jvm.options", "jvm.config", "azure-pipelines.yml", "bitbucket-pipelines.yml"):
        return 3
    if base.endswith((".yml", ".yaml")):
        return 4 if re.search(r"(^|/)(k8s|kube|kubernetes|deploy|deployment|manifests?|helm|charts?|templates|kustomize|overlays|base|infra|ops|values)", p) else 6
    if base in ("pom.xml", "build.gradle", "build.gradle.kts", "gradle.properties", "settings.gradle", "settings.gradle.kts"):
        return 5
    if base.endswith((".service", ".vmoptions", ".tf", ".tfvars", ".hcl", ".nomad")):
        return 5
    if base in ("setenv.sh", "entrypoint.sh", "docker-entrypoint.sh", "run.sh", "start.sh", "startup.sh", "catalina.sh") or re.match(r"(entrypoint|run|start|launch)[\w-]*\.sh$", base):
        return 5
    if base.endswith(".sh") and re.search(r"(^|/)(bin|scripts?|docker|deploy)/", p):
        return 7
    if base.startswith(".env"):
        return 7
    if base.endswith(".json") and re.search(r"(task|taskdef|container|ecs|appspec)", base):
        return 7
    if base.endswith(".properties") and re.search(r"(application|bootstrap|catalina|jvm|wrapper|gradle)", base):
        return 8
    return 99


DEV_PIN_FILES = (".java-version", ".sdkmanrc", ".tool-versions", ".mise.toml", "mise.toml", ".jabbarc")
DOCS_SCOPE_RE = re.compile(r"(?i)(^|/)(docs?|documentation|examples?|samples?|demo)/")


def scope_for(path: str) -> str:
    """runtime | build | dev | docs. Only runtime findings drive the EXPOSED / MITIGATED verdicts."""
    base = path.rsplit("/", 1)[-1].lower()
    if base in DEV_PIN_FILES:
        return "dev"
    if BUILD_SCOPE_RE.search(path):
        return "build"
    if DOCS_SCOPE_RE.search(path):
        return "docs"
    return "runtime"


def is_build_scope(path: str) -> bool:
    return scope_for(path) != "runtime"


# --------------------------------------------------------------------------------------------
# Content analysis
# --------------------------------------------------------------------------------------------
def parse_image_ref(ref: str) -> Tuple[str, Optional[str], Optional[str]]:
    digest = None
    if "@" in ref:
        ref, digest = ref.split("@", 1)
    name, tag = ref, None
    i = ref.rfind(":")
    if i > ref.rfind("/"):
        name, tag = ref[:i], ref[i + 1:]
    return name, tag, digest


def classify_image(name: str, tag: Optional[str], digest: Optional[str]) -> Optional[Dict[str, Any]]:
    """Return a classification dict (plus kind) for a JDK or JVM-app image reference, or None if not JVM-related."""
    is_jdk = bool(JDK_IMAGE_RE.search(name))
    is_app = bool(JVM_APP_IMAGE_RE.search(name))
    if not (is_jdk or is_app):
        return None
    tag = tag or ("latest" if not digest else "")
    if is_jdk:
        m = TAG_EXACT_RE.match(tag)
        if m:
            d = classify_exact(m.group(1))
            d["kind"] = "EXACT"
            if name.endswith("openjdk") and "/" not in name.strip("/") and d["major"] in (18, 19, 20):
                d["reason"] += "; the deprecated `openjdk` image only shipped EA/EOL builds here"
            return d
        m = TAG_MAJOR_RE.match(tag)
        if m and int(m.group(1)) < 8:
            m = re.match(r"(?i)^\d+[-_](\d{1,2})(?![\d.])", tag)
        if m:
            d = classify_major(int(m.group(1)), tag)
            d["kind"] = "FLOATING"
            if name.rstrip("/").endswith("openjdk") and d["major"] == 17:
                d["reason"] = "Deprecated `openjdk:17` image resolves to 17.0.2, which predates the affected intrinsic; still migrate off this image"
                d["status"] = "PATCHED_OR_UNAFFECTED"
            return d
    m = TAG_EMBEDDED_MAJOR_RE.search(tag)
    if m:
        d = classify_major(int(m.group(1)), tag)
        d["kind"] = "FLOATING"
        return d
    if is_jdk:
        d = dict(normalized=None, major=None, status="UNKNOWN", baseline=None, kind="UNKNOWN",
                 reason=f"JDK image tag `{tag or '(digest only)'}` does not encode a version; resolve the digest", action="Inspect the image: docker run --rm IMAGE java -version")
        return d
    return None


def analyze_dockerfile(path: str, text: str, out: RepoResult) -> None:
    scope = scope_for(path)
    variables: Dict[str, str] = {}
    aliases: set = set()
    for n, line in enumerate(text.splitlines(), 1):
        m = ARG_ENV_RE.match(line)
        if m:
            variables[m.group(1)] = m.group(2).strip("\"'")
    for n, line in enumerate(text.splitlines(), 1):
        m = FROM_RE.match(line)
        if not m:
            # package managers and download URLs on java-ish lines
            _analyze_java_line(path, n, line, scope, out, source="package-manager")
            continue
        ref = _expand_vars(m.group(1), variables)
        if m.group(2):
            aliases.add(m.group(2).lower())
        if ref.lower() in aliases or ref.lower() == "scratch":
            continue
        name, tag, digest = parse_image_ref(ref)
        d = classify_image(name, tag, digest)
        if d:
            out.java_evidence.append(f"{path}:{n} FROM {ref}")
            out.versions.append(VersionFinding(path, n, "dockerfile-from", ref, d["kind"], d["status"], d.get("normalized"), d.get("major"),
                                               d.get("baseline"), d["reason"], d["action"], scope))


def _expand_vars(s: str, variables: Dict[str, str]) -> str:
    def repl(m: re.Match) -> str:
        name = m.group(1) or m.group(2)
        default = m.group(3)
        return variables.get(name, default if default is not None else m.group(0))
    return re.sub(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::[-+]([^}]*))?\}|\$([A-Za-z_][A-Za-z0-9_]*)",
                  lambda m: variables.get(m.group(1) or m.group(3), (m.group(2) if m.group(2) is not None else m.group(0))), s)


def _analyze_java_line(path: str, n: int, line: str, scope: str, out: RepoResult, source: str = "generic") -> None:
    """Versions on lines that mention Java: ARG/ENV JAVA_VERSION=..., apt/apk packages, download URLs."""
    if not JAVA_LINE_RE.search(line):
        return
    em = ENV_MAJOR_RE.search(line)
    if em and not VERSION_TOKEN_RE.search(line):
        raw = f"{em.group(1).upper()}={em.group(2)}"
        d = classify_major(int(em.group(2)), raw)
        out.versions.append(VersionFinding(path, n, "dockerfile-arg-env", raw, "FLOATING", d["status"], d["normalized"], d["major"],
                                           d["baseline"], d["reason"], d["action"], scope))
        return
    if JAVA8_PERF_RE.search(line):
        d = classify_exact("8u511b33-perf")
        out.versions.append(VersionFinding(path, n, source, "8u511b33-perf", "EXACT", d["status"], d["normalized"], 8, None, d["reason"], d["action"], scope))
        return
    for vm in VERSION_TOKEN_RE.finditer(line):
        ver = vm.group(0)
        parsed = parse_version(ver)
        if not parsed or parsed[0] < 8 or parsed[0] > 40:
            continue
        # skip obvious non-JDK versions adjacent to other product names (python:3.12, alpine 3.20, maven 3.9.9, gradle 8.10)
        pre = line[max(0, vm.start() - 24):vm.start()].lower()
        if re.search(r"(python|alpine|ubuntu|debian|node|golang|maven|gradle|tomcat|jetty|kafka|elasticsearch|nginx|redis|postgres|mysql)\S*\s*[:=/_-]?\s*$", pre):
            continue
        d = classify_exact(ver)
        out.versions.append(VersionFinding(path, n, source if source != "package-manager" else "generic", ver, "EXACT", d["status"], d["normalized"],
                                           d["major"], d["baseline"], d["reason"], d["action"], scope))
        return
    pm = PKG_MAJOR_RE.search(line)
    if pm:
        major = int(next(g for g in pm.groups() if g))
        d = classify_major(major, pm.group(0))
        out.versions.append(VersionFinding(path, n, "package-manager", pm.group(0), "FLOATING", d["status"], d["normalized"], major,
                                           d["baseline"], d["reason"] + " (distro package; refreshed by rebuild/upgrade)", d["action"], scope))


def analyze_yaml(path: str, text: str, out: RepoResult) -> None:
    scope = scope_for(path)
    lines = text.splitlines()
    is_workflow = path.lower().startswith(".github/workflows/")
    for n, line in enumerate(lines, 1):
        m = IMAGE_LINE_RE.match(line)
        if m and not line.lstrip().lower().startswith("from"):
            ref = m.group(1)
            if "${" in ref or "{{" in ref:
                pass
            name, tag, digest = parse_image_ref(ref)
            d = classify_image(name, tag, digest)
            if d:
                out.java_evidence.append(f"{path}:{n} image {ref}")
                out.versions.append(VersionFinding(path, n, "image-ref", ref, d["kind"], d["status"], d.get("normalized"), d.get("major"),
                                                   d.get("baseline"), d["reason"], d["action"], scope))
            continue
        tm = TRAVIS_JDK_RE.match(line)
        if tm and path.lower().endswith(".travis.yml"):
            d = classify_major(int(tm.group(1)), line.strip())
            out.versions.append(VersionFinding(path, n, "travis-jdk", line.strip(), "FLOATING", d["status"], d["normalized"], d["major"], d["baseline"], d["reason"], d["action"], "build"))
            continue
        _analyze_java_line(path, n, line, scope, out)
    if is_workflow or "setup-java" in text:
        _analyze_setup_java(path, text, out)


def _resolve_matrix(text: str, key: str) -> List[str]:
    vals: List[str] = []
    m = re.search(r"(?m)^\s*%s:\s*\[([^\]]*)\]" % re.escape(key), text)
    if m:
        vals = [v.strip().strip("\"'") for v in m.group(1).split(",") if v.strip()]
    else:
        m = re.search(r"(?m)^(\s*)%s:\s*\n((?:\1\s+-\s*[^\n]+\n?)+)" % re.escape(key), text)
        if m:
            vals = [re.sub(r"^\s*-\s*", "", ln).strip().strip("\"'") for ln in m.group(2).splitlines() if ln.strip()]
    return vals


def _analyze_setup_java(path: str, text: str, out: RepoResult) -> None:
    for m in SETUP_JAVA_RE.finditer(text):
        n = text.count("\n", 0, m.start()) + 1
        val = m.group(1).strip()
        candidates: List[str] = []
        mm = re.match(r"\$\{\{\s*matrix\.([\w.-]+)\s*\}\}", val)
        if mm:
            candidates = _resolve_matrix(text, mm.group(1)) or _resolve_matrix(text, mm.group(1).replace("-", "_"))
            if not candidates:
                out.versions.append(VersionFinding(path, n, "setup-java", val, "UNKNOWN", "UNKNOWN", None, None, None,
                                                   "Matrix value could not be resolved from this file", "Inspect the workflow matrix", "build"))
                continue
        elif val == "|" or val == "":
            after = text[m.end():].splitlines()[:8]
            candidates = [ln.strip() for ln in after if re.match(r"^\s+\d", ln)]
        else:
            candidates = [val]
        for c in candidates:
            c = c.strip().strip("\"'")
            if re.fullmatch(r"\d{1,2}", c):
                d = classify_major(int(c), c)
                kind = "FLOATING"
            elif re.fullmatch(r"\d{1,2}(?:\.\d+)*\.x", c):
                d = classify_major(int(c.split(".")[0]), c)
                kind = "FLOATING"
            elif re.fullmatch(r"\d+(?:\.\d+){1,4}(?:[_+]\d+)?", c):
                d = classify_exact(c)
                kind = "EXACT"
            elif re.fullmatch(r"\d{1,2}-ea", c):
                d = classify_major(int(c.split("-")[0]), c)
                kind = "FLOATING"
            else:
                continue
            out.java_evidence.append(f"{path}:{n} setup-java {c}")
            out.versions.append(VersionFinding(path, n, "setup-java", c, kind, d["status"], d["normalized"], d["major"], d["baseline"],
                                               d["reason"] + " (CI runner JDK, not the deployed runtime)", d["action"], "build"))


def analyze_pin_file(path: str, text: str, out: RepoResult) -> None:
    base = path.rsplit("/", 1)[-1].lower()
    raw: Optional[str] = None
    source = "generic"
    if base == ".java-version":
        raw, source = text.strip().splitlines()[0].strip() if text.strip() else None, "java-version-file"
    elif base == ".sdkmanrc":
        m = SDKMAN_RE.search(text)
        raw, source = (m.group(1) if m else None), "sdkmanrc"
    elif base == ".tool-versions":
        m = TOOL_VERSIONS_RE.search(text)
        raw, source = (m.group(1) if m else None), "tool-versions"
    elif base in (".mise.toml", "mise.toml"):
        m = MISE_RE.search(text)
        raw, source = (m.group(1) if m else None), "mise"
    elif base == "system.properties":
        m = SYSPROP_RE.search(text)
        raw, source = (m.group(1) if m else None), "system-properties"
    elif base == ".jabbarc":
        raw, source = text.strip().strip("\"'") or None, "jabbarc"
    if not raw:
        return
    out.java_evidence.append(f"{path}:1 {source} {raw}")
    ver = re.sub(r"^(?:temurin|tem|adoptopenjdk|adopt|openjdk|open|corretto|amzn|zulu|liberica|librca|sapmachine|sapmchn|graalvm(?:-ce|-community)?|graalce|semeru|sem|oracle|microsoft|ms)[-_]?", "", raw, flags=re.I)
    ver = re.sub(r"[-_](?:tem|amzn|zulu|librca|sapmchn|graalce|sem|open|oracle|ms|hs|jdk|jre)$", "", ver, flags=re.I)
    scope = scope_for(path)  # dev for .sdkmanrc/.java-version/..., runtime for system.properties (Heroku)
    if "zulu" in raw.lower() and re.match(r"^\d{2}\.\d{2}\.\d{2}$", ver):
        out.versions.append(VersionFinding(path, 1, source, raw, "UNKNOWN", "UNKNOWN", None, None, None, "Zulu uses its own version numbering; map to the OpenJDK version", "Check the Azul release notes", scope))
        return
    if re.fullmatch(r"\d{1,2}", ver):
        d = classify_major(int(ver), raw)
        kind = "FLOATING"
    else:
        d = classify_exact(ver)
        kind = "EXACT" if d["status"] != "UNKNOWN" else "UNKNOWN"
    out.versions.append(VersionFinding(path, 1, source, raw, kind, d["status"], d["normalized"], d["major"], d["baseline"], d["reason"], d["action"], scope))


def analyze_build_file(path: str, text: str, out: RepoResult) -> None:
    base = path.rsplit("/", 1)[-1].lower()
    out.java_evidence.append(f"{path} build file")
    if base == "pom.xml":
        for m in POM_LEVEL_RE.finditer(text):
            n = text.count("\n", 0, m.start()) + 1
            parsed = parse_version(m.group(2))
            if parsed:
                out.versions.append(VersionFinding(path, n, "pom-language-level", f"<{m.group(1)}>{m.group(2)}", "LANGUAGE_LEVEL", "LANGUAGE_LEVEL", m.group(2), parsed[0], baseline_for(parsed[0]),
                                                   f"Compiler level {m.group(2)} says which JDK line runs it, not the patch level", "Find the runtime pin (Dockerfile, manifest, host) for this line", "build"))
    elif base.startswith("build.gradle") or base.startswith("settings.gradle"):
        for m in GRADLE_LEVEL_RE.finditer(text):
            n = text.count("\n", 0, m.start()) + 1
            tok = next(g for g in m.groups() if g)
            tok = tok.replace("1_", "1.")
            parsed = parse_version(tok)
            if parsed:
                out.versions.append(VersionFinding(path, n, "gradle-language-level", m.group(0).strip(), "LANGUAGE_LEVEL", "LANGUAGE_LEVEL", tok, parsed[0], baseline_for(parsed[0]),
                                                   f"Toolchain/compatibility level {tok} says which JDK line runs it, not the patch level", "Find the runtime pin for this line", "build"))


def analyze_flags_and_mentions(path: str, text: str, out: RepoResult) -> None:
    scope = scope_for(path)
    for n, line in enumerate(text.splitlines(), 1):
        if FLAG_REENABLE_RE.search(line):
            out.flags.append(FlagFinding(path, n, "EXPLICITLY_ENABLED", line.strip()[:200], scope))
        elif FLAG_ACTIVE_RE.search(line):
            out.flags.append(FlagFinding(path, n, "ACTIVE", line.strip()[:200], scope))
        elif FLAG_CAP_RE.search(line):
            out.flags.append(FlagFinding(path, n, "CAPPED", line.strip()[:200], scope))
        elif FLAG_MENTION_RE.search(line):
            out.flags.append(FlagFinding(path, n, "MENTION", line.strip()[:200], scope))
        if CVE_MENTION_RE.search(line):
            out.cve_mentions.append(f"{path}:{n}")
    ev = sorted({m.group(1).lower() for m in JAVA_EVIDENCE_RE.finditer(text)})
    if ev:
        out.java_evidence.append(f"{path} mentions {', '.join(ev[:6])}")
    if path.lower().startswith(".github/workflows/") and re.search(r"gate_cve_2026_114938|CVE-2026-114938|java4shell|j4s", text, re.I):
        out.gate_ci["github_workflows"].append(path)
    if path.lower() == ".gitlab-ci.yml" and re.search(r"gate_cve_2026_114938|CVE-2026-114938|java4shell|j4s", text, re.I):
        out.gate_ci["gitlab_ci"] = True


def analyze_file(path: str, text: str, out: RepoResult) -> None:
    base = path.rsplit("/", 1)[-1].lower()
    analyze_flags_and_mentions(path, text, out)
    if base == "dockerfile" or base.startswith("dockerfile.") or base.endswith(".dockerfile") or base == "containerfile":
        analyze_dockerfile(path, text, out)
    elif base.endswith((".yml", ".yaml")):
        analyze_yaml(path, text, out)
    elif base in (".java-version", ".sdkmanrc", ".tool-versions", "system.properties", ".mise.toml", "mise.toml", ".jabbarc"):
        analyze_pin_file(path, text, out)
    elif base in ("pom.xml", "build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts"):
        analyze_build_file(path, text, out)
    else:
        scope = scope_for(path)
        for n, line in enumerate(text.splitlines(), 1):
            m = IMAGE_LINE_RE.match(line)
            if m:
                name, tag, digest = parse_image_ref(m.group(1))
                d = classify_image(name, tag, digest)
                if d:
                    out.java_evidence.append(f"{path}:{n} image {m.group(1)}")
                    out.versions.append(VersionFinding(path, n, "image-ref", m.group(1), d["kind"], d["status"], d.get("normalized"), d.get("major"), d.get("baseline"), d["reason"], d["action"], scope))
                    continue
            _analyze_java_line(path, n, line, scope, out)


def analyze_source(path: str, text: str, out: RepoResult) -> None:
    if "Base64" not in text and "Decoder" not in text:      # J4S-SRC-05 prefilter
        return
    for n, line in enumerate(text.splitlines(), 1):
        dec = DECODER_RE.search(line)
        auth = AUTH_CONTEXT_RE.search(line)
        if dec:
            out.source_hits.append(SourceHit(path, n, "J4S-SRC-01", line.strip()[:200], bool(auth)))
        elif auth:
            out.source_hits.append(SourceHit(path, n, "J4S-SRC-04", line.strip()[:200], True))


# --------------------------------------------------------------------------------------------
# Verdict
# --------------------------------------------------------------------------------------------
def dedupe_versions(versions: List[VersionFinding]) -> List[VersionFinding]:
    """Keep the first occurrence of (path, source, normalized-or-raw, status); Dockerfiles repeat the same version many times."""
    seen: set = set()
    out: List[VersionFinding] = []
    exact_majors = {(v.path, v.major) for v in versions if v.kind == "EXACT" and v.major is not None}
    for v in versions:
        if v.kind == "FLOATING" and v.source == "package-manager" and (v.path, v.major) in exact_majors:
            continue  # "openjdk-21" in a path/package name next to an exact pin of the same line adds nothing
        key = (v.path, v.source, v.normalized or v.raw, v.status)
        if key in seen:
            continue
        seen.add(key)
        out.append(v)
    return out


def decide(r: RepoResult) -> None:
    r.versions = dedupe_versions(r.versions)
    r.java_evidence = sorted(set(r.java_evidence))
    r.cve_mentions = sorted(set(r.cve_mentions))
    src_total = sum(r.source_files.values())
    lang_java = (r.primary_language or "").lower() in JVM_LANGUAGES or any(k.lower() in JVM_LANGUAGES for k in r.languages)
    r.is_java = bool(lang_java or src_total or r.build_files or r.versions or any(f.state in ("ACTIVE", "CAPPED", "EXPLICITLY_ENABLED") for f in r.flags))
    if not r.is_java and not r.java_evidence:
        r.verdict = "NOT_JAVA"
        r.reasons = ["No JVM language, build file, JDK pin, or JVM flag found on the default branch"]
        r.actions = []
        return
    runtime_versions = [v for v in r.versions if v.scope == "runtime" and v.kind in ("EXACT", "FLOATING")]
    build_versions = [v for v in r.versions if v.scope != "runtime" and v.kind in ("EXACT", "FLOATING")]
    runtime_flags = [f for f in r.flags if f.scope == "runtime"]
    reenabled = [f for f in r.flags if f.state == "EXPLICITLY_ENABLED"]
    mitigated = [f for f in runtime_flags if f.state in ("ACTIVE", "CAPPED")]
    vuln = [v for v in runtime_versions if v.status == "VULN_RANGE"]
    floating = [v for v in runtime_versions if v.status == "FLOATING_PATCHABLE"]
    patched = [v for v in runtime_versions if v.status == "PATCHED_OR_UNAFFECTED"]
    unknown = [v for v in runtime_versions if v.status == "UNKNOWN"]
    reasons: List[str] = []
    actions: List[str] = []

    for v in vuln:
        reasons.append(f"{v.path}:{v.line} pins {v.raw} -> {v.status} ({v.reason})")
    for v in floating:
        reasons.append(f"{v.path}:{v.line} floating pin {v.raw} -> verify resolved build")
    for f in mitigated:
        reasons.append(f"{f.path}:{f.line} mitigation {f.state}: {f.text[:80]}")
    for f in reenabled:
        reasons.append(f"{f.path}:{f.line} intrinsic explicitly re-enabled (J4S-FLAG-04)")

    if reenabled and (vuln or floating or not patched):
        r.verdict = "EXPLICITLY_ENABLED"
        actions.append("Remove -XX:+UseBASE64Intrinsics (J4S-FLAG-04); it defeats the mitigation and any gate")
    elif vuln and not mitigated:
        r.verdict = "EXPOSED"
    elif vuln and mitigated:
        r.verdict = "MITIGATED_FLAG"
        actions.append("Mitigation flag present but the JDK is still vulnerable: schedule the upgrade and keep the flag until then")
    elif mitigated:
        r.verdict = "MITIGATED_FLAG"
        if not runtime_versions:
            reasons.append("No runtime JDK pin found; verdict rests on the flag alone")
    elif floating or unknown:
        r.verdict = "UNVERIFIED_FLOATING"
        actions.append("Resolve the floating/unknown image or package to an exact version (docker run IMAGE java -version; image digest created after 2026-11-17 patch release)")
    elif patched:
        r.verdict = "PATCHED"
        reasons.append("; ".join(f"{v.path}:{v.line} {v.raw} -> {v.status}" for v in patched[:4]))
    else:
        r.verdict = "UNVERIFIED_NO_PIN"
        reasons.append("Java workload without a runtime JDK pin in this repository (runtime defined elsewhere: platform image, host JDK, Helm values repo)")
        actions.append("Locate where this code runs and audit that host/image with scripts/verify_java4shell_runtime.sh or helpers/j4s_k8s.sh")

    if r.verdict in ("EXPOSED", "EXPLICITLY_ENABLED"):
        actions.insert(0, "Set JAVA_TOOL_OPTIONS=-XX:-UseBASE64Intrinsics in the runtime (Dockerfile ENV / manifest env / service unit) now")
        targets = sorted({v.baseline for v in vuln if v.baseline})
        if targets:
            actions.append(f"Upgrade the pinned JDK to {', '.join(targets)} or newer (vendor equivalent)")
        eol = sorted({str(v.major) for v in vuln if v.major in EOL_VULNERABLE_MAJORS})
        if eol:
            actions.append(f"JDK {', '.join(eol)} is EOL with no patch: migrate to 21 or 25")
    if build_versions and not runtime_versions:
        bv = sorted({f"{v.raw} ({v.scope})" for v in build_versions})[:4]
        reasons.append(f"Non-runtime JDK pins only ({', '.join(bv)}); CI runners, developer pins and docs are not the production runtime")
    other_vuln = [v for v in build_versions if v.status == "VULN_RANGE"]
    if other_vuln:
        ov = sorted({f"{v.path}:{v.line} {v.raw}" for v in other_vuln})[:4]
        reasons.append(f"Vulnerable JDK in {', '.join(sorted({v.scope for v in other_vuln}))} scope: {'; '.join(ov)}")
        actions.append("Update developer/CI JDK pins (" + ", ".join(sorted({v.raw for v in other_vuln})[:3]) + ") to the patched baseline as well")
    if r.source_hits:
        pre = sum(1 for h in r.source_hits if h.pre_auth_context)
        reasons.append(f"{len(r.source_hits)} Base64 decode call sites in source, {pre} with auth/JWT/SAML context (J4S-SRC-01/04)")
        if pre and r.verdict in ("EXPOSED", "UNVERIFIED_FLOATING", "UNVERIFIED_NO_PIN", "EXPLICITLY_ENABLED"):
            actions.append("Pre-authentication Base64 decoding present: validate padding before decode and prioritise this service")
    if not r.gate_ci["github_workflows"] and not r.gate_ci["gitlab_ci"] and r.verdict not in ("NOT_JAVA", "PATCHED"):
        actions.append("No CI gate referencing CVE-2026-114938 found: add scripts/gate_cve_2026_114938.py to the pipeline (runbook §7.2)")
    if r.files_skipped:
        reasons.append(f"{r.files_skipped} of {r.files_candidates} candidate files not fetched (--max-files {len(r.files_fetched) if not r.source_mode else 'cap'}); raise --max-files for a complete verdict")
        if r.verdict == "PATCHED":
            r.verdict = "UNVERIFIED_FLOATING"
            actions.insert(0, "Verdict downgraded from PATCHED because not every manifest was inspected; rerun with a higher --max-files")
    if r.tree_truncated:
        reasons.append("Git tree listing was truncated by GitHub (very large repository); some files were not considered")
    if r.archived:
        reasons.append("Repository is archived")
    r.reasons = reasons
    r.actions = actions


# --------------------------------------------------------------------------------------------
# Per-repo scan
# --------------------------------------------------------------------------------------------
def scan_repo(gh: GitHub, full_name: str, opts: argparse.Namespace, meta: Optional[Dict[str, Any]] = None) -> RepoResult:
    r = RepoResult(repo=full_name)
    try:
        info = meta or gh.get_json(f"repos/{full_name}")
        if not info:
            raise GitHubError(404, "repository not found or not accessible")
        r.html_url = info.get("html_url", "")
        r.default_branch = info.get("default_branch", "") or "HEAD"
        r.archived = bool(info.get("archived"))
        r.fork = bool(info.get("fork"))
        r.private = bool(info.get("private"))
        r.pushed_at = info.get("pushed_at", "") or ""
        r.primary_language = info.get("language")
        if opts.languages_api:
            langs = gh.get_json(f"repos/{full_name}/languages", allow_404=True) or {}
            r.languages = {k: int(v) for k, v in langs.items()}
        if info.get("size") == 0:
            r.verdict = "NOT_JAVA"
            r.reasons = ["Empty repository"]
            return r

        tree = gh.get_json(f"repos/{full_name}/git/trees/{urllib.parse.quote(r.default_branch, safe='')}", {"recursive": "1"}, allow_404=True)
        if not tree:
            raise GitHubError(404, f"tree for {r.default_branch} not found (empty repository?)")
        r.tree_truncated = bool(tree.get("truncated"))
        blobs = [e for e in tree.get("tree", []) if e.get("type") == "blob"]
        candidates: List[Tuple[int, Dict[str, Any]]] = []
        source_blobs: List[Dict[str, Any]] = []
        for e in blobs:
            p = e["path"]
            lower = p.lower()
            if lower.endswith(SOURCE_EXT) and not SKIP_DIR_RE.search(lower):
                lang = SOURCE_LANG_BY_EXT[next(x for x in SOURCE_EXT if lower.endswith(x))]
                r.source_files[lang] = r.source_files.get(lang, 0) + 1
                source_blobs.append(e)
            base = lower.rsplit("/", 1)[-1]
            if base in ("pom.xml", "build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts", "build.sbt", "project.clj", "deps.edn") or lower.endswith((".jar", ".war", ".ear")):
                r.build_files.append(p)
            pr = file_priority(p)
            if pr < 99 and int(e.get("size") or 0) <= opts.max_file_size:
                candidates.append((pr, e))
        candidates.sort(key=lambda t: (t[0], t[1]["path"]))
        selected = [e for _, e in candidates[: opts.max_files]]
        r.files_candidates = len(candidates)
        r.files_skipped = max(0, len(candidates) - len(selected))
        r.build_files = sorted(r.build_files)[:50]

        def fetch(e: Dict[str, Any]) -> Tuple[str, Optional[str]]:
            try:
                raw = gh.get_raw(f"repos/{full_name}/git/blobs/{e['sha']}")
                return e["path"], raw.decode("utf-8", "replace")
            except GitHubError as ex:
                gh.log(f"{full_name}:{e['path']} fetch failed: {ex}")
                return e["path"], None

        with concurrent.futures.ThreadPoolExecutor(max_workers=opts.file_workers) as pool:
            for path, text in pool.map(fetch, selected):
                if text is None:
                    continue
                r.files_fetched.append(path)
                analyze_file(path, text, r)

        if opts.source and source_blobs:
            _scan_source(gh, full_name, r, source_blobs, opts)
        if opts.track_issues:
            _track_issues(gh, full_name, r)
        decide(r)
    except GitHubError as e:
        r.error = str(e)
        r.verdict = "ERROR"
        r.reasons = [str(e)]
    except Exception as e:  # keep one bad repo from killing the run
        r.error = f"{type(e).__name__}: {e}"
        r.verdict = "ERROR"
        r.reasons = [r.error]
    return r


def _scan_source(gh: GitHub, full_name: str, r: RepoResult, source_blobs: List[Dict[str, Any]], opts: argparse.Namespace) -> None:
    by_path = {e["path"]: e for e in source_blobs}
    picked: List[str] = []
    mode = opts.source_mode
    if mode in ("search", "both") and gh.token:
        try:
            for item in gh.paginate("search/code", {"q": f"Base64 repo:{full_name}", "per_page": 100}, key="items", limit=100):
                p = item.get("path", "")
                if p in by_path and p not in picked:
                    picked.append(p)
            r.source_mode = "code-search"
        except GitHubError as e:
            gh.log(f"{full_name}: code search unavailable ({e.message}); falling back to path heuristics")
            mode = "paths"
    if mode in ("paths", "both") or (not picked and mode == "search"):
        heur = sorted((p for p in by_path if AUTHY_PATH_RE.search(p)), key=lambda p: (0 if re.search(r"(?i)base64|decod", p) else 1, p))
        for p in heur:
            if p not in picked:
                picked.append(p)
        r.source_mode = (r.source_mode + "+paths").lstrip("+") if r.source_mode else "paths"
    picked.sort(key=lambda p: (0 if AUTHY_PATH_RE.search(p) else 1, p))
    picked = picked[: opts.max_source_files]

    def fetch(p: str) -> Tuple[str, Optional[str]]:
        e = by_path[p]
        if int(e.get("size") or 0) > opts.max_file_size:
            return p, None
        try:
            return p, gh.get_raw(f"repos/{full_name}/git/blobs/{e['sha']}").decode("utf-8", "replace")
        except GitHubError:
            return p, None

    with concurrent.futures.ThreadPoolExecutor(max_workers=opts.file_workers) as pool:
        for p, text in pool.map(fetch, picked):
            if text is not None:
                r.files_fetched.append(p)
                analyze_source(p, text, r)


def _track_issues(gh: GitHub, full_name: str, r: RepoResult) -> None:
    try:
        data = gh.get_json("search/issues", {"q": f"repo:{full_name} CVE-2026-114938 OR Java4Shell", "per_page": 20})
        items = (data or {}).get("items", [])
        r.tracking = {
            "issues": [i["html_url"] for i in items if "pull_request" not in i],
            "pull_requests": [i["html_url"] for i in items if "pull_request" in i],
            "open": sum(1 for i in items if i.get("state") == "open"),
        }
    except GitHubError as e:
        r.tracking = {"error": e.message}


# --------------------------------------------------------------------------------------------
# Repository discovery
# --------------------------------------------------------------------------------------------
def parse_repo_arg(s: str) -> Optional[str]:
    s = s.strip()
    if not s or s.startswith("#"):
        return None
    m = re.match(r"^(?:https?://[^/]+/|git@[^:]+:)?([\w.-]+)/([\w.-]+?)(?:\.git)?/?$", s)
    return f"{m.group(1)}/{m.group(2)}" if m else None


def discover(gh: GitHub, opts: argparse.Namespace) -> List[Dict[str, Any]]:
    repos: List[Dict[str, Any]] = []
    if opts.me:
        repos.extend(gh.paginate("user/repos", {"affiliation": opts.affiliation, "sort": "pushed"}, limit=opts.limit))
    for u in opts.user:
        me = None
        if gh.token:
            try:
                me = (gh.get_json("user") or {}).get("login")
            except GitHubError:
                me = None
        if me and me.lower() == u.lower():
            repos.extend(gh.paginate("user/repos", {"affiliation": "owner", "sort": "pushed"}, limit=opts.limit))
        else:
            repos.extend(gh.paginate(f"users/{u}/repos", {"type": "owner", "sort": "pushed"}, limit=opts.limit))
    for o in opts.org:
        repos.extend(gh.paginate(f"orgs/{o}/repos", {"type": opts.org_type, "sort": "pushed"}, limit=opts.limit))
    out: List[Dict[str, Any]] = []
    seen: set = set()
    langs = {l.strip().lower() for l in opts.language.split(",") if l.strip()} if opts.language else set()
    name_re = re.compile(opts.name_regex) if opts.name_regex else None
    topics = {t.lower() for t in opts.topic}
    for repo in repos:
        fn = repo["full_name"]
        if fn in seen:
            continue
        seen.add(fn)
        if repo.get("archived") and not opts.include_archived:
            continue
        if repo.get("fork") and not opts.include_forks:
            continue
        if opts.visibility and (repo.get("visibility") or ("private" if repo.get("private") else "public")) != opts.visibility:
            continue
        if opts.pushed_since and (repo.get("pushed_at") or "") < opts.pushed_since:
            continue
        if name_re and not name_re.search(repo["name"]):
            continue
        if topics and not topics & {t.lower() for t in repo.get("topics", [])}:
            continue
        if langs and not opts.all_languages:
            primary = (repo.get("language") or "").lower()
            if primary not in langs:
                if opts.deep_languages:
                    try:
                        rl = gh.get_json(f"repos/{fn}/languages", allow_404=True) or {}
                    except GitHubError:
                        rl = {}
                    repo["_languages"] = rl
                    if not {k.lower() for k in rl} & langs:
                        continue
                else:
                    continue
        out.append(repo)
    return out


# --------------------------------------------------------------------------------------------
# Output
# --------------------------------------------------------------------------------------------
def summarize(results: List[RepoResult]) -> Dict[str, Any]:
    counts = {v: 0 for v in VERDICT_ORDER}
    for r in results:
        counts[r.verdict] = counts.get(r.verdict, 0) + 1
    return {
        "repos": len(results),
        "by_verdict": {k: v for k, v in counts.items() if v},
        "exposed": [r.repo for r in results if r.verdict == "EXPOSED"],
        "explicitly_enabled": [r.repo for r in results if r.verdict == "EXPLICITLY_ENABLED"],
        "unverified": [r.repo for r in results if r.verdict.startswith("UNVERIFIED")],
        "without_ci_gate": [r.repo for r in results if r.is_java and not r.gate_ci["github_workflows"] and not r.gate_ci["gitlab_ci"]],
        "errors": [r.repo for r in results if r.verdict == "ERROR"],
    }


def version_summary(r: RepoResult, limit: int = 3) -> str:
    rt = [v for v in r.versions if v.scope == "runtime" and v.kind in ("EXACT", "FLOATING")]
    rt.sort(key=lambda v: ({"VULN_RANGE": 0, "FLOATING_PATCHABLE": 1, "UNKNOWN": 2, "PATCHED_OR_UNAFFECTED": 3}.get(v.status, 4), v.path))
    uniq = list(dict.fromkeys(f"{v.normalized or v.raw}={v.status}" for v in rt))
    parts = uniq[:limit]
    if len(uniq) > limit:
        parts.append(f"+{len(uniq) - limit}")
    if not rt:
        bl = [v for v in r.versions if v.scope != "runtime" and v.kind in ("EXACT", "FLOATING")]
        if bl:
            parts.append(f"non-runtime:{','.join(sorted({v.raw for v in bl})[:3])}")
    return " ".join(parts) or "-"


def flag_summary(r: RepoResult) -> str:
    rt = {f.state for f in r.flags if f.scope == "runtime" and f.state != "MENTION"}
    bl = {f.state for f in r.flags if f.scope != "runtime" and f.state != "MENTION"}
    s = ",".join(sorted(rt)) if rt else "MISSING"
    if bl:
        s += f" (non-runtime:{','.join(sorted(bl))})"
    return s


def render_table(results: List[RepoResult]) -> str:
    rows = [("REPO", "VERDICT", "RUNTIME JDK PINS", "FLAG", "GATE", "SRC-HITS", "NOTE")]
    for r in sorted(results, key=lambda x: (VERDICT_ORDER.index(x.verdict) if x.verdict in VERDICT_ORDER else 99, x.repo)):
        gate = "yes" if (r.gate_ci["github_workflows"] or r.gate_ci["gitlab_ci"]) else ("-" if r.verdict in ("NOT_JAVA", "ERROR") else "no")
        hits = str(len(r.source_hits)) if r.source_mode else "-"
        note = (r.error or (r.reasons[0] if r.reasons else ""))[:70]
        rows.append((r.repo, r.verdict, version_summary(r), flag_summary(r), gate, hits, note))
    widths = [min(max(len(row[i]) for row in rows), 60) for i in range(len(rows[0]))]
    lines = []
    for i, row in enumerate(rows):
        lines.append("  ".join(cell[:widths[j]].ljust(widths[j]) for j, cell in enumerate(row)).rstrip())
        if i == 0:
            lines.append("  ".join("-" * w for w in widths))
    return "\n".join(lines)


def render_markdown(results: List[RepoResult], summary: Dict[str, Any], scope: str) -> str:
    out = [f"# {CVE} ({ALIAS}) GitHub repository scan", "", f"Scope: `{scope}` · generated {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')} · {summary['repos']} repositories", ""]
    out.append("| Verdict | Repos |")
    out.append("| :--- | ---: |")
    for k in VERDICT_ORDER:
        if summary["by_verdict"].get(k):
            out.append(f"| `{k}` | {summary['by_verdict'][k]} |")
    out += ["", "| Repository | Verdict | Runtime JDK pins | Mitigation flag | CI gate | Source hits |", "| :--- | :--- | :--- | :--- | :--- | ---: |"]
    for r in sorted(results, key=lambda x: (VERDICT_ORDER.index(x.verdict) if x.verdict in VERDICT_ORDER else 99, x.repo)):
        gate = "yes" if (r.gate_ci["github_workflows"] or r.gate_ci["gitlab_ci"]) else "no"
        link = f"[{r.repo}]({r.html_url})" if r.html_url else r.repo
        out.append(f"| {link} | `{r.verdict}` | {version_summary(r).replace('|', '/')} | {flag_summary(r)} | {gate} | {len(r.source_hits) if r.source_mode else '-'} |")
    detail = [r for r in results if r.verdict in ("EXPOSED", "EXPLICITLY_ENABLED", "MITIGATED_FLAG", "UNVERIFIED_FLOATING")]
    if detail:
        out += ["", "## Details"]
        for r in detail:
            out += ["", f"### {r.repo} — `{r.verdict}`", ""]
            for reason in r.reasons:
                out.append(f"- {reason}")
            if r.actions:
                out.append("")
                out.append("Actions:")
                for a in r.actions:
                    out.append(f"1. {a}")
            vs = [v for v in r.versions if v.kind != "LANGUAGE_LEVEL"]
            if vs:
                out += ["", "| File | Source | Raw | Status | Baseline |", "| :--- | :--- | :--- | :--- | :--- |"]
                for v in vs[:25]:
                    out.append(f"| `{v.path}:{v.line}` | {v.source} | `{v.raw}` | `{v.status}` | {v.baseline or '-'} |")
            hits = [h for h in r.source_hits if h.pre_auth_context][:10]
            if hits:
                out += ["", "Pre-auth Base64 decode sites:", ""]
                for h in hits:
                    out.append(f"- `{h.path}:{h.line}` ({h.pattern_id}) `{h.snippet[:100].replace('`', '')}`")
    return "\n".join(out) + "\n"


def render_csv(results: List[RepoResult]) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["repo", "verdict", "html_url", "default_branch", "archived", "fork", "private", "pushed_at", "primary_language", "is_java",
                "runtime_versions", "non_runtime_versions", "runtime_flags", "non_runtime_flags", "gate_ci", "source_hits", "pre_auth_hits", "reasons", "actions", "error"])
    for r in results:
        w.writerow([
            r.repo, r.verdict, r.html_url, r.default_branch, r.archived, r.fork, r.private, r.pushed_at, r.primary_language or "", r.is_java,
            "; ".join(f"{v.path}:{v.line} {v.raw} {v.status}" for v in r.versions if v.scope == "runtime" and v.kind in ("EXACT", "FLOATING")),
            "; ".join(f"{v.path}:{v.line} {v.raw} {v.status} [{v.scope}]" for v in r.versions if v.scope != "runtime" and v.kind in ("EXACT", "FLOATING")),
            "; ".join(f"{f.path}:{f.line} {f.state}" for f in r.flags if f.scope == "runtime" and f.state != "MENTION"),
            "; ".join(f"{f.path}:{f.line} {f.state} [{f.scope}]" for f in r.flags if f.scope != "runtime" and f.state != "MENTION"),
            "yes" if (r.gate_ci["github_workflows"] or r.gate_ci["gitlab_ci"]) else "no",
            len(r.source_hits), sum(1 for h in r.source_hits if h.pre_auth_context),
            " | ".join(r.reasons), " | ".join(r.actions), r.error or ""])
    return buf.getvalue()


SARIF_RULES = {
    "J4S-VER-05": ("Vulnerable JDK version pinned", "JDK pin is inside the CVE-2026-114938 vulnerable range (runbook §1 baselines)", "error"),
    "J4S-VER-FLOAT": ("Floating JDK pin", "Floating JDK tag or package resolves at build time; verify the resolved build is patched", "warning"),
    "J4S-FLAG-04": ("Base64 intrinsic explicitly re-enabled", "-XX:+UseBASE64Intrinsics defeats the mitigation", "error"),
    "J4S-FLAG-06": ("Mitigation flag missing", "Java runtime definition without -XX:-UseBASE64Intrinsics or -XX:UseAVX=0..2", "warning"),
    "J4S-SRC-01": ("java.util.Base64 decode call site", "Base64 decoding reachable in source", "note"),
    "J4S-SRC-04": ("Pre-authentication Base64 decode", "Base64 decoding in Authorization/JWT/SAML context", "warning"),
}


def to_sarif(r: RepoResult) -> Dict[str, Any]:
    results: List[Dict[str, Any]] = []

    def add(rule: str, path: str, line: int, msg: str) -> None:
        results.append({"ruleId": rule, "level": SARIF_RULES[rule][2], "message": {"text": msg},
                        "locations": [{"physicalLocation": {"artifactLocation": {"uri": path, "uriBaseId": "%SRCROOT%"},
                                                            "region": {"startLine": max(1, line)}}}]})
    for v in r.versions:
        if v.status == "VULN_RANGE":
            add("J4S-VER-05", v.path, v.line, f"{v.raw}: {v.reason}. {v.action}")
        elif v.status == "FLOATING_PATCHABLE":
            add("J4S-VER-FLOAT", v.path, v.line, f"{v.raw}: {v.reason}")
    for f in r.flags:
        if f.state == "EXPLICITLY_ENABLED":
            add("J4S-FLAG-04", f.path, f.line, f.text)
    if r.verdict in ("EXPOSED",):
        for v in r.versions:
            if v.scope == "runtime" and v.status == "VULN_RANGE" and v.source in ("dockerfile-from", "image-ref"):
                add("J4S-FLAG-06", v.path, v.line, "Runtime image without -XX:-UseBASE64Intrinsics")
    for h in r.source_hits:
        add(h.pattern_id, h.path, h.line, h.snippet)
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "gh_j4s_scan", "version": TOOL_VERSION, "informationUri": f"https://nvd.nist.gov/vuln/detail/{CVE}",
                                       "rules": [{"id": k, "name": v[0], "shortDescription": {"text": v[0]}, "fullDescription": {"text": v[1]},
                                                  "defaultConfiguration": {"level": v[2]}} for k, v in SARIF_RULES.items()]}},
                  "versionControlProvenance": [{"repositoryUri": r.html_url, "branch": r.default_branch}],
                  "results": results}]}


# --------------------------------------------------------------------------------------------
# Self-test (offline)
# --------------------------------------------------------------------------------------------
def self_test() -> int:
    failures: List[str] = []

    def check(cond: bool, label: str) -> None:
        if not cond:
            failures.append(label)

    for ver, want in [("17.0.21.0.3", "PATCHED_OR_UNAFFECTED"), ("17.0.21.0.2", "VULN_RANGE"), ("17.0.5", "PATCHED_OR_UNAFFECTED"), ("17.0.6", "VULN_RANGE"),
                      ("21.0.12_7", "VULN_RANGE"), ("21.0.13.1", "PATCHED_OR_UNAFFECTED"), ("21.0.13.1_9", "PATCHED_OR_UNAFFECTED"), ("25.0.4", "VULN_RANGE"),
                      ("25.0.5.1", "PATCHED_OR_UNAFFECTED"), ("27.0.1.1", "PATCHED_OR_UNAFFECTED"), ("22.0.2", "VULN_RANGE"), ("11.0.24", "PATCHED_OR_UNAFFECTED"),
                      ("1.8.0_392", "PATCHED_OR_UNAFFECTED"), ("8u511b33-perf", "VULN_RANGE"), ("8u392", "PATCHED_OR_UNAFFECTED")]:
        got = classify_exact(ver)["status"]
        check(got == want, f"classify_exact({ver}) = {got}, want {want}")
    check(classify_major(21)["status"] == "FLOATING_PATCHABLE", "classify_major(21)")
    check(classify_major(22)["status"] == "VULN_RANGE", "classify_major(22)")
    check(classify_major(11)["status"] == "PATCHED_OR_UNAFFECTED", "classify_major(11)")

    for ref, want_status, want_kind in [
        ("eclipse-temurin:21.0.12_7-jre-jammy", "VULN_RANGE", "EXACT"), ("eclipse-temurin:21-jre", "FLOATING_PATCHABLE", "FLOATING"),
        ("amazoncorretto:21-alpine3.20", "FLOATING_PATCHABLE", "FLOATING"), ("amazoncorretto:17.0.9", "VULN_RANGE", "EXACT"),
        ("azul/zulu-openjdk-alpine:21.0.4-21.36", "VULN_RANGE", "EXACT"), ("bellsoft/liberica-runtime-container:jdk-21-slim-musl", "FLOATING_PATCHABLE", "FLOATING"),
        ("maven:3.9.9-eclipse-temurin-21", "FLOATING_PATCHABLE", "FLOATING"), ("tomcat:10.1.30-jdk17-temurin-jammy", "FLOATING_PATCHABLE", "FLOATING"),
        ("openjdk:17", "PATCHED_OR_UNAFFECTED", "FLOATING"), ("openjdk:11-jre-slim", "PATCHED_OR_UNAFFECTED", "FLOATING"), ("openjdk:19-jdk", "VULN_RANGE", "FLOATING"),
        ("ghcr.io/graalvm/jdk-community:21", "FLOATING_PATCHABLE", "FLOATING"), ("mcr.microsoft.com/openjdk/jdk:21-ubuntu", "FLOATING_PATCHABLE", "FLOATING"),
        ("eclipse-temurin:25.0.5.1_9-jre", "PATCHED_OR_UNAFFECTED", "EXACT"), ("sapmachine:17.0.21.0.3", "PATCHED_OR_UNAFFECTED", "EXACT"),
        ("cgr.dev/chainguard/jre:openjdk-21", "FLOATING_PATCHABLE", "FLOATING"), ("ibm-semeru-runtimes:open-21-jdk", "FLOATING_PATCHABLE", "FLOATING"),
        ("eclipse-temurin@sha256:deadbeef", "UNKNOWN", "UNKNOWN")]:
        name, tag, digest = parse_image_ref(ref)
        d = classify_image(name, tag, digest)
        check(d is not None and d["status"] == want_status and d["kind"] == want_kind, f"classify_image({ref}) = {d and (d['status'], d['kind'])}, want ({want_status}, {want_kind})")
    for ref in ["python:3.12-slim", "nginx:1.27", "node:20.11.0", "postgres:16", "alpine:3.20"]:
        name, tag, digest = parse_image_ref(ref)
        check(classify_image(name, tag, digest) is None, f"classify_image({ref}) should be None")

    r = RepoResult("t/t")
    analyze_file("Dockerfile", 'ARG JAVA_VERSION=21.0.12_7\nFROM eclipse-temurin:${JAVA_VERSION}-jre AS base\nFROM base\nENV JAVA_TOOL_OPTIONS="-XX:-UseBASE64Intrinsics -Xmx1g"\nRUN apt-get install -y openjdk-17-jre-headless\n', r)
    check(any(v.raw == "eclipse-temurin:21.0.12_7-jre" and v.status == "VULN_RANGE" for v in r.versions), "Dockerfile ARG expansion in FROM")
    check(len([v for v in r.versions if v.source == "dockerfile-from"]) == 1, "FROM alias skipped")
    check(any(f.state == "ACTIVE" for f in r.flags), "Dockerfile ENV flag ACTIVE")
    check(any(v.source == "package-manager" and v.major == 17 for v in r.versions), "apt package major")
    r2 = RepoResult("t/t")
    analyze_file("Dockerfile", "FROM ubuntu:24.04\nENV JAVA_VERSION=jdk-17.0.9+9\nRUN curl -LfsSo /tmp/openjdk.tar.gz https://github.com/adoptium/temurin17-binaries/releases/download/jdk-17.0.9%2B9/OpenJDK17U-jdk_x64_linux_hotspot_17.0.9_9.tar.gz\n", r2)
    decide(r2)
    check([ (v.source, v.normalized, v.status) for v in r2.versions ] == [("generic", "17.0.9", "VULN_RANGE")], f"download URL versions {[(v.source, v.raw, v.status) for v in r2.versions]}")
    check(r2.verdict == "EXPOSED", f"download URL verdict {r2.verdict}")
    r2 = RepoResult("t/t")
    analyze_file("Dockerfile", "ENV JAVA_VERSION=jdk-27.0.1.0\nRUN msiexec 'INSTALLDIR=C:\\openjdk-27'\n", r2)
    decide(r2)
    check([(v.kind, v.normalized) for v in r2.versions] == [("EXACT", "27.0.1.0")], f"windows path not a package {[(v.kind, v.raw) for v in r2.versions]}")
    r2 = RepoResult("t/t")
    analyze_file(".devcontainer/Dockerfile", "FROM mcr.microsoft.com/vscode/devcontainers/java:0-17-bullseye\n", r2)
    check(r2.versions and r2.versions[0].major == 17 and r2.versions[0].scope == "build", f"devcontainer tag {r2.versions and (r2.versions[0].major, r2.versions[0].scope)}")
    decide(r)
    check(r.verdict == "MITIGATED_FLAG", f"Dockerfile verdict {r.verdict}, want MITIGATED_FLAG")

    r = RepoResult("t/t")
    analyze_file("k8s/deploy.yaml", 'kind: Deployment\nspec:\n  containers:\n  - name: app\n    image: amazoncorretto:21.0.5\n    env:\n    - name: JAVA_TOOL_OPTIONS\n      value: -XX:UseAVX=2\n', r)
    decide(r)
    check(r.verdict == "MITIGATED_FLAG" and any(f.state == "CAPPED" for f in r.flags), f"k8s CAPPED verdict {r.verdict}")

    r = RepoResult("t/t")
    analyze_file("deploy/app.yaml", 'image: "eclipse-temurin:17.0.9_9-jre"\nargs: ["-XX:+UseBASE64Intrinsics"]\n', r)
    decide(r)
    check(r.verdict == "EXPLICITLY_ENABLED", f"re-enable verdict {r.verdict}")

    r = RepoResult("t/t")
    analyze_file("Dockerfile", "FROM eclipse-temurin:21.0.13.1_9-jre\nCMD java -jar app.jar\n", r)
    decide(r)
    check(r.verdict == "PATCHED", f"patched verdict {r.verdict}")

    r = RepoResult("t/t")
    analyze_file("Dockerfile", "FROM amazoncorretto:21.0.5\nCMD java -jar app.jar\n", r)
    decide(r)
    check(r.verdict == "EXPOSED", f"exposed verdict {r.verdict}")

    r = RepoResult("t/t")
    analyze_file(".github/workflows/ci.yml", "jobs:\n  build:\n    strategy:\n      matrix:\n        java: [ 17, 21 ]\n    steps:\n      - uses: actions/setup-java@v4\n        with:\n          distribution: temurin\n          java-version: ${{ matrix.java }}\n", r)
    check(sorted(v.raw for v in r.versions if v.source == "setup-java") == ["17", "21"], f"setup-java matrix {[v.raw for v in r.versions]}")
    check(all(v.scope == "build" for v in r.versions), "workflow versions are build scope")
    decide(r)
    check(r.verdict == "UNVERIFIED_NO_PIN", f"ci-only verdict {r.verdict}")

    r = RepoResult("t/t")
    analyze_file(".sdkmanrc", "java=21.0.12-tem\n", r)
    check(r.versions and r.versions[0].normalized == "21.0.12" and r.versions[0].status == "VULN_RANGE" and r.versions[0].scope == "dev", "sdkmanrc parse (dev scope)")
    decide(r)
    check(r.verdict == "UNVERIFIED_NO_PIN" and any("dev" in x for x in r.reasons) and any("developer/CI" in a for a in r.actions), f"dev pin verdict {r.verdict} {r.reasons}")
    r = RepoResult("t/t")
    analyze_file("framework-docs/antora.yml", "asciidoc:\n  attributes:\n    graalvm-docs: https://www.graalvm.org/22.3/reference-manual/java\n", r)
    check(not [v for v in r.versions if v.kind != "LANGUAGE_LEVEL"], f"two-component doc number ignored {[(v.raw) for v in r.versions]}")
    r = RepoResult("t/t")
    analyze_file("Dockerfile", "ARG JAVA_VERSION=21\nFROM ubuntu\nRUN apt-get install -y openjdk-${JAVA_VERSION}-jre\n", r)
    check(any(v.source == "dockerfile-arg-env" and v.major == 21 and v.kind == "FLOATING" and v.raw == "JAVA_VERSION=21" for v in r.versions), f"ARG JAVA_VERSION=21 {[(v.source, v.raw) for v in r.versions]}")
    r = RepoResult("t/t")
    analyze_file("docs/examples/Dockerfile", "FROM eclipse-temurin:21.0.12_7-jre\n", r)
    decide(r)
    check(r.versions[0].scope == "docs" and r.verdict == "UNVERIFIED_NO_PIN", f"docs scope {r.versions[0].scope} {r.verdict}")
    r = RepoResult("t/t")
    analyze_file(".tool-versions", "nodejs 20.11.0\njava temurin-17.0.21.0.3+9\n", r)
    check(r.versions and r.versions[0].status == "PATCHED_OR_UNAFFECTED", f"tool-versions parse {r.versions and r.versions[0].normalized}")
    r = RepoResult("t/t")
    analyze_file(".java-version", "21\n", r)
    check(r.versions and r.versions[0].kind == "FLOATING", ".java-version major")
    r = RepoResult("t/t")
    analyze_file("pom.xml", "<properties><java.version>17</java.version></properties>", r)
    check(r.versions and r.versions[0].kind == "LANGUAGE_LEVEL" and r.versions[0].major == 17, "pom level")
    r = RepoResult("t/t")
    analyze_file("build.gradle.kts", "java { toolchain { languageVersion.set(JavaLanguageVersion.of(21)) } }", r)
    check(r.versions and r.versions[0].major == 21, "gradle toolchain level")

    r = RepoResult("t/t")
    analyze_source("src/main/java/Auth.java", 'String h = req.getHeader("Authorization");\nbyte[] b = Base64.getDecoder().decode(h.substring(6));\nString jwt = Base64.getUrlDecoder().decode(token);\nString x = "no decoding here";\n', r)
    check(len(r.source_hits) == 2 and all(h.pattern_id == "J4S-SRC-01" for h in r.source_hits), f"source hits {[(h.pattern_id, h.line) for h in r.source_hits]}")
    r = RepoResult("t/t")
    analyze_source("A.java", 'byte[] raw = decode(authHeader.replace("Bearer ", "")); // Base64 payload\n', r)
    check(len(r.source_hits) == 1 and r.source_hits[0].pattern_id == "J4S-SRC-04", "auth context hit")

    check(FLAG_ACTIVE_RE.search("JAVA_TOOL_OPTIONS=-XX:-UseBASE64Intrinsics") is not None, "flag after = delimiter")
    check(FLAG_ACTIVE_RE.search("-XX:-UseBASE64IntrinsicsX") is None, "flag token boundary")
    check(parse_repo_arg("https://github.com/acme/app.git") == "acme/app", "repo url parse")
    check(parse_repo_arg("git@github.com:acme/app.git") == "acme/app", "repo ssh parse")

    if failures:
        print("SELF-TEST FAILED:")
        for f in failures:
            print(f"  - {f}")
        return 1
    print("SELF-TEST PASSED (gh_j4s_scan.py)")
    return 0


# --------------------------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------------------------
def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("repos", nargs="*", help="owner/repo, GitHub URLs, or '-' to read them from stdin")
    sc = ap.add_argument_group("scope")
    sc.add_argument("--user", action="append", default=[], metavar="LOGIN", help="scan repositories owned by this user (repeatable)")
    sc.add_argument("--org", action="append", default=[], metavar="ORG", help="scan repositories of this organization (repeatable)")
    sc.add_argument("--me", action="store_true", help="scan the authenticated user's repositories (see --affiliation)")
    sc.add_argument("--repos-file", metavar="FILE", help="file with one owner/repo or URL per line")
    sc.add_argument("--affiliation", default="owner", help="for --me: owner,collaborator,organization_member (default owner)")
    sc.add_argument("--org-type", default="all", choices=["all", "public", "private", "forks", "sources", "member"], help="for --org (default all)")
    sc.add_argument("--limit", type=int, default=0, help="max repositories to list per scope (0 = all)")
    fl = ap.add_argument_group("filters (discovery only)")
    fl.add_argument("--language", default="java,kotlin,scala,groovy,clojure", help="primary-language filter, comma list (default JVM languages)")
    fl.add_argument("--all-languages", action="store_true", help="do not filter by language")
    fl.add_argument("--deep-languages", action="store_true", help="also keep repos whose secondary languages include a JVM language (1 extra request per candidate)")
    fl.add_argument("--include-archived", action="store_true")
    fl.add_argument("--include-forks", action="store_true")
    fl.add_argument("--visibility", choices=["public", "private", "internal"])
    fl.add_argument("--pushed-since", metavar="YYYY-MM-DD", help="skip repositories not pushed since this date")
    fl.add_argument("--name-regex", metavar="RE", help="keep repositories whose name matches RE")
    fl.add_argument("--topic", action="append", default=[], help="keep repositories carrying this topic (repeatable)")
    an = ap.add_argument_group("analysis")
    an.add_argument("--source", action="store_true", help="also fetch source files and report Base64 decode call sites (J4S-SRC-01/04)")
    an.add_argument("--source-mode", choices=["search", "paths", "both"], default="search", help="how to pick source files: code search (default), path heuristics, or both")
    an.add_argument("--max-source-files", type=int, default=25)
    an.add_argument("--max-files", type=int, default=80, help="config/manifest files fetched per repository (default 80)")
    an.add_argument("--max-file-size", type=int, default=512 * 1024, help="skip files larger than this many bytes")
    an.add_argument("--languages-api", action="store_true", help="fetch /languages for every scanned repository")
    an.add_argument("--track-issues", action="store_true", help="look for issues/PRs mentioning the CVE in each repository (search API)")
    an.add_argument("--strict", action="store_true", help="exit 2 also for UNVERIFIED_* verdicts")
    ou = ap.add_argument_group("output")
    ou.add_argument("--format", choices=["table", "json", "ndjson", "csv", "md"], default="table")
    ou.add_argument("--out", metavar="FILE", help="write the report here instead of stdout")
    ou.add_argument("--sarif-dir", metavar="DIR", help="write one SARIF 2.1.0 file per repository into DIR")
    ou.add_argument("--repos-out", metavar="FILE", help="write the scanned owner/repo list (one per line)")
    cn = ap.add_argument_group("connection")
    cn.add_argument("--token", help="GitHub token (default: $GH_TOKEN, $GITHUB_TOKEN, gh auth token)")
    cn.add_argument("--api-url", default=os.environ.get("GITHUB_API_URL", "https://api.github.com"))
    cn.add_argument("--workers", type=int, default=4, help="repositories scanned concurrently")
    cn.add_argument("--file-workers", type=int, default=4, help="file fetches per repository in flight")
    cn.add_argument("--max-wait", type=float, default=300, help="longest rate-limit sleep in seconds before failing a request")
    cn.add_argument("--timeout", type=float, default=30)
    ap.add_argument("-v", "--verbose", action="store_true")
    ap.add_argument("--self-test", action="store_true", help="run offline parser/classifier checks and exit")
    opts = ap.parse_args(argv)

    if opts.self_test:
        return self_test()

    token = resolve_token(opts.token)
    if not token:
        sys.stderr.write("[gh] no token found: continuing unauthenticated (public repos only, 60 requests/hour, no code search)\n")
    gh = GitHub(token, opts.api_url, timeout=opts.timeout, max_wait=opts.max_wait, verbose=opts.verbose)

    explicit: List[str] = []
    for a in opts.repos:
        if a == "-":
            explicit.extend(x for x in (parse_repo_arg(l) for l in sys.stdin) if x)
        else:
            p = parse_repo_arg(a)
            if not p:
                ap.error(f"not an owner/repo or GitHub URL: {a}")
            explicit.append(p)
    if opts.repos_file:
        with open(opts.repos_file, encoding="utf-8") as fh:
            explicit.extend(x for x in (parse_repo_arg(l) for l in fh) if x)
    metas: Dict[str, Dict[str, Any]] = {}
    targets: List[str] = list(dict.fromkeys(explicit))
    if opts.user or opts.org or opts.me:
        try:
            for repo in discover(gh, opts):
                if repo["full_name"] not in metas:
                    metas[repo["full_name"]] = repo
                    targets.append(repo["full_name"])
        except GitHubError as e:
            sys.stderr.write(f"error: discovery failed: {e}\n")
            return 1
    if not targets:
        ap.error("nothing to scan: give owner/repo arguments, '-', --repos-file, --user, --org or --me")
    scope = ", ".join([f"user:{u}" for u in opts.user] + [f"org:{o}" for o in opts.org] + (["me"] if opts.me else []) + ([f"{len(explicit)} explicit"] if explicit else []))
    sys.stderr.write(f"[gh] scanning {len(targets)} repositories ({scope})\n")

    results: List[RepoResult] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, opts.workers)) as pool:
        futs = {pool.submit(scan_repo, gh, t, opts, metas.get(t)): t for t in targets}
        done = 0
        for fut in concurrent.futures.as_completed(futs):
            res = fut.result()
            results.append(res)
            done += 1
            if opts.verbose or len(targets) > 10:
                sys.stderr.write(f"[gh] {done}/{len(targets)} {res.repo}: {res.verdict}\n")
    results.sort(key=lambda r: (VERDICT_ORDER.index(r.verdict) if r.verdict in VERDICT_ORDER else 99, r.repo))
    summary = summarize(results)

    if opts.sarif_dir:
        os.makedirs(opts.sarif_dir, exist_ok=True)
        for r in results:
            if r.verdict in ("ERROR", "NOT_JAVA"):
                continue
            with open(os.path.join(opts.sarif_dir, r.repo.replace("/", "__") + ".sarif"), "w", encoding="utf-8") as fh:
                json.dump(to_sarif(r), fh, indent=2)
    if opts.repos_out:
        with open(opts.repos_out, "w", encoding="utf-8") as fh:
            fh.write("\n".join(r.repo for r in results) + "\n")

    if opts.format == "json":
        text = json.dumps({"cve": CVE, "alias": ALIAS, "tool": "gh_j4s_scan", "tool_version": TOOL_VERSION, "generated_at": datetime.now(timezone.utc).isoformat(),
                           "scope": scope, "api_url": gh.api_url, "summary": summary, "repos": [r.to_dict() for r in results]}, indent=2)
    elif opts.format == "ndjson":
        text = "\n".join(json.dumps(r.to_dict()) for r in results) + "\n"
    elif opts.format == "csv":
        text = render_csv(results)
    elif opts.format == "md":
        text = render_markdown(results, summary, scope)
    else:
        text = render_table(results) + "\n\n" + "  ".join(f"{k}={v}" for k, v in summary["by_verdict"].items()) + "\n"
    if opts.out:
        with open(opts.out, "w", encoding="utf-8") as fh:
            fh.write(text)
        sys.stderr.write(f"[gh] report written to {opts.out}\n")
    else:
        sys.stdout.write(text)
    sys.stderr.write(f"[gh] {gh.rate_summary()}\n")

    bad = STRICT_VERDICTS if opts.strict else BLOCKING_VERDICTS
    if any(r.verdict in bad for r in results):
        return 2
    if results and all(r.verdict == "ERROR" for r in results):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
