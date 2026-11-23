#!/usr/bin/env python3
"""Scan Java/Kotlin/Scala/Groovy source for java.util.Base64 decode call sites and classify
their input provenance for CVE-2026-114938 (Java4Shell).

Self-contained: Python 3.10+, standard library only. Implements patterns J4S-SRC-01..05 from
patterns/SPEC.md (runbook §6 ast_taint.py regex fallback and §7.3 quick patterns).

Usage:
  scan_java4shell_source.py <source-root> [--json] [--sarif out.sarif] [--include-tests]
                            [--min-kind DYNAMIC_INTERNAL|DYNAMIC_UNTRUSTED]
Exit codes: 0 = no DYNAMIC_UNTRUSTED findings, 2 = DYNAMIC_UNTRUSTED findings present, 1 = error.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import asdict, dataclass

CVE = "CVE-2026-114938"
SOURCE_EXTS = (".java", ".kt", ".kts", ".scala", ".groovy")
PREFILTER = ("Base64", "Decoder")

# J4S-SRC-02: precise invocation; the argument is captured with a balanced-paren scan rather
# than the runbook's ([^;]+) so chained calls like dec.wrap(in).read() stop at the right paren.
BASE64_CALL_RE = re.compile(
    r"\b(?:(?:java\s*\.\s*util\s*\.\s*)?Base64\s*\.\s*)?(?:getDecoder|getUrlDecoder|getMimeDecoder)\s*\(\s*\)\s*\.\s*(?:decode|wrap)\s*\("
)
METHOD_DECL_RE = re.compile(
    r"^\s*(?:(?:public|private|protected|static|final|synchronized|abstract|default|native|override|fun|def)\s+)*"
    r"(?:<[^>]+>\s*)?[\w.<>\[\],?\s]+\s+\w+\s*\([^;{}]*\)\s*(?:throws\s+[\w.,\s]+)?\s*(?:\{|=|$)"
)
# J4S-SRC-01 (loose; used only to catch decoder variables like `dec.decode(x)`)
LOOSE_DECODER_RE = re.compile(r"\bBase64\s*\.\s*(getDecoder|getUrlDecoder|getMimeDecoder)\s*\(")
DECODER_VAR_RE = re.compile(r"\b(?:Base64\.Decoder|Decoder)\s+(\w+)\s*=\s*Base64\s*\.\s*get(?:Url|Mime)?Decoder\s*\(")
VAR_DECODE_RE_TMPL = r"\b{var}\s*\.\s*(?:decode|wrap)\s*\("

# J4S-SRC-03: untrusted source signatures
SOURCE_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("http_auth_header", re.compile(r"\b(?:getHeader|getHeaders|Authorization|Proxy-Authorization|Basic)\b", re.I)),
    ("http_request_input", re.compile(r"\b(?:getParameter|getInputStream|getReader|getBody|ServerHttpRequest|HttpServletRequest|@RequestBody|@RequestHeader|@PathVariable)\b", re.I)),
    ("jwt_saml_token", re.compile(r"\b(?:jwt|jws|saml|bearer|id_token|access_token)\b", re.I)),
    ("file_or_stream_io", re.compile(r"\b(?:Files\.read|FileInputStream|InputStream|BufferedReader|Scanner|MultipartFile)\b", re.I)),
    ("messaging_or_net", re.compile(r"\b(?:ConsumerRecord|Message|SQS|Kafka|Socket|URLConnection|HttpClient|WebClient)\b", re.I)),
]
# J4S-SRC-04: pre-auth context on the same line
PREAUTH_CTX_RE = re.compile(
    r"\b(Authorization|Proxy-Authorization|Basic\s+[A-Za-z0-9+/=_-]+|jwt|jws|saml|bearer)\b.{0,120}\b(Base64|decode|getDecoder)\b",
    re.I,
)
LITERAL_RE = re.compile(r'"(?:\\.|[^"\\])*"')
CONST_IDENT_RE = re.compile(r"[A-Z][A-Z0-9_]{2,}")
TEST_PATH_RE = re.compile(r"(^|[/\\])(test|tests|androidTest|it)[/\\]|test-classes|Test\.(java|kt|scala|groovy)$", re.I)

KIND_ORDER = {"CONSTANT": 0, "UNKNOWN": 1, "DYNAMIC_INTERNAL": 2, "DYNAMIC_UNTRUSTED": 3}


@dataclass
class Finding:
    file: str
    line: int
    column: int
    call: str
    argument: str
    input_kind: str
    sources: list[str]
    preauth_context: bool
    is_test: bool
    reason: str
    remediation: str = (
        "Pass -XX:-UseBASE64Intrinsics (e.g. JAVA_TOOL_OPTIONS) and/or upgrade to a patched JDK "
        "(17.0.21.0.3+ / 21.0.13.1+ / 25.0.5.1+ / 27.0.1.1+); validate Base64 length/padding before decode."
    )


def balanced_arg(line: str, open_idx: int) -> str | None:
    """Return the text between the '(' at open_idx and its matching ')', or None if unbalanced on this line."""
    depth = 0
    in_str = False
    i = open_idx
    while i < len(line):
        ch = line[i]
        if in_str:
            if ch == "\\":
                i += 1
            elif ch == '"':
                in_str = False
        elif ch == '"':
            in_str = True
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return line[open_idx + 1:i]
        i += 1
    return None


def method_context(lines: list[str], idx: int, back: int = 40, fwd: int = 5) -> str:
    """Context = from the nearest enclosing method declaration (within `back` lines) to `fwd` lines after,
    stopping at the next method declaration. Approximates method scope without a parser."""
    start = max(0, idx - 1 - 16)
    for j in range(idx - 1, max(-1, idx - 1 - back), -1):
        if METHOD_DECL_RE.match(lines[j]):
            start = j
            break
    end = min(len(lines), idx + fwd)
    for j in range(idx, end):
        if METHOD_DECL_RE.match(lines[j]) and j != idx - 1:
            end = j
            break
    return "\n".join(lines[start:end])


def classify_expression(expr: str, context: str) -> tuple[str, list[str], str]:
    cleaned = " ".join(expr.strip().split())
    is_literal = bool(LITERAL_RE.fullmatch(cleaned))
    is_const = bool(CONST_IDENT_RE.fullmatch(cleaned))
    # Deviation from runbook: a literal or SCREAMING_CASE constant argument is CONSTANT regardless of
    # what else the enclosing method touches; surrounding header reads cannot make a literal untrusted.
    if is_literal or is_const:
        return "CONSTANT", [], f"Argument '{cleaned[:80]}' is a literal/constant"
    combined = f"{cleaned}\n{context}"
    sources = [label for label, rx in SOURCE_PATTERNS if rx.search(combined)]
    if sources:
        return "DYNAMIC_UNTRUSTED", sources, f"Argument '{cleaned[:80]}' linked to sources: {', '.join(sources)}"
    if cleaned:
        return "DYNAMIC_INTERNAL", [], f"Dynamic expression '{cleaned[:80]}' with no external source signature in context"
    return "UNKNOWN", [], "Unable to determine argument provenance"


def scan_file(path: str, include_tests: bool) -> list[Finding]:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError:
        return []
    if not any(tok in text for tok in PREFILTER):
        return []

    is_test = bool(TEST_PATH_RE.search(path))
    if is_test and not include_tests:
        return []

    lines = text.splitlines()
    decoder_vars = {m.group(1) for m in DECODER_VAR_RE.finditer(text)}
    var_res = [re.compile(VAR_DECODE_RE_TMPL.format(var=re.escape(v))) for v in decoder_vars]

    findings: list[Finding] = []
    for idx, line in enumerate(lines, start=1):
        matches: list[tuple[int, str, str]] = []
        for rx in (BASE64_CALL_RE, *var_res):
            for m in rx.finditer(line):
                arg = balanced_arg(line, m.end() - 1)
                if arg is None:  # argument spans lines; take the rest of this line as a best effort
                    arg = line[m.end():]
                    call = line[m.start():].rstrip()
                else:
                    call = line[m.start(): m.end() + len(arg) + 1]
                matches.append((m.start(), call, arg))
        if not matches:
            continue
        ctx = method_context(lines, idx)
        for col, call, arg in matches:
            kind, srcs, reason = classify_expression(arg, ctx)
            findings.append(
                Finding(
                    file=path, line=idx, column=col + 1, call=call.strip()[:160], argument=arg.strip()[:160],
                    input_kind=kind, sources=srcs, preauth_context=bool(PREAUTH_CTX_RE.search(line)),
                    is_test=is_test, reason=reason,
                )
            )
    return findings


def walk(root: str, include_tests: bool) -> list[Finding]:
    out: list[Finding] = []
    skip_dirs = {".git", "node_modules", "target", "build", ".gradle", ".idea", "out", ".venv", "venv"}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in skip_dirs]
        for fn in filenames:
            if fn.endswith(SOURCE_EXTS):
                out.extend(scan_file(os.path.join(dirpath, fn), include_tests))
    return out


def to_sarif(findings: list[Finding]) -> dict:
    level = {"DYNAMIC_UNTRUSTED": "error", "DYNAMIC_INTERNAL": "warning", "UNKNOWN": "note", "CONSTANT": "note"}
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "scan_java4shell_source", "version": "1.0.0",
                "rules": [{"id": f"{CVE}/base64-decode", "shortDescription": {"text": "java.util.Base64 decode of possibly untrusted input"}}],
            }},
            "results": [{
                "ruleId": f"{CVE}/base64-decode",
                "level": level[f.input_kind],
                "message": {"text": f"[{f.input_kind}] {f.reason}. {f.remediation}"},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": f.file.replace(os.sep, "/")},
                    "region": {"startLine": f.line, "startColumn": f.column},
                }}],
                "properties": {"sources": f.sources, "preauth_context": f.preauth_context, "is_test": f.is_test},
            } for f in findings],
        }],
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("root", nargs="?", default=".")
    ap.add_argument("--json", action="store_true", help="Emit JSON instead of text")
    ap.add_argument("--sarif", metavar="FILE", help="Also write SARIF 2.1.0 to FILE")
    ap.add_argument("--include-tests", action="store_true", help="Include test source trees")
    ap.add_argument("--min-kind", default="CONSTANT", choices=list(KIND_ORDER), help="Only report findings at or above this kind")
    args = ap.parse_args()

    if not os.path.isdir(args.root):
        print(f"error: {args.root} is not a directory", file=sys.stderr)
        return 1

    findings = [f for f in walk(args.root, args.include_tests) if KIND_ORDER[f.input_kind] >= KIND_ORDER[args.min_kind]]
    findings.sort(key=lambda f: (-KIND_ORDER[f.input_kind], f.file, f.line))
    untrusted = sum(1 for f in findings if f.input_kind == "DYNAMIC_UNTRUSTED")

    if args.sarif:
        with open(args.sarif, "w", encoding="utf-8") as fh:
            json.dump(to_sarif(findings), fh, indent=2)

    if args.json:
        print(json.dumps({"cve": CVE, "root": args.root, "total": len(findings), "dynamic_untrusted": untrusted,
                          "findings": [asdict(f) for f in findings]}, indent=2))
    else:
        print(f"=== {CVE} (Java4Shell) source scan: {args.root} ===")
        print(f"Findings: {len(findings)} | DYNAMIC_UNTRUSTED: {untrusted}\n")
        for f in findings:
            flags = ("[preauth] " if f.preauth_context else "") + ("[test] " if f.is_test else "")
            print(f"{f.input_kind:17} {flags}{f.file}:{f.line}:{f.column}")
            print(f"    call: {f.call}")
            print(f"    why:  {f.reason}")
        if not findings:
            print("No java.util.Base64 decode call sites found.")
    return 2 if untrusted else 0


if __name__ == "__main__":
    raise SystemExit(main())
