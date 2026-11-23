#!/usr/bin/env python3
"""Base64 input analyzer for CVE-2026-114938 (Java4Shell) investigation. Library + CLI.

Explains WHY a Base64 token is suspicious (malformed trailing padding is the trigger shape for the
VBMI intrinsic bug), finds such tokens in logs/HAR/headers, and validates inputs strictly so an
application filter can reject them before `Base64.getDecoder().decode()`. It never decodes with the JVM.

    from j4s_b64check import analyze, find_tokens, is_strictly_valid
    analyze("QUJD====").anomalies   -> ['excess_padding', 'length_not_multiple_of_4', ...]

    j4s_b64check.py token 'QUJD====' 'SGVsbG8='
    j4s_b64check.py scan access.log --min-len 64 [--json]        # any text: logs, HAR, request dumps
    j4s_b64check.py headers < request-headers.txt               # Authorization / Proxy-Authorization lines
    echo -n 'QUJD=QUJD' | j4s_b64check.py token -
Exit codes: 0 = nothing suspicious, 2 = suspicious token(s) found.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import json
import re
import sys
from dataclasses import asdict, dataclass, field

STD = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")
URL = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
# A run that starts with an alphabet char and may contain "=" anywhere (so malformed interior padding is kept in one token)
TOKEN_RE = re.compile(r"[A-Za-z0-9+/_-][A-Za-z0-9+/_=-]{%d,}")
AUTH_RE = re.compile(r"^(?:Proxy-)?Authorization:\s*(Basic|Bearer|Negotiate|Digest)?\s*(\S+)", re.I | re.M)
# Edge rule equivalents (patterns J4S-EDGE-01..03)
EDGE_01 = re.compile(r"={3,}")
EDGE_02 = re.compile(r"=[A-Za-z0-9+/_-]{1,64}")
EDGE_03 = re.compile(r"[A-Za-z0-9+/_-]{64,}[^=A-Za-z0-9+/_-]?={1}(?:[^=A-Za-z0-9+/_-]|$)")


@dataclass
class Analysis:
    token: str
    length: int
    alphabet: str  # std | url | mixed | invalid
    pad_count: int
    body_len: int
    strict_valid: bool
    anomalies: list[str] = field(default_factory=list)
    edge_rules_hit: list[str] = field(default_factory=list)
    suspicious: bool = False
    looks_like_jwt: bool = False

    def to_dict(self) -> dict:
        d = asdict(self)
        d["token"] = self.token if len(self.token) <= 96 else self.token[:93] + "..."
        return d


def _alphabet(body: str) -> str:
    chars = set(body)
    if chars <= STD and chars <= URL:
        return "std"  # only shared characters
    if chars <= STD:
        return "std"
    if chars <= URL:
        return "url"
    if chars <= (STD | URL):
        return "mixed"
    return "invalid"


def is_strictly_valid(token: str) -> bool:
    """RFC 4648 strict: correct alphabet, length multiple of 4 incl. padding, 0-2 trailing '=' only."""
    try:
        if _alphabet(token.rstrip("=")) in ("mixed", "invalid"):
            return False
        t = token.replace("-", "+").replace("_", "/")
        base64.b64decode(t, validate=True)
        return len(t) % 4 == 0 and t.count("=") <= 2 and "=" not in t.rstrip("=")
    except (binascii.Error, ValueError):
        return False


def analyze(token: str) -> Analysis:
    token = token.strip()
    segs = token.split(".")
    if len(segs) == 3 and all(seg and _alphabet(seg.rstrip("=")) in ("std", "url") for seg in segs):
        # JWT/JWS: analyze each segment on its own; the dots are structure, not Base64
        parts = [analyze(seg) for seg in segs]
        a = Analysis(token=token, length=len(token), alphabet="url(jwt)", pad_count=sum(x.pad_count for x in parts),
                     body_len=sum(x.body_len for x in parts), strict_valid=all(x.strict_valid or (x.pad_count == 0 and x.alphabet in ("std", "url") and x.body_len % 4 != 1) for x in parts))
        a.looks_like_jwt = True
        for i, x in enumerate(parts):
            a.anomalies += [f"seg{i}:{an}" for an in x.anomalies]
            a.edge_rules_hit += [r for r in x.edge_rules_hit if r not in a.edge_rules_hit]
        a.suspicious = bool(a.anomalies)
        return a
    body = token.rstrip("=")
    pad = len(token) - len(body)
    alpha = _alphabet(body.replace("=", "")) if body else "invalid"
    a = Analysis(token=token, length=len(token), alphabet=alpha, pad_count=pad, body_len=len(body), strict_valid=is_strictly_valid(token))

    if pad > 2:
        a.anomalies.append("excess_padding")  # the runbook's primary trigger shape
    if "=" in body:
        a.anomalies.append("padding_inside_body")
    if alpha == "mixed":
        a.anomalies.append("mixed_std_and_url_alphabet")
    if alpha == "invalid":
        a.anomalies.append("non_base64_characters")
    if len(token) % 4 != 0 and pad > 0:
        a.anomalies.append("length_not_multiple_of_4_with_padding")
    if pad and body and ((len(body) % 4) == 1):
        a.anomalies.append("impossible_body_length_mod4_eq_1")
    expected_pad = (-len(body)) % 4
    if pad and expected_pad != pad and pad <= 2:
        a.anomalies.append(f"padding_mismatch_expected_{expected_pad}_got_{pad}")

    for name, rx in (("J4S-EDGE-01", EDGE_01), ("J4S-EDGE-02", EDGE_02), ("J4S-EDGE-03", EDGE_03)):
        if rx.search(token):
            a.edge_rules_hit.append(name)
    # EDGE-03 alone on a strictly valid token is the known false positive; only count it when something else is wrong
    a.suspicious = bool(a.anomalies) or any(r in a.edge_rules_hit for r in ("J4S-EDGE-01", "J4S-EDGE-02")) and not a.strict_valid
    return a


def find_tokens(text: str, min_len: int = 64) -> list[str]:
    rx = re.compile(TOKEN_RE.pattern % min_len)
    return [m.group(0) for m in rx.finditer(text)]


def _peel_key(tok: str, min_len: int) -> str:
    """'body=QUJD...' or 'token=QUJD...' -> the value part, when the prefix is short and the remainder still qualifies."""
    while "=" in tok:
        i = tok.index("=")
        if i < 16 and len(tok) - i - 1 >= min_len and re.fullmatch(r"[A-Za-z0-9_-]+", tok[:i]):
            tok = tok[i + 1:]
        else:
            break
    return tok


def scan_text(text: str, min_len: int = 64, only_suspicious: bool = True) -> list[tuple[int, Analysis]]:
    out = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        for tok in find_tokens(line, min_len):
            a = analyze(_peel_key(tok, min_len))
            if a.suspicious or not only_suspicious:
                out.append((lineno, a))
    return out


def scan_headers(text: str) -> list[Analysis]:
    res = []
    for m in AUTH_RE.finditer(text):
        tok = m.group(2)
        if m.group(1) and m.group(1).lower() in ("digest", "negotiate"):
            continue
        res.append(analyze(tok))
    return res


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    t = sub.add_parser("token", help="Analyze token(s); '-' reads one token from stdin"); t.add_argument("tokens", nargs="+"); t.add_argument("--json", action="store_true")
    s = sub.add_parser("scan", help="Find suspicious Base64-like tokens in a text file ('-' = stdin)"); s.add_argument("file"); s.add_argument("--min-len", type=int, default=64); s.add_argument("--all", action="store_true", help="Report every token, not only suspicious ones"); s.add_argument("--json", action="store_true")
    h = sub.add_parser("headers", help="Analyze Authorization headers from a file or stdin"); h.add_argument("file", nargs="?"); h.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)

    def read(f: str | None) -> str:
        return sys.stdin.read() if f in (None, "-") else open(f, encoding="utf-8", errors="replace").read()

    if a.cmd == "token":
        toks = [sys.stdin.read().strip() if x == "-" else x for x in a.tokens]
        res = [analyze(x) for x in toks]
        if a.json:
            print(json.dumps([r.to_dict() for r in res], indent=2))
        else:
            for r in res:
                tag = "SUSPICIOUS" if r.suspicious else ("valid" if r.strict_valid else "non-strict")
                print(f"{tag:10} len={r.length} pad={r.pad_count} alphabet={r.alphabet} jwt={r.looks_like_jwt} anomalies={r.anomalies or '-'} edge={r.edge_rules_hit or '-'}  {r.to_dict()['token']}")
        return 2 if any(r.suspicious for r in res) else 0
    if a.cmd == "scan":
        hits = scan_text(read(a.file), a.min_len, only_suspicious=not a.all)
        if a.json:
            print(json.dumps([{"line": ln, **an.to_dict()} for ln, an in hits], indent=2))
        else:
            for ln, an in hits:
                print(f"line {ln}: {'SUSPICIOUS' if an.suspicious else 'ok':10} anomalies={an.anomalies or '-'} edge={an.edge_rules_hit or '-'} {an.to_dict()['token']}")
            print(f"-- {sum(1 for _, x in hits if x.suspicious)} suspicious token(s)", file=sys.stderr)
        return 2 if any(x.suspicious for _, x in hits) else 0
    if a.cmd == "headers":
        res = scan_headers(read(a.file))
        if a.json:
            print(json.dumps([r.to_dict() for r in res], indent=2))
        else:
            for r in res:
                print(f"{'SUSPICIOUS' if r.suspicious else 'ok':10} anomalies={r.anomalies or '-'} {r.to_dict()['token']}")
        return 2 if any(r.suspicious for r in res) else 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
