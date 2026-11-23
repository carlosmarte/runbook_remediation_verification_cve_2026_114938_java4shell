#!/usr/bin/env python3
"""Scan .class/.jar/.war/.ear/.zip artifacts for references to java.util.Base64 decoding
methods (CVE-2026-114938 / Java4Shell). Pure-Python replacement for the runbook's Rust
`j4s-extract` (§5): parses the class-file constant pool, detects shaded/relocated copies,
flags test artifacts, and recurses into nested archives (depth 3).

Self-contained: Python 3.10+, standard library only. Implements J4S-BC-01..06.

Usage:
  scan_java4shell_jars.py <path-or-dir> [more paths...] [--jsonl out.jsonl] [--quiet]
Output: one JSON object per class with Base64 decode references (JSONL, j4s-extract compatible).
Exit codes: 0 = no findings, 2 = findings present, 1 = error.
"""

from __future__ import annotations

import argparse
import io
import json
import os
import struct
import sys
import zipfile

CLASS_MAGIC = 0xCAFEBABE
MAX_NESTED_DEPTH = 3
SCAN_EXTS = (".class", ".jar", ".war", ".ear", ".zip")
ARCHIVE_EXTS = (".jar", ".war", ".ear", ".zip")
BASE64_METHODS = {"getDecoder", "getUrlDecoder", "getMimeDecoder", "decode", "wrap"}


def is_base64_owner(owner: str) -> bool:
    # J4S-BC-02: exact owner, inner classes, and shaded/relocated suffix forms
    return (
        owner == "java/util/Base64"
        or owner.startswith("java/util/Base64$")
        or owner.endswith("/java/util/Base64")
        or "/java/util/Base64$" in owner
    )


def looks_like_test_path(path: str) -> bool:  # J4S-BC-04
    p = path.lower()
    return "/test/" in p or "\\test\\" in p or "test-classes" in p or p.endswith("test.jar") or p.endswith("tests.jar")


def looks_like_shaded(class_name: str, entry_path: str) -> bool:  # J4S-BC-05
    c = f"{class_name} {entry_path}".lower()
    return any(k in c for k in ("shaded", "shadow", "repack", "reloc"))


def parse_class(data: bytes) -> dict | None:
    """Minimal constant-pool parser. Returns class name, Base64 invocations, string sample, methods."""
    if len(data) < 10 or struct.unpack(">I", data[:4])[0] != CLASS_MAGIC:
        return None
    pos = 8
    cp_count = struct.unpack(">H", data[pos:pos + 2])[0]
    pos += 2
    pool: dict[int, tuple] = {}
    idx = 1
    try:
        while idx < cp_count:
            tag = data[pos]
            pos += 1
            if tag == 1:
                ln = struct.unpack(">H", data[pos:pos + 2])[0]
                pos += 2
                pool[idx] = ("utf8", data[pos:pos + ln].decode("utf-8", errors="replace"))
                pos += ln
            elif tag in (3, 4):
                pos += 4
            elif tag in (5, 6):
                pos += 8
                idx += 1
            elif tag == 7:
                pool[idx] = ("class", struct.unpack(">H", data[pos:pos + 2])[0])
                pos += 2
            elif tag == 8:
                pool[idx] = ("string", struct.unpack(">H", data[pos:pos + 2])[0])
                pos += 2
            elif tag in (9, 10, 11):
                c, n = struct.unpack(">HH", data[pos:pos + 4])
                pool[idx] = ("methodref" if tag != 9 else "fieldref", c, n)
                pos += 4
            elif tag == 12:
                n, d = struct.unpack(">HH", data[pos:pos + 4])
                pool[idx] = ("nat", n, d)
                pos += 4
            elif tag == 15:
                pos += 3
            elif tag in (16, 19, 20):
                pos += 2
            elif tag in (17, 18):
                pos += 4
            else:
                return None
            idx += 1
        pos += 2  # access flags
        this_class = struct.unpack(">H", data[pos:pos + 2])[0]
        pos += 6  # this + super
        iface_count = struct.unpack(">H", data[pos:pos + 2])[0]
        pos += 2 + iface_count * 2

        def skip_attrs(p: int) -> int:
            n = struct.unpack(">H", data[p:p + 2])[0]
            p += 2
            for _ in range(n):
                ln = struct.unpack(">I", data[p + 2:p + 6])[0]
                p += 6 + ln
            return p

        field_count = struct.unpack(">H", data[pos:pos + 2])[0]
        pos += 2
        for _ in range(field_count):
            pos = skip_attrs(pos + 6)
        method_count = struct.unpack(">H", data[pos:pos + 2])[0]
        pos += 2
        methods: list[tuple[str, str]] = []
        for _ in range(method_count):
            _, n, d = struct.unpack(">HHH", data[pos:pos + 6])
            methods.append((utf8(pool, n), utf8(pool, d)))
            pos = skip_attrs(pos + 6)
    except (struct.error, IndexError):
        return None

    class_name = cls(pool, this_class)
    invocations: set[str] = set()
    strings: list[str] = []
    for ent in pool.values():
        if ent[0] == "methodref":
            owner = cls(pool, ent[1])
            nat = pool.get(ent[2])
            if owner and nat and nat[0] == "nat":
                mname, mdesc = utf8(pool, nat[1]), utf8(pool, nat[2])
                if is_base64_owner(owner) and mname in BASE64_METHODS:
                    invocations.add(f"{owner}.{mname}:{mdesc}")
        elif ent[0] == "string" and len(strings) < 16:
            s = utf8(pool, ent[1])
            if s and len(s) <= 120:
                strings.append(s)
    return {
        "class_name": class_name.replace("/", "."),
        "base64_invocations": sorted(invocations),
        "string_constants": sorted(set(strings)),
        "methods": methods,
    }


def utf8(pool: dict, i: int) -> str:
    e = pool.get(i)
    return e[1] if e and e[0] == "utf8" else ""


def cls(pool: dict, i: int) -> str:
    e = pool.get(i)
    return utf8(pool, e[1]) if e and e[0] == "class" else ""


def finding(artifact: str, entry: str, is_test: bool, data: bytes) -> dict | None:
    parsed = parse_class(data)
    if not parsed or not parsed["base64_invocations"]:
        return None
    mname, mdesc = parsed["methods"][0] if parsed["methods"] else ("<class-constant-pool>", "")
    return {
        "artifact_path": artifact,
        "entry_path": entry,
        "is_test_artifact": is_test,
        "is_shaded": looks_like_shaded(parsed["class_name"], entry),
        "class_name": parsed["class_name"],
        "method_name": mname,
        "method_descriptor": mdesc,
        "invoked_targets": parsed["base64_invocations"],
        "constant_strings_sample": parsed["string_constants"],
        "evidence_refs": [f"bytecode:{parsed['class_name']}:{mname}"],
    }


def scan_zip(fobj, artifact: str, prefix: str, is_test: bool, depth: int, out: list[dict]) -> None:
    try:
        zf = zipfile.ZipFile(fobj)
    except (zipfile.BadZipFile, OSError):
        return
    with zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            name = info.filename
            full = name if not prefix else f"{prefix}!{name}"
            entry_test = is_test or looks_like_test_path(full)
            lower = name.lower()
            try:
                if lower.endswith(".class"):
                    if info.file_size > 16 * 1024 * 1024:
                        continue
                    f = finding(artifact, full, entry_test, zf.read(info))
                    if f:
                        out.append(f)
                elif depth < MAX_NESTED_DEPTH and lower.endswith(ARCHIVE_EXTS):
                    if info.file_size > 256 * 1024 * 1024:
                        continue
                    scan_zip(io.BytesIO(zf.read(info)), artifact, full, entry_test, depth + 1, out)
            except (zipfile.BadZipFile, OSError, RuntimeError):
                continue


def scan_path(path: str, out: list[dict]) -> None:
    is_test = looks_like_test_path(path)
    lower = path.lower()
    try:
        if lower.endswith(".class"):
            with open(path, "rb") as fh:
                f = finding(path, path, is_test, fh.read())
            if f:
                out.append(f)
        elif lower.endswith(ARCHIVE_EXTS):
            with open(path, "rb") as fh:
                scan_zip(fh, path, "", is_test, 0, out)
    except OSError:
        return


def collect(paths: list[str]) -> list[str]:
    files: list[str] = []
    for p in paths:
        if os.path.isdir(p):
            for dirpath, dirnames, filenames in os.walk(p):
                dirnames[:] = [d for d in dirnames if d not in (".git", "node_modules")]
                files.extend(os.path.join(dirpath, fn) for fn in filenames if fn.lower().endswith(SCAN_EXTS))
        elif os.path.isfile(p):
            files.append(p)
    return sorted(set(files))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("paths", nargs="+")
    ap.add_argument("--jsonl", metavar="FILE", help="Write JSONL findings to FILE (default: stdout)")
    ap.add_argument("--quiet", action="store_true", help="Suppress summary on stderr")
    args = ap.parse_args()

    files = collect(args.paths)
    out: list[dict] = []
    for f in files:
        scan_path(f, out)

    sink = open(args.jsonl, "w", encoding="utf-8") if args.jsonl else sys.stdout
    try:
        for rec in out:
            sink.write(json.dumps(rec) + "\n")
    finally:
        if args.jsonl:
            sink.close()

    if not args.quiet:
        shaded = sum(1 for r in out if r["is_shaded"])
        tests = sum(1 for r in out if r["is_test_artifact"])
        print(f"[scan_java4shell_jars] scanned {len(files)} artifact(s); {len(out)} class(es) reference java.util.Base64 "
              f"decoding ({shaded} shaded, {tests} test)", file=sys.stderr)
    return 2 if out else 0


if __name__ == "__main__":
    raise SystemExit(main())
