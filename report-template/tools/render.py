#!/usr/bin/env python3
"""render.py - fill a Markdown report template with a facts JSON file.

    render.py TEMPLATE.md facts.json [-o out.md] [--strict]

Template syntax (deliberately small, no dependencies):
  {{path}}                    value; dotted paths walk dicts: {{fleet.exposed_vbmi}}, {{meta.org}}
  {{path|filter}}             filters: pct (0.42 -> 42%), int, n (thousands), upper, lower, yesno, count, join, date,
                              default:TEXT (used when the value is missing or empty), md (escape pipes for tables)
  {{#each path}} ... {{/each}}  repeat the block for every item; inside use {{.}} (scalar item), {{.field}}, {{@index}}
  {{#if path}} ... {{else}} ... {{/if}}   truthiness (empty list / 0 / "" / missing are false)
  {{! comment }}              dropped from the output
Missing values render as "—" and are listed on stderr; --strict makes them an error (exit 1).
Python 3.9+, standard library only.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from typing import Any, List, Optional, Tuple

TAG_RE = re.compile(r"\{\{\s*(?P<kind>#each|#if|/each|/if|else|!)?\s*(?P<body>[^}]*?)\s*\}\}", re.S)


COMMENT_RE = re.compile(r"[ \t]*\{\{!.*?\}\}[ \t]*\n?", re.S)
STANDALONE_RE = re.compile(r"(?m)^[ \t]*(\{\{\s*(?:#each|#if|/each|/if|else)\b[^}]*\}\})[ \t]*\n")


def preprocess(src: str) -> str:
    """Drop comments and the line break after a block tag that stands alone on its line (Mustache standalone rule)."""
    src = COMMENT_RE.sub("", src)
    return STANDALONE_RE.sub(r"\1", src)


def tokenize(src: str) -> List[Tuple[str, Any]]:
    src = preprocess(src)
    out: List[Tuple[str, Any]] = []
    pos = 0
    for m in TAG_RE.finditer(src):
        if m.start() > pos:
            out.append(("text", src[pos:m.start()]))
        kind = m.group("kind") or ""
        body = m.group("body").strip()
        if kind == "!":
            pass
        elif kind in ("#each", "#if"):
            out.append((kind[1:], body))
        elif kind in ("/each", "/if"):
            out.append(("end" + kind[1:], None))
        elif kind == "else":
            out.append(("else", None))
        else:
            path, _, filt = body.partition("|")
            out.append(("var", (path.strip(), filt.strip())))
        pos = m.end()
    if pos < len(src):
        out.append(("text", src[pos:]))
    return out


def parse(tokens: List[Tuple[str, Any]], i: int = 0, stop: Tuple[str, ...] = ()) -> Tuple[List[Any], int]:
    nodes: List[Any] = []
    while i < len(tokens):
        kind, val = tokens[i]
        if kind in stop:
            return nodes, i
        if kind == "text":
            nodes.append(("text", val))
            i += 1
        elif kind == "var":
            nodes.append(("var", val[0], val[1]))
            i += 1
        elif kind == "each":
            body, i = parse(tokens, i + 1, ("endeach",))
            nodes.append(("each", val, body))
            i += 1
        elif kind == "if":
            body, i = parse(tokens, i + 1, ("else", "endif"))
            else_body: List[Any] = []
            if i < len(tokens) and tokens[i][0] == "else":
                else_body, i = parse(tokens, i + 1, ("endif",))
            nodes.append(("if", val, body, else_body))
            i += 1
        else:
            raise ValueError(f"unexpected {kind} at token {i}")
    return nodes, i


class Renderer:
    def __init__(self, facts: Any):
        self.stack: List[Any] = [facts]
        self.index_stack: List[int] = []
        self.missing: List[str] = []

    def lookup(self, path: str) -> Tuple[bool, Any]:
        if path == ".":
            return True, self.stack[-1]
        if path == "@index":
            return (True, self.index_stack[-1]) if self.index_stack else (False, None)
        if path.startswith("."):
            parts = path[1:].split(".")
            ctx = self.stack[-1]
            return self._walk(ctx, parts)
        parts = path.split(".")
        for ctx in reversed(self.stack):
            ok, v = self._walk(ctx, parts)
            if ok:
                return True, v
        return False, None

    @staticmethod
    def _walk(ctx: Any, parts: List[str]) -> Tuple[bool, Any]:
        cur = ctx
        for p in parts:
            if isinstance(cur, dict) and p in cur:
                cur = cur[p]
            elif isinstance(cur, list) and p.isdigit() and int(p) < len(cur):
                cur = cur[int(p)]
            else:
                return False, None
        return True, cur

    def render(self, nodes: List[Any]) -> str:
        out: List[str] = []
        for n in nodes:
            if n[0] == "text":
                out.append(n[1])
            elif n[0] == "var":
                out.append(self.value(n[1], n[2]))
            elif n[0] == "each":
                ok, items = self.lookup(n[1])
                if not ok or not isinstance(items, (list, dict)):
                    if not ok:
                        self.missing.append(n[1])
                    continue
                seq = list(items.items()) if isinstance(items, dict) else items
                for idx, item in enumerate(seq, 1):
                    if isinstance(items, dict):
                        item = {"key": item[0], "value": item[1]}
                    self.stack.append(item)
                    self.index_stack.append(idx)
                    out.append(self.render(n[2]))
                    self.stack.pop()
                    self.index_stack.pop()
            elif n[0] == "if":
                ok, v = self.lookup(n[1])
                out.append(self.render(n[2]) if (ok and truthy(v)) else self.render(n[3]))
        return "".join(out)

    def value(self, path: str, filt: str) -> str:
        ok, v = self.lookup(path)
        default = None
        filters = [f.strip() for f in filt.split("|") if f.strip()] if filt else []
        for f in filters:
            if f.startswith("default:"):
                default = f[len("default:"):]
        if (not ok or v is None or v == "" or v == []) and default is not None:
            return default
        if not ok:
            self.missing.append(path)
            return "—"
        if v is None:
            return "—"
        for f in filters:
            v = apply_filter(f, v)
        if isinstance(v, bool):
            return "yes" if v else "no"
        if isinstance(v, float):
            return f"{v:,.2f}".rstrip("0").rstrip(".") if v != int(v) else f"{int(v):,}"
        if isinstance(v, (list, dict)):
            return json.dumps(v, ensure_ascii=False)
        return str(v)


def truthy(v: Any) -> bool:
    if isinstance(v, str):
        return v.strip() not in ("", "0", "false", "no", "—")
    return bool(v)


def apply_filter(f: str, v: Any) -> Any:
    if f.startswith("default:"):
        return v
    if f == "pct":
        try:
            return f"{float(v) * 100:.1f}%".replace(".0%", "%")
        except (TypeError, ValueError):
            return v
    if f == "int":
        try:
            return int(float(v))
        except (TypeError, ValueError):
            return v
    if f == "n":
        try:
            return f"{int(float(v)):,}"
        except (TypeError, ValueError):
            return v
    if f == "upper":
        return str(v).upper()
    if f == "lower":
        return str(v).lower()
    if f == "yesno":
        return "yes" if truthy(v) else "no"
    if f == "count":
        return len(v) if isinstance(v, (list, dict, str)) else v
    if f == "join":
        return ", ".join(str(x) for x in v) if isinstance(v, list) else v
    if f == "date":
        return str(v)[:10]
    if f == "md":
        return str(v).replace("|", "\\|").replace("\n", " ")
    return v


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("template")
    ap.add_argument("facts")
    ap.add_argument("-o", "--out")
    ap.add_argument("--strict", action="store_true", help="fail when a placeholder has no value")
    a = ap.parse_args(argv)
    with open(a.template, encoding="utf-8") as fh:
        src = fh.read()
    with open(a.facts, encoding="utf-8") as fh:
        facts = json.load(fh)
    nodes, _ = parse(tokenize(src))
    r = Renderer(facts)
    text = re.sub(r"\n{3,}", "\n\n", r.render(nodes)).lstrip("\n")
    if a.out:
        with open(a.out, "w", encoding="utf-8") as fh:
            fh.write(text)
    else:
        sys.stdout.write(text)
    if r.missing:
        uniq = sorted(set(r.missing))
        sys.stderr.write(f"[render] {len(uniq)} placeholder(s) without a value: {', '.join(uniq)}\n")
        if a.strict:
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
