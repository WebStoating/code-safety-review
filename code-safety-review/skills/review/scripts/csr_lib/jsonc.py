"""Tolerant JSON-with-comments loader (VS Code style: comments, trailing commas, BOM)."""
from __future__ import annotations

import json
from typing import Any


def strip(text: str) -> str:
    text = text.lstrip("\ufeff")
    out = []
    i, n = 0, len(text)
    in_str = False
    while i < n:
        c = text[i]
        if in_str:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if c == '"':
                in_str = False
            i += 1
            continue
        if c == '"':
            in_str = True
            out.append(c)
            i += 1
        elif c == "/" and i + 1 < n and text[i + 1] == "/":
            j = text.find("\n", i)
            i = n if j == -1 else j
        elif c == "/" and i + 1 < n and text[i + 1] == "*":
            j = text.find("*/", i + 2)
            seg = text[i:(n if j == -1 else j + 2)]
            out.append("\n" * seg.count("\n"))  # keep line numbers stable
            i = n if j == -1 else j + 2
        else:
            out.append(c)
            i += 1
    return _drop_trailing_commas("".join(out))


def _drop_trailing_commas(s: str) -> str:
    out = []
    in_str = False
    i, n = 0, len(s)
    while i < n:
        c = s[i]
        if in_str:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(s[i + 1])
                i += 2
                continue
            if c == '"':
                in_str = False
            i += 1
            continue
        if c == '"':
            in_str = True
        elif c == ",":
            j = i + 1
            while j < n and s[j] in " \t\r\n":
                j += 1
            if j < n and s[j] in "}]":
                i += 1
                continue
        out.append(c)
        i += 1
    return "".join(out)


def loads(text: str) -> Any:
    try:
        return json.loads(strip(text))
    except json.JSONDecodeError as e:
        raise ValueError(str(e)) from e
