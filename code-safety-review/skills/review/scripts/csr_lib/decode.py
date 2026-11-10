"""Pure decoding helpers. Nothing here evaluates decoded content."""
from __future__ import annotations

import base64
import binascii
import re
from typing import Optional

INVISIBLE_RANGES = [
    (0x200B, 0x200F),  # zero-width, LRM/RLM
    (0x202A, 0x202E),  # bidi embeddings/overrides
    (0x2060, 0x2064),  # word joiner, invisible operators
    (0x2066, 0x2069),  # bidi isolates
    (0xFE00, 0xFE0F),  # variation selectors
    (0xFEFF, 0xFEFF),  # BOM / ZWNBSP
    (0x00AD, 0x00AD),  # soft hyphen
    (0x180E, 0x180E),  # mongolian vowel separator
    (0xE0000, 0xE007F),  # tags
    (0xE0100, 0xE01EF),  # variation selectors supplement
]


def is_invisible(cp: int) -> bool:
    for lo, hi in INVISIBLE_RANGES:
        if lo <= cp <= hi:
            return True
    return False


def escape_invisible(s: str) -> str:
    out = []
    for ch in s:
        cp = ord(ch)
        if is_invisible(cp) or (cp < 32 and ch not in "\t\n") or 0x7F <= cp <= 0x9F:
            out.append(f"<U+{cp:04X}>")
        else:
            out.append(ch)
    return "".join(out)


def decode_unicode_tags(s: str) -> str:
    """Return the ASCII text hidden in Unicode Tag characters (U+E0020..U+E007E)."""
    return "".join(chr(ord(c) - 0xE0000) for c in s if 0xE0020 <= ord(c) <= 0xE007E)


def _printable_ratio(t: str) -> float:
    if not t:
        return 0.0
    ok = sum(1 for c in t if c.isprintable() or c in "\r\n\t")
    return ok / len(t)


def try_base64(s: str) -> Optional[str]:
    s = s.strip().strip("'\"`")
    if len(s) < 8 or not re.fullmatch(r"[A-Za-z0-9+/_\-]+={0,2}", s):
        return None
    fns = (base64.urlsafe_b64decode,) if ("-" in s or "_" in s) else (base64.b64decode,)
    for fn in fns:
        try:
            padded = s + "=" * (-len(s) % 4)
            raw = fn(padded)
        except (binascii.Error, ValueError):
            continue
        try:
            t = raw.decode("utf-8")
        except UnicodeDecodeError:
            continue
        if _printable_ratio(t) > 0.95:
            return t
    return None


def try_hex(s: str) -> Optional[str]:
    s = s.strip().strip("'\"`")
    if "\\x" in s:
        s = "".join(re.findall(r"\\x([0-9a-fA-F]{2})", s))
    s = re.sub(r"\s+", "", s)
    if len(s) < 4 or len(s) % 2 or not re.fullmatch(r"[0-9a-fA-F]+", s):
        return None
    try:
        t = bytes.fromhex(s).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return None
    return t if _printable_ratio(t) > 0.95 else None


def decode_charcodes(expr: str) -> Optional[str]:
    m = re.search(r"fromCharCode\s*\(([\d\s,xXa-fA-F]+)\)", expr)
    nums = []
    if m:
        nums = [x.strip() for x in m.group(1).split(",") if x.strip()]
    else:
        nums = re.findall(r"chr\(\s*(0x[0-9a-fA-F]+|\d+)\s*\)", expr)
    if not nums:
        return None
    try:
        return "".join(chr(int(n, 0)) for n in nums)
    except ValueError:
        return None


def try_decode_any(s: str) -> Optional[str]:
    """Best-effort single-layer decode, peeling up to 3 layers of base64/hex."""
    cur = s
    result = None
    for _ in range(3):
        nxt = try_base64(cur) or try_hex(cur) or decode_charcodes(cur)
        if not nxt or nxt == cur:
            break
        result = cur = nxt
    return result


def line_of(text: str, index: int) -> int:
    return text.count("\n", 0, index) + 1


def snippet(text: str, index: int, width: int = 160) -> str:
    start = text.rfind("\n", 0, index) + 1
    end = text.find("\n", index)
    if end == -1:
        end = len(text)
    line = text[start:end]
    col = index - start
    if len(line) > width:
        lo = max(0, col - width // 3)
        line = ("…" if lo else "") + line[lo:lo + width] + ("…" if lo + width < len(line) else "")
    return escape_invisible(line.strip())
