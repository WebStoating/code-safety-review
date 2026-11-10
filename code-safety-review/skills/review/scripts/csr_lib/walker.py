"""Safe enumeration of a target folder: no symlink following, size caps, text sniffing."""
from __future__ import annotations

import os
from pathlib import Path
from typing import List, Optional, Tuple

from .model import FileEntry, Finding, Severity, Skipped

SKIP_DIRS = {(".git", "objects"), (".git", "lfs"), (".git", "modules")}
DEFAULT_MAX_BYTES = 5_000_000


def decode_text(data: bytes) -> Optional[str]:
    """Decode bytes to text if they look like text; return None for binary."""
    if not data:
        return ""
    text: Optional[str] = None
    if data.startswith(b"\xef\xbb\xbf"):
        text = _try(data[3:], "utf-8")
    elif data.startswith(b"\xff\xfe") or data.startswith(b"\xfe\xff"):
        text = _try(data, "utf-16")
    else:
        sample = data[:4096]
        if len(sample) >= 4 and b"\x00" in sample:
            even_nul = sample[0::2].count(0)
            odd_nul = sample[1::2].count(0)
            half = len(sample) / 2
            if odd_nul > 0.4 * half and even_nul < 0.05 * half:
                text = _try(data, "utf-16-le")
            elif even_nul > 0.4 * half and odd_nul < 0.05 * half:
                text = _try(data, "utf-16-be")
            else:
                return None
        else:
            text = _try(data, "utf-8")
            if text is None:
                # tolerate a few bad bytes (latin-1 files etc.)
                t = data.decode("utf-8", errors="replace")
                if t.count("�") <= max(4, len(t) // 100):
                    text = t
    if text is None:
        return None
    if not text:
        return text
    ctrl = sum(1 for ch in text[:20000] if ord(ch) < 32 and ch not in "\t\r\n\f\v\x1b")
    if ctrl > 0.05 * min(len(text), 20000):
        return None
    return text


def _try(data: bytes, enc: str) -> Optional[str]:
    try:
        return data.decode(enc)
    except (UnicodeDecodeError, LookupError):
        return None


def walk(root: Path, max_bytes: int = DEFAULT_MAX_BYTES) -> Tuple[List[FileEntry], List[Skipped], List[Finding]]:
    root = Path(root)
    root_real = os.path.realpath(root)
    files: List[FileEntry] = []
    skipped: List[Skipped] = []
    findings: List[Finding] = []

    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        rel_dir = os.path.relpath(dirpath, root)
        rel_dir = "" if rel_dir == "." else rel_dir.replace(os.sep, "/")
        parts = tuple(rel_dir.split("/")) if rel_dir else ()
        keep = []
        for d in sorted(dirnames):
            full = os.path.join(dirpath, d)
            rel = f"{rel_dir}/{d}" if rel_dir else d
            if os.path.islink(full):
                _symlink(full, rel, root_real, findings, skipped)
                continue
            if parts + (d,) in SKIP_DIRS or (len(parts) >= 1 and (parts[-1], d) in SKIP_DIRS):
                skipped.append(Skipped(rel, "git internal objects"))
                continue
            keep.append(d)
        dirnames[:] = keep
        for fn in sorted(filenames):
            full = os.path.join(dirpath, fn)
            rel = f"{rel_dir}/{fn}" if rel_dir else fn
            if os.path.islink(full):
                _symlink(full, rel, root_real, findings, skipped)
                continue
            try:
                st = os.lstat(full)
            except OSError as e:
                skipped.append(Skipped(rel, f"stat failed: {e}"))
                continue
            if not os.path.isfile(full):
                skipped.append(Skipped(rel, "not a regular file"))
                continue
            if st.st_size > max_bytes:
                skipped.append(Skipped(rel, f"size>{max_bytes}"))
                continue
            try:
                with open(full, "rb") as fh:
                    data = fh.read()
            except OSError as e:
                skipped.append(Skipped(rel, f"read failed: {e}"))
                continue
            text = decode_text(data)
            if text is None and _code_like(rel):
                # NUL/control bytes in a comment must not hide a code/config file from the rules
                text = data.decode("utf-8", errors="replace").replace("\x00", "\ufffd")
                findings.append(Finding(
                    "FS-CONTROL-CHARS", Severity.HIGH if _autorun_like(rel) else Severity.MEDIUM, rel, None,
                    "NUL/control characters in a source or config file",
                    f"{sum(1 for b in data if b < 9 or 13 < b < 32)} control bytes",
                    "Parsers and editors ignore these bytes inside comments, but naive tools treat the file as "
                    "binary and skip it. It was scanned as text anyway.",
                ))
            kind = "text" if text is not None else "binary"
            files.append(FileEntry(rel, Path(full), st.st_size, data if kind == "binary" else data[:65536], text, kind))
    return files, skipped, findings


CODE_LIKE_EXT = {".json", ".jsonc", ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".mts", ".cts", ".vue", ".svelte",
                 ".py", ".pth", ".sh", ".bash", ".zsh", ".ps1", ".bat", ".cmd", ".toml", ".yml", ".yaml", ".ini",
                 ".cfg", ".md", ".mdc", ".xml", ".code-workspace", ".dict", ".npl", ".txt", ".rb", ".pl", ".lock"}
CODE_LIKE_NAMES = {".npmrc", ".yarnrc", ".pnpmrc", ".cursorrules", ".windsurfrules", ".clinerules", "makefile",
                   "dockerfile", ".gitmodules", ".gitattributes", "config", ".env"}
AUTORUN_MARKERS = (".vscode/", ".devcontainer", ".claude/", ".codex/", ".cursor/", ".husky/", ".githooks/", ".git/",
                   ".idea/", ".github/workflows/")
AUTORUN_NAMES = {"package.json", ".npmrc", ".yarnrc", ".yarnrc.yml", "setup.py", "pyproject.toml", "conftest.py",
                 "__init__.py", "sitecustomize.py", "agents.md", "claude.md", "skill.md", "gemini.md", ".mcp.json",
                 ".gitmodules", "devcontainer.json"}


def _code_like(rel: str) -> bool:
    name = rel.rsplit("/", 1)[-1].lower()
    ext = ("." + name.rsplit(".", 1)[-1]) if "." in name.lstrip(".") else ""
    return ext in CODE_LIKE_EXT or name in CODE_LIKE_NAMES or rel.startswith(".git/hooks/")


def _autorun_like(rel: str) -> bool:
    low = "/" + rel.lower()
    name = low.rsplit("/", 1)[-1]
    return any("/" + m in low for m in AUTORUN_MARKERS) or name in AUTORUN_NAMES or name.endswith(".pth")


def _symlink(full: str, rel: str, root_real: str, findings: List[Finding], skipped: List[Skipped]) -> None:
    try:
        target = os.readlink(full)
    except OSError:
        target = "?"
    resolved = os.path.realpath(full)
    inside = resolved == root_real or resolved.startswith(root_real + os.sep)
    skipped.append(Skipped(rel, f"symlink -> {target} (not followed)"))
    if not inside:
        findings.append(Finding(
            "FS-SYMLINK-ESCAPE", Severity.MEDIUM, rel, None,
            "Symlink points outside the repository",
            f"{rel} -> {target}",
            "A symlink that leaves the repository can make tools read or write files elsewhere "
            "on your machine (e.g. ~/.ssh). It was not followed.",
        ))
