"""Payloads hidden in non-code files, unexpected binaries, shipped secrets, known IOCs. (design §7.4)"""
from __future__ import annotations

import posixpath
import re
from typing import List, Optional

from .decode import line_of, snippet, try_base64, try_hex, decode_charcodes
from .model import FileEntry, Finding, ScanContext, Severity
from .patterns import (B64_BLOB, CHARCODE_CHAIN, DATA_URI, EXEC_JS, EXEC_PY, HEX_BLOB, INTERPRETER_ON_NONCODE,
                       KNOWN_IOCS, OBF_IDENT)

MAGIC = {
    ".woff": [b"wOFF"],
    ".woff2": [b"wOF2"],
    ".ttf": [b"\x00\x01\x00\x00", b"true", b"OTTO", b"ttcf"],
    ".otf": [b"OTTO", b"\x00\x01\x00\x00"],
    ".eot": None,  # header has no fixed prefix; checked for text content only
    ".png": [b"\x89PNG"],
    ".jpg": [b"\xff\xd8\xff"],
    ".jpeg": [b"\xff\xd8\xff"],
    ".gif": [b"GIF8"],
    ".ico": [b"\x00\x00\x01\x00", b"\x00\x00\x02\x00", b"\x89PNG"],
    ".webp": [b"RIFF"],
    ".bmp": [b"BM"],
    ".zip": [b"PK\x03\x04", b"PK\x05\x06"],
    ".gz": [b"\x1f\x8b"],
    ".tgz": [b"\x1f\x8b"],
    ".pdf": [b"%PDF"],
    ".wasm": [b"\x00asm"],
    ".mp3": [b"ID3", b"\xff\xfb", b"\xff\xf3", b"\xff\xf2"],
    ".mp4": None,
}
BINARY_EXT = {".node", ".exe", ".dll", ".so", ".dylib", ".bin", ".scr", ".cmd", ".bat", ".ps1", ".vbs", ".vbe",
              ".lnk", ".jar", ".msi", ".app", ".com", ".hta", ".wsf", ".pyc", ".pyd", ".elf"}
EXEC_MAGIC = [(b"\x7fELF", "ELF"), (b"\xcf\xfa\xed\xfe", "Mach-O"), (b"\xce\xfa\xed\xfe", "Mach-O"),
              (b"\xfe\xed\xfa\xcf", "Mach-O")]
DATA_EXT = {".dict", ".txt", ".npl", ".dat", ".csv", ".log", ".lock", ".cfg", ".ini"}
CMD_SOURCES = {".json", ".jsonc", ".sh", ".bash", ".zsh", ".yml", ".yaml", ".toml", ".cmd", ".bat", ".ps1",
               ".md", ".mk", ".code-workspace", ".js", ".mjs", ".cjs", ".ts", ".py", ".xml", ".cfg", ".ini", ""}
SECRET_NAMES = re.compile(r"^(\.env(\.[\w-]+)?|id_(rsa|dsa|ecdsa|ed25519)(\.pub)?|.*\.(pem|key|p12|pfx|keystore|jks)|"
                          r"credentials|\.git-credentials|\.netrc|\.pypirc)$", re.I)
SECRET_OK = re.compile(r"^\.env\.(example|sample|template|dist|defaults|schema)$|\.pub$", re.I)


def _sha(fe: FileEntry) -> str:
    return fe.sha256()


def _decoded_preview(text: str) -> Optional[str]:
    for pat, fn in ((HEX_BLOB, try_hex), (B64_BLOB, try_base64)):
        for m in pat.finditer(text):
            d = fn(m.group(0))
            if d:
                return d[:2000]
    m = CHARCODE_CHAIN.search(text)
    if m:
        end = text.find(")", m.end())
        d = decode_charcodes(text[m.start(): end + 1 if end != -1 else len(text)])
        if d:
            return d[:2000]
    return None


def _code_signals(text: str) -> List[str]:
    sig = []
    if EXEC_JS.search(text) or EXEC_PY.search(text):
        sig.append("code execution")
    if len(OBF_IDENT.findall(text)) >= 3:
        sig.append("obfuscated _0x identifiers")
    if CHARCODE_CHAIN.search(text):
        sig.append("fromCharCode/chr chain")
    if any(try_hex(m.group(0)) for m in HEX_BLOB.finditer(text)):
        sig.append("hex-encoded text")
    if any(try_base64(m.group(0)) for m in B64_BLOB.finditer(text) if not DATA_URI.search(
            text[max(0, m.start() - 40): m.start()])):
        sig.append("base64-encoded text")
    return sig


def _resolve(ctx: ScanContext, src: FileEntry, ref: str) -> Optional[FileEntry]:
    ref = ref.strip("'\"").replace("\\", "/")
    for base in ("", posixpath.dirname(src.rel), posixpath.dirname(posixpath.dirname(src.rel))):
        cand = posixpath.normpath(posixpath.join(base, ref.lstrip("/")))
        if cand in ctx.by_rel:
            return ctx.by_rel[cand]
    return None


def check(ctx: ScanContext) -> List[Finding]:
    out: List[Finding] = []
    for fe in ctx.files:
        if fe.rel.startswith(".git/"):
            continue
        ext = fe.ext
        name = fe.name

        # known indicators anywhere
        if fe.text is not None:
            m = KNOWN_IOCS.search(fe.text)
            if m:
                out.append(Finding("PAYLOAD-KNOWN-IOC", Severity.CRITICAL, fe.rel, line_of(fe.text, m.start()),
                                   "Known malware indicator", snippet(fe.text, m.start()),
                                   f"Matches an indicator from a published campaign: {m.group(0)}",
                                   sha256=_sha(fe)))

        # interpreter run on a non-code file (node x.woff2)
        if fe.text is not None and ext in CMD_SOURCES and fe.size < 1_000_000 and "lock" not in name.lower():
            for m in INTERPRETER_ON_NONCODE.finditer(fe.text):
                target = _resolve(ctx, fe, m.group(4))
                if target is not None and target.ext == ".md":
                    continue
                exists_text = target is not None and target.kind == "text" and target.ext in MAGIC
                if target is None and (fe.ext == ".md" or m.group(5).lower() in ("md", "txt", "log", "csv", "lock",
                                                                                   "map", "css")):
                    continue  # prose/docs mentioning a file that isn't shipped: not interesting
                if exists_text or (target is not None and _code_signals(target.text or "")):
                    sev = Severity.CRITICAL
                elif target is not None:
                    sev = Severity.HIGH
                else:
                    sev = Severity.MEDIUM  # referenced file not in the repo (may be fetched at runtime)
                out.append(Finding("PAYLOAD-INTERPRETER-NONCODE", sev, fe.rel, line_of(fe.text, m.start()),
                                   f"Interpreter executes a non-code file ({m.group(4)})",
                                   snippet(fe.text, m.start()),
                                   "Running node/python/sh on a font, image or data file is how loaders hide "
                                   "payloads (e.g. the fake-font campaign). "
                                   + (f"{target.rel} exists and contains text, not {target.ext} data."
                                      if exists_text else "")))

        # extension / magic mismatch
        if ext in MAGIC and fe.size > 0:
            magics = MAGIC[ext]
            ok = magics is None and fe.kind == "binary" or (magics and any(fe.data.startswith(mg) for mg in magics))
            if not ok or fe.kind == "text":  # a correct magic prefix followed by text/JS is still a disguise
                if fe.kind == "text":
                    sig = _code_signals(fe.text or "")
                    sev = Severity.CRITICAL if sig else Severity.HIGH
                    out.append(Finding("PAYLOAD-EXT-MISMATCH", sev, fe.rel, 1,
                                       f"{ext} file contains text, not {ext[1:]} data",
                                       snippet(fe.text or "", 0),
                                       "A binary asset that is actually text is a classic payload hiding spot. "
                                       + ("Signals: " + ", ".join(sig) + "." if sig else ""),
                                       decoded=_decoded_preview(fe.text or ""), sha256=_sha(fe)))
                elif magics:
                    out.append(Finding("PAYLOAD-EXT-MISMATCH", Severity.MEDIUM, fe.rel, None,
                                       f"{ext} file has unexpected magic bytes",
                                       fe.data[:16].hex(" "), "File header doesn't match its extension.",
                                       sha256=_sha(fe)))

        # code hidden in data files
        if fe.kind == "text" and (ext in DATA_EXT or ext == ".svg" or name.endswith(".dict")):
            text = fe.text or ""
            if ext == ".svg":
                m = re.search(r"<script\b|\son\w+\s*=", text, re.I)
                if m:
                    out.append(Finding("PAYLOAD-CODE-IN-DATA", Severity.MEDIUM, fe.rel, line_of(text, m.start()),
                                       "SVG contains script/event handler", snippet(text, m.start()),
                                       "SVGs with script run when opened in a browser or previewed."))
            else:
                sig = _code_signals(text)
                if "code execution" in sig and len(sig) >= 2 or (ext == ".npl" and sig):
                    m = EXEC_JS.search(text) or EXEC_PY.search(text)
                    idx = m.start() if m else 0
                    out.append(Finding("PAYLOAD-CODE-IN-DATA", Severity.HIGH, fe.rel, line_of(text, idx),
                                       f"Obfuscated code inside a {ext or name} data file",
                                       snippet(text, idx), "Signals: " + ", ".join(sig) +
                                       ". Data files are a fallback hiding place (e.g. spellright.dict).",
                                       decoded=_decoded_preview(text), sha256=_sha(fe)))

        # binaries
        exe_magic = next((label for mg, label in EXEC_MAGIC if fe.data.startswith(mg)), None)
        if exe_magic is None and fe.data.startswith(b"MZ") and b"PE\x00\x00" in fe.data[:1024]:
            exe_magic = "PE"
        if ext in BINARY_EXT or exe_magic:
            rel_l = fe.rel.lower()
            native_ok = ext in (".node", ".so", ".dylib", ".dll") and ("/build/release/" in rel_l or
                                                                      "/prebuilds/" in rel_l)
            if exe_magic and ext not in BINARY_EXT and ext not in (".node", ""):
                sev, title = Severity.HIGH, f"{exe_magic} executable disguised as {ext or 'extensionless file'}"
            elif native_ok or ext == ".pyc":
                sev, title = Severity.LOW, f"Prebuilt native/bytecode file ({ext})"
            else:
                sev, title = Severity.MEDIUM, f"Executable/script binary shipped ({ext or exe_magic})"
            out.append(Finding("PAYLOAD-BINARY", sev, fe.rel, None, title, f"{fe.size} bytes",
                               "Binaries can't be reviewed as source; verify origin or rebuild from source.",
                               sha256=_sha(fe)))

        # shipped secrets
        if SECRET_NAMES.match(name) and not SECRET_OK.search(name):
            out.append(Finding("PAYLOAD-SECRET-FILE", Severity.MEDIUM, fe.rel, None,
                               "Credential/secret file shipped in the repository", name,
                               "Shipped .env/keys may be bait or leaked secrets; don't load them.", sha256=_sha(fe)))
        elif name == ".npmrc" and fe.text and "_authToken" in fe.text:
            out.append(Finding("PAYLOAD-SECRET-FILE", Severity.MEDIUM, fe.rel, None, ".npmrc contains an auth token",
                               ".npmrc", "Shipped registry credentials.", sha256=_sha(fe)))
    return out
