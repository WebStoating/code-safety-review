"""Python: setup.py / build backends, .pth, import-time side effects, index URLs,
dangerous code combinations. (design §7.3) Files are parsed with `ast`, never executed."""
from __future__ import annotations

import ast
import re
from typing import List, Optional, Tuple

from .decode import line_of, snippet, try_base64, try_hex, decode_charcodes
from .model import FileEntry, Finding, ScanContext, Severity
from .patterns import (CHARCODE_CHAIN, CLIPBOARD, DANGEROUS_REASONS, DECODE_PY, ENV_DUMP_PY as ENV_DUMP, EXEC_PY, NETWORK_PY,
                       RAW_IP_URL, SECRET_PATHS, WEBHOOK_HOSTS, B64_BLOB, HEX_BLOB, IPV4, command_risks)

PY_MANIFESTS = {"pyproject.toml", "setup.py", "setup.cfg", "pipfile"}
PY_LOCKS = {"pipfile.lock", "poetry.lock", "uv.lock", "pdm.lock"}
INSTALL_BASES = re.compile(r"\b(install|develop|egg_info|build_py|build_ext|build|sdist|bdist_\w+|install_\w+|"
                           r"easy_install|test)\b")
IMPORT_TIME_FILES = {"__init__.py", "__main__.py", "conftest.py", "noxfile.py", "sitecustomize.py",
                     "usercustomize.py", "manage.py"}
SHELL_STR = re.compile(r"\b(os\.system|os\.popen|subprocess\.\w+|Popen)\s*\(\s*\[?\s*(?:f|r|b)?(['\"])(.{1,400}?)\2",
                       re.S)


def _f(rule, sev, fe, line, title, snip, detail, decoded=None) -> Finding:
    return Finding(rule, sev, fe.rel, line, title, snip[:400], detail, decoded=decoded)


def _strings(tree: Optional[ast.AST], text: str) -> List[str]:
    vals = []
    if tree is not None:
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, (str, bytes)):
                v = node.value.decode("latin-1") if isinstance(node.value, bytes) else node.value
                if len(v) >= 16:
                    vals.append(v)
    else:
        vals = re.findall(r"['\"]([A-Za-z0-9+/=]{16,})['\"]", text)
    return vals


def decoded_preview(tree, text: str) -> Optional[str]:
    out = []
    for s in _strings(tree, text):
        d = try_base64(s) or try_hex(s)
        if d and d not in out:
            out.append(d[:1500])
    m = CHARCODE_CHAIN.search(text)
    if m:
        d = decode_charcodes(text[m.start(): m.end() + 20])
        if d:
            out.append(d)
    return "\n".join(out[:5]) or None


def py_combos(text: str) -> List[Tuple[Severity, str, int]]:
    res = []
    for d in DECODE_PY.finditer(text):
        for e in EXEC_PY.finditer(text):
            if abs(e.start() - d.start()) <= 400 and re.match(r"(exec|eval|compile|__import__|os\.system|"
                                                               r"marshal|subprocess|os\.popen)",
                                                               e.group(0)):
                res.append((Severity.CRITICAL, "decodes data and executes it (decode → exec)", min(d.start(), e.start())))
                break
        if res:
            break
    for n in NETWORK_PY.finditer(text):
        e = re.compile(r"(?<![\w.])(exec|eval|compile)\s*\(|\bmarshal\.loads\s*\(").search(
            text, max(0, n.start() - 400), n.end() + 400)
        if e:
            res.append((Severity.CRITICAL, "downloads code and executes it (network → exec/eval)", min(e.start(), n.start())))
            break
    if NETWORK_PY.search(text):
        obfuscated = bool(DECODE_PY.search(text))
        for pat, what, sev in ((ENV_DUMP, "serialises the environment", Severity.CRITICAL),
                               (CLIPBOARD, "reads the clipboard", Severity.CRITICAL),
                               (SECRET_PATHS, "reads credential/secret locations",
                                Severity.CRITICAL if obfuscated else Severity.HIGH)):
            s = pat.search(text)
            if s:
                res.append((sev, f"{what} and makes network requests", s.start()))
                break
    for m in SHELL_STR.finditer(text):
        danger = [r for r in command_risks(m.group(3)) if r in DANGEROUS_REASONS]
        if danger:
            res.append((Severity.CRITICAL, "runs a shell command that " + ", ".join(danger), m.start()))
            break
    return res


def _parse(fe: FileEntry) -> Optional[ast.AST]:
    try:
        return ast.parse(fe.text or "", filename=fe.rel)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return None


def _is_main_guard(node: ast.stmt) -> bool:
    return isinstance(node, ast.If) and "__name__" in ast.dump(node.test) and "__main__" in ast.dump(node.test)


def _module_level_segments(tree: ast.Module, text: str) -> List[Tuple[int, str]]:
    segs = []
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Import, ast.ImportFrom)):
            continue
        if _is_main_guard(node):
            continue
        if isinstance(node, ast.Expr) and isinstance(getattr(node, "value", None), ast.Constant):
            continue  # docstring
        seg = ast.get_source_segment(text, node) or ""
        segs.append((node.lineno, seg))
    return segs


def _kinds(seg: str) -> List[str]:
    k = []
    if EXEC_PY.search(seg):
        k.append("code/command execution")
    if NETWORK_PY.search(seg) or RAW_IP_URL.search(seg):
        k.append("network connection")
    if SECRET_PATHS.search(seg) or ENV_DUMP.search(seg):
        k.append("secret/environment access")
    return k


def _check_setup_py(ctx: ScanContext, fe: FileEntry, tree, out: List[Finding]) -> None:
    text = fe.text or ""
    ctx.note("autorun_files", fe.rel)
    if tree is None:
        out.append(_f("PY-UNPARSEABLE", Severity.INFO, fe, None, "setup.py could not be parsed", fe.rel,
                      "Not valid Python 3; scanned with regex only."))
        for sev, why, idx in py_combos(text):
            out.append(_f("PY-SETUP-TOPLEVEL", sev, fe, line_of(text, idx), why, snippet(text, idx),
                          "Code in setup.py runs on `pip install`."))
        return
    for node in tree.body:
        if isinstance(node, ast.ClassDef):
            bases = " ".join(ast.get_source_segment(text, b) or "" for b in node.bases)
            if INSTALL_BASES.search(bases):
                seg = ast.get_source_segment(text, node) or ""
                combos = py_combos(seg)
                kinds = _kinds(seg)
                sev = Severity.CRITICAL if combos or len(kinds) >= 2 else Severity.HIGH
                out.append(_f("PY-SETUP-CMDCLASS", sev, fe, node.lineno,
                              f"setup.py overrides the '{bases}' command (class {node.name})",
                              snippet(text, text.find(f"class {node.name}")),
                              "Custom install/build commands execute during `pip install`. "
                              + "; ".join([c[1] for c in combos] + kinds),
                              decoded=decoded_preview(node, seg)))
    for lineno, seg in _module_level_segments(tree, text):
        kinds = _kinds(seg)
        if not kinds:
            continue
        combos = py_combos(seg)
        sev = Severity.CRITICAL if combos else Severity.MEDIUM
        out.append(_f("PY-SETUP-TOPLEVEL", sev, fe, lineno, "setup.py runs code at module level",
                      seg.splitlines()[0] if seg else "", ", ".join(kinds) + " outside setup(); runs on install.",
                      decoded=decoded_preview(None, seg)))


def _check_import_time(ctx: ScanContext, fe: FileEntry, tree, out: List[Finding]) -> None:
    text = fe.text or ""
    if tree is None:
        out.append(_f("PY-UNPARSEABLE", Severity.INFO, fe, None, f"{fe.name} could not be parsed", fe.rel,
                      "Not valid Python 3; regex checks only."))
        return
    for lineno, seg in _module_level_segments(tree, text):
        kinds = _kinds(seg)
        if not kinds:
            continue
        combos = py_combos(seg)
        combined = combos or (len(kinds) >= 2 and "network connection" in kinds)
        if fe.name in ("sitecustomize.py", "usercustomize.py"):
            rule = "PY-SITECUSTOMIZE"
        else:
            rule = "PY-INIT-SIDE-EFFECT"
        if fe.name == "__main__.py":
            sev = Severity.CRITICAL if combined else Severity.MEDIUM
        else:
            sev = Severity.CRITICAL if combined else Severity.HIGH
        ips = IPV4.findall(seg)
        when = {"conftest.py": "whenever pytest runs", "noxfile.py": "whenever nox runs",
                "__main__.py": "when run with python -m"}.get(fe.name, "as soon as the module is imported")
        out.append(_f(rule, sev, fe, lineno, f"{fe.name} does {', '.join(kinds)} at import time",
                      seg.strip().splitlines()[0] if seg.strip() else "",
                      f"Module-level code runs {when}. " + "; ".join(c[1] for c in combos)
                      + (f" Hosts/IPs: {', '.join(ips)}." if ips else ""),
                      decoded=decoded_preview(None, seg)))


def _check_pth(fe: FileEntry, out: List[Finding]) -> None:
    text = fe.text or ""
    for m in re.finditer(r"^\s*import\b.*$", text, re.M):
        line = m.group(0)
        danger = [r for r in command_risks(line) if r in DANGEROUS_REASONS] or py_combos(line)
        sev = Severity.CRITICAL if (danger or EXEC_PY.search(line) or NETWORK_PY.search(line)) else Severity.HIGH
        out.append(_f("PY-PTH-IMPORT", sev, fe, line_of(text, m.start()),
                      ".pth file executes code at interpreter start-up", line.strip(),
                      "Lines starting with `import` in a .pth file run every time Python starts in an environment "
                      "where this package is installed."))


INDEX_RE = re.compile(r"^\s*(--extra-index-url|--index-url|-i|--trusted-host|--find-links|-f)[\s=]+(\S+)", re.M)


def _check_requirements(ctx: ScanContext, fe: FileEntry, out: List[Finding]) -> None:
    text = fe.text or ""
    ctx.note("manifests", fe.rel)
    for m in INDEX_RE.finditer(text):
        opt, url = m.group(1), m.group(2)
        if "pypi.org" in url or "pythonhosted.org" in url:
            continue
        sev = Severity.HIGH if opt == "--extra-index-url" else Severity.MEDIUM
        out.append(_f("PY-INDEX-URL", sev, fe, line_of(text, m.start()), f"Requirements use {opt} {url}",
                      m.group(0).strip(),
                      "--extra-index-url enables dependency confusion: pip picks the highest version from ANY index."
                      if opt == "--extra-index-url" else "Packages may come from a non-PyPI source."))
    for m in re.finditer(r"^\s*([\w.\-\[\]]+\s*@\s*)?(git\+\S+|https?://\S+\.(?:zip|whl|tar\.gz))", text, re.M):
        out.append(_f("PY-DEP-NONREGISTRY", Severity.MEDIUM, fe, line_of(text, m.start()),
                      "Requirement installed from a URL/VCS", m.group(0).strip(),
                      "Direct URL/VCS requirements bypass PyPI and run their build backend on install."))


def _check_pyproject(ctx: ScanContext, fe: FileEntry, out: List[Finding]) -> None:
    text = fe.text or ""
    ctx.note("manifests", fe.rel)
    m = re.search(r"^\s*backend-path\s*=", text, re.M)
    if m:
        out.append(_f("PY-LOCAL-BUILD-BACKEND", Severity.HIGH, fe, line_of(text, m.start()),
                      "Build backend is loaded from the repository", snippet(text, m.start()),
                      "`pip install .`/`pip wheel` will import and execute the in-tree backend module."))
    for pat, what in ((r"^\s*\[tool\.hatch\.build(\.targets\.\w+)?\.hooks\.custom\]", "Hatch custom build hook"),
                      (r"^\s*\[tool\.poetry\.build\]", "Poetry build script"),
                      (r"^\s*\[tool\.pdm\.build\][^\[]*run-setuptools", "PDM setuptools build")):
        m = re.search(pat, text, re.M | re.S)
        if m:
            out.append(_f("PY-LOCAL-BUILD-BACKEND", Severity.MEDIUM, fe, line_of(text, m.start()), what,
                          snippet(text, m.start()), "Executes repository code during build/install."))
    for m in re.finditer(r"^\s*(extra-index-url|index-url|url)\s*=\s*[\"'](\S+)[\"']", text, re.M):
        if "pypi.org" not in m.group(2) and re.search(r"\[\[?tool\.(uv|poetry|pdm)", text[:m.start()]):
            out.append(_f("PY-INDEX-URL", Severity.MEDIUM, fe, line_of(text, m.start()),
                          "Custom package index configured", m.group(0).strip(), "Packages may come from a non-PyPI index."))
    for m in re.finditer(r"[\"'][\w.\-\[\]]+\s*@\s*(git\+[^\"']+|https?://[^\"']+)[\"']", text):
        out.append(_f("PY-DEP-NONREGISTRY", Severity.MEDIUM, fe, line_of(text, m.start()),
                      "Dependency installed from a URL/VCS", m.group(0), "Bypasses PyPI."))


def _check_generic_py(fe: FileEntry, tree, out: List[Finding]) -> bool:
    text = fe.text or ""
    combos = py_combos(text)
    for sev, why, idx in combos:
        out.append(_f("PY-DANGEROUS-COMBO", sev, fe, line_of(text, idx), why.capitalize(), snippet(text, idx),
                      f"{why}. Typical of droppers and credential stealers.", decoded=decoded_preview(tree, text)))
    if combos:
        return True
    m = re.search(r"(?<![\w.])(exec|eval|compile)\s*\(|__import__\s*\(|\bos\.(system|popen)\s*\(|marshal\.loads", text)
    if m:
        out.append(_f("PY-EXEC", Severity.LOW, fe, line_of(text, m.start()), "Dynamic code/command execution",
                      snippet(text, m.start()), "Single pattern; benign on its own. Check what feeds it."))
    m = RAW_IP_URL.search(text) or WEBHOOK_HOSTS.search(text)
    if m:
        out.append(_f("PY-NETWORK", Severity.MEDIUM, fe, line_of(text, m.start()),
                      "Contacts a raw IP or webhook/tunnel endpoint", snippet(text, m.start()),
                      "Hard-coded IPs and webhook services are common exfiltration endpoints."))
    m = SECRET_PATHS.search(text)
    if m:
        out.append(_f("PY-SECRET-READ", Severity.LOW, fe, line_of(text, m.start()), "References a credential location",
                      snippet(text, m.start()), "Check whether the code reads and sends it anywhere."))
    blob = next((b for b in list(B64_BLOB.finditer(text)) + list(HEX_BLOB.finditer(text))
                 if try_base64(b.group(0)) or try_hex(b.group(0))), None)
    ch = CHARCODE_CHAIN.search(text)
    if blob or ch:
        idx = (blob or ch).start()
        out.append(_f("PY-OBFUSCATION", Severity.MEDIUM, fe, line_of(text, idx), "Encoded/obfuscated content",
                      snippet(text, idx), "Decodable blob or chr() chain.", decoded=decoded_preview(tree, text)))
    return False


def check(ctx: ScanContext) -> List[Finding]:
    out: List[Finding] = []
    for fe in ctx.files:
        if fe.text is None or fe.rel.startswith(".git/"):
            continue
        name = fe.name
        low = name.lower()
        if low in PY_MANIFESTS or re.match(r"requirements.*\.(txt|in)$", low) or low in ("pip.conf", "uv.toml"):
            ctx.note("manifests", fe.rel)
        if low in PY_LOCKS:
            ctx.note("lockfiles", fe.rel)
        if fe.ext == ".pth":
            ctx.note("autorun_files", fe.rel)
            _check_pth(fe, out)
        elif low == "pyproject.toml":
            _check_pyproject(ctx, fe, out)
        elif re.match(r"(requirements|constraints).*\.(txt|in)$", low) or low in ("pip.conf", "pip.ini", "uv.toml"):
            _check_requirements(ctx, fe, out)
        elif fe.ext == ".py":
            tree = _parse(fe)
            if name == "setup.py":
                _check_setup_py(ctx, fe, tree, out)
            elif name in IMPORT_TIME_FILES:
                _check_import_time(ctx, fe, tree, out)
            _check_generic_py(fe, tree, out)
    return out
