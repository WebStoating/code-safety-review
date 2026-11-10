"""Node.js / JavaScript / TypeScript: lifecycle scripts, npm config, lockfiles, entry points,
dangerous code combinations, obfuscation. (design §7.2)"""
from __future__ import annotations

import bisect
import json
import posixpath
import re
from typing import List, Optional, Tuple
from urllib.parse import urlparse

from .decode import line_of, snippet, try_base64, try_hex
from .model import FileEntry, Finding, ScanContext, Severity
from .patterns import (B64_ANY, B64_BLOB, CLIPBOARD, DATA_URI, DECODE_JS, ENV_DUMP_JS, EXEC_CMD_JS, EXEC_JS,
                       EXEC_NAMES, EXEC_STRONG_JS, HEX_BLOB, JOINED_NAME, NETWORK_CALL_JS, NETWORK_JS,
                       OBF_IDENT, RAW_IP_URL, SECRET_PATHS, WEBHOOK_HOSTS, command_risks, DANGEROUS_REASONS)

LIFECYCLE = ["preinstall", "install", "postinstall", "preprepare", "prepare", "postprepare", "prepublish",
             "prepack", "postpack", "dependencies"]
# Scripts npm runs for a package installed from the registry (prepare & co. only run for the root/git deps).
INSTALLED_LIFECYCLE = ["preinstall", "install", "postinstall"]
JS_EXT = {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".mts", ".cts", ".vue", ".svelte"}
PUBLIC_REGISTRIES = {"registry.npmjs.org", "registry.yarnpkg.com", "registry.npmmirror.com"}
LOCKFILES = {"package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock", "bun.lockb"}
NONREG_SPEC = re.compile(r"^(git\+|git:|github:|gitlab:|bitbucket:|gist:|https?:|file:|link:|portal:|patch:)"
                         r"|^[\w.-]+/[\w.-]+(#.*)?$", re.I)
RUNS_FILE = re.compile(r"\b(node|nodejs|bun|deno(?:\s+run)?|sh|bash|zsh|python3?|tsx|ts-node)\s+(?:-\S+\s+)*"
                       r"['\"]?(\.{0,2}/?[\w@./-]+\.(?:c|m)?(?:js|ts|sh|py))\b")
EXEC_CALL_STR = re.compile(r"\b(exec|execSync|spawn|spawnSync|execFile|execFileSync)\s*\(\s*(['\"`])(.{1,400}?)\2",
                           re.S)
AI_CLI = re.compile(r"""['"`](claude|gemini|q|codex|cursor-agent|amp|aider)['"`][^\n]{0,200}?"""
                    r"""(--dangerously-skip-permissions|--yolo|--trust-all-tools|--full-auto|['"`]-p['"`]|--print)""")
DEBUG_TRAP = re.compile(r"""constructor\s*\(\s*['"`]\s*while\s*\(\s*(true|!0|1)\s*\)\s*\{\s*\}\s*['"`]\s*\)""")


_ALLOWLIST = None


def _install_allowlisted(name: str) -> bool:
    global _ALLOWLIST
    if _ALLOWLIST is None:
        import fnmatch  # noqa: F401
        from pathlib import Path
        f = Path(__file__).resolve().parents[2] / "assets" / "install-script-allowlist.txt"
        try:
            _ALLOWLIST = {ln.strip() for ln in f.read_text().splitlines() if ln.strip() and not ln.startswith("#")}
        except OSError:
            _ALLOWLIST = set()
    import fnmatch
    return any(fnmatch.fnmatchcase(name or "", a) for a in _ALLOWLIST)


def _f(rule, sev, fe, line, title, snip, detail, decoded=None) -> Finding:
    return Finding(rule, sev, fe.rel, line, title, snip[:400], detail, decoded=decoded)


# ------------------------------------------------------------- JS helpers ----

def _decoded_strings(text: str, limit: int = 5) -> Optional[str]:
    out = []
    for pat in (B64_ANY, B64_BLOB):
        for m in pat.finditer(text):
            s = m.group(1) if m.groups() else m.group(0)
            if DATA_URI.search(text[max(0, m.start() - 40): m.start() + 1]):
                continue
            d = try_base64(s)
            if d and d not in out and (re.search(r"[:/.(]", d)):
                out.append(d)
            if len(out) >= limit:
                break
    for m in HEX_BLOB.finditer(text):
        d = try_hex(m.group(0))
        if d and d not in out:
            out.append(d)
    return "\n".join(x[:1500] for x in out) or None


def _near(a: re.Pattern, b: re.Pattern, text: str, window: int) -> Optional[int]:
    bpos = [m.start() for m in b.finditer(text)]
    if not bpos:
        return None
    for m in a.finditer(text):
        i = bisect.bisect_left(bpos, m.start() - window)
        if i < len(bpos) and bpos[i] <= m.start() + window:
            return min(bpos[i], m.start())
    return None


def _joined_exec_name(text: str) -> Optional[Tuple[int, str]]:
    for m in JOINED_NAME.finditer(text):
        word = "".join(re.findall(r"['\"]([A-Za-z_]+)['\"]", m.group(1)))
        if word in EXEC_NAMES:
            return m.start(), word
    return None


def js_combos(text: str) -> List[Tuple[Severity, str, int]]:
    """Return (severity, reason, index) for dangerous combinations in one JS file."""
    res = []
    m = DEBUG_TRAP.search(text)
    if m:
        res.append((Severity.CRITICAL, "anti-debugging infinite-loop trap (seen in infostealers)", m.start()))
    i = _near(DECODE_JS, EXEC_JS, text, 400)
    if i is not None:
        res.append((Severity.CRITICAL, "decodes data and executes it (decode → eval/exec)", i))
    i = _near(NETWORK_CALL_JS, EXEC_STRONG_JS, text, 800)
    if i is not None:
        res.append((Severity.CRITICAL, "downloads code and evaluates it (network → eval/Function/vm)", i))
    net = NETWORK_CALL_JS.search(text)
    if net:
        obfuscated = bool(DECODE_JS.search(text) or OBF_IDENT.search(text))
        for pat, what, sev in ((ENV_DUMP_JS, "serialises the whole environment", Severity.CRITICAL),
                               (CLIPBOARD, "reads the clipboard", Severity.CRITICAL),
                               (SECRET_PATHS, "reads credential/secret locations",
                                Severity.CRITICAL if obfuscated else Severity.HIGH)):
            s = pat.search(text)
            if s:
                res.append((sev, f"{what} and makes network requests", s.start()))
                break
    for m in EXEC_CALL_STR.finditer(text):
        danger = [r for r in command_risks(m.group(3)) if r in DANGEROUS_REASONS]
        if danger:
            res.append((Severity.CRITICAL, "spawns a shell command that " + ", ".join(danger), m.start()))
            break
    j = _joined_exec_name(text)
    if j is not None:
        res.append((Severity.HIGH if net else Severity.MEDIUM,
                    f"builds the name '{j[1]}' from string fragments (hides code execution)", j[0]))
    if not res:
        i = _near(EXEC_CMD_JS, NETWORK_CALL_JS, text, 300)
        if i is not None and re.search(r"child_process", text):
            res.append((Severity.HIGH, "runs commands next to network calls", i))
    return res


def _depth_map(text: str) -> List[int]:
    """Brace depth at each '{'/'}' change, skipping strings and comments. Returns per-index depth lookup list
    sampled lazily via _depth_at."""
    changes = []  # (index, depth_after)
    depth = 0
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c in "'\"`":
            q = c
            i += 1
            while i < n and text[i] != q:
                if text[i] == "\\":
                    i += 1
                i += 1
        elif c == "/" and i + 1 < n and text[i + 1] == "/":
            j = text.find("\n", i)
            i = n if j == -1 else j
            continue
        elif c == "/" and i + 1 < n and text[i + 1] == "*":
            j = text.find("*/", i + 2)
            i = n if j == -1 else j + 2
            continue
        elif c == "{":
            depth += 1
            changes.append((i, depth))
        elif c == "}":
            depth = max(0, depth - 1)
            changes.append((i, depth))
        i += 1
    return changes


def _depth_at(changes, idx: int) -> int:
    d = 0
    for pos, dep in changes:
        if pos >= idx:
            break
        d = dep
    return d


IIFE_START = re.compile(r"^\s*(?:['\"]use strict['\"];?\s*)?[;!(+~]\s*\(?\s*(?:async\s*)?(?:function\b|\([^)]*\)\s*=>)")


def top_level_hits(text: str) -> List[Tuple[str, int]]:
    changes = _depth_map(text)
    allowed = 1 if IIFE_START.match(text) else 0
    hits = []
    for pat, what in ((EXEC_JS, "code/command execution"), (NETWORK_CALL_JS, "network request"),
                      (SECRET_PATHS, "secret file access"), (ENV_DUMP_JS, "environment dump")):
        for m in pat.finditer(text):
            if _depth_at(changes, m.start()) <= allowed:
                hits.append((what, m.start()))
                break
    return hits


# ---------------------------------------------------------- package.json ----

def _entry_files(pkg: dict) -> List[str]:
    out = []
    # `bin` scripts only run when invoked as commands, so they are not import-time entry points.
    for k in ("main", "module", "browser"):
        if isinstance(pkg.get(k), str):
            out.append(pkg[k])
    ex = pkg.get("exports")
    dot = ex.get(".") if isinstance(ex, dict) else ex
    stack = [dot]
    while stack:
        v = stack.pop()
        if isinstance(v, str):
            out.append(v)
        elif isinstance(v, dict):
            stack.extend(v.values())
    if not out:
        out.append("index.js")
    return out


def _resolve_in_pkg(ctx: ScanContext, pkg_dir: str, ref: str) -> Optional[FileEntry]:
    ref = ref.strip("'\"")
    cand = posixpath.normpath(posixpath.join(pkg_dir, ref))
    for c in (cand, cand + ".js", cand + "/index.js", cand + ".cjs", cand + ".mjs"):
        if c in ctx.by_rel:
            return ctx.by_rel[c]
    return None


def _check_package_json(ctx: ScanContext, fe: FileEntry, out: List[Finding]) -> None:
    try:
        pkg = json.loads(fe.text or "")
    except ValueError:
        return
    if not isinstance(pkg, dict):
        return
    ctx.note("manifests", fe.rel)
    pkg_dir = posixpath.dirname(fe.rel)
    in_nm = "node_modules/" in fe.rel
    text = fe.text or ""

    scripts = pkg.get("scripts") if isinstance(pkg.get("scripts"), dict) else {}
    for key in (INSTALLED_LIFECYCLE if in_nm else LIFECYCLE):
        cmd = scripts.get(key)
        if not isinstance(cmd, str):
            continue
        ctx.note("autorun_files", fe.rel)
        reasons = command_risks(cmd)
        danger = [r for r in reasons if r in DANGEROUS_REASONS]
        sev = Severity.CRITICAL if danger else Severity.MEDIUM
        details = []
        m = RUNS_FILE.search(cmd)
        if m:
            target = _resolve_in_pkg(ctx, pkg_dir, m.group(2))
            if sev < Severity.HIGH:
                sev = Severity.HIGH
            if target is not None:
                ctx.note("entry_points", target.rel)
                combos = js_combos(target.text or "") if target.text else []
                if combos:
                    sev = Severity.CRITICAL
                    details.append(f"{target.rel}: " + "; ".join(c[1] for c in combos))
                else:
                    details.append(f"runs {target.rel} — read it in full")
            else:
                details.append(f"runs {m.group(2)} (not present in the scanned tree)")
        if danger:
            details.append("command " + ", ".join(danger))
        if in_nm and sev < Severity.CRITICAL and _install_allowlisted(str(pkg.get("name") or "")):
            sev = Severity.LOW
            details.append("package is on the well-known install-script allowlist")
        line = line_of(text, text.find(f'"{key}"')) if f'"{key}"' in text else None
        out.append(_f("NODE-LIFECYCLE-SCRIPT", sev, fe, line,
                      f"npm '{key}' script runs automatically on install" + (" (inside node_modules)" if in_nm else ""),
                      f'"{key}": {json.dumps(cmd)}',
                      "Lifecycle scripts execute during `npm install` with your privileges. " + "; ".join(details)))

    for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        deps = pkg.get(section)
        if not isinstance(deps, dict):
            continue
        for name, spec in deps.items():
            if isinstance(spec, str) and NONREG_SPEC.search(spec) and not spec.startswith("workspace:"):
                idx = text.find(f'"{name}"')
                out.append(_f("NODE-DEP-NONREGISTRY", Severity.MEDIUM, fe, line_of(text, idx) if idx >= 0 else None,
                              f"Dependency '{name}' is not installed from the npm registry",
                              f'"{name}": "{spec}"',
                              "Git/URL/file dependencies bypass registry malware scanning and can run "
                              "`prepare` scripts and ship their own .npmrc even with --ignore-scripts."))

    seen_targets = set()
    for ref in _entry_files(pkg):
        target = _resolve_in_pkg(ctx, pkg_dir, ref)
        if target is None or target.text is None or target.rel in seen_targets:
            continue
        seen_targets.add(target.rel)
        if not in_nm:
            ctx.note("entry_points", target.rel)
        hits = top_level_hits(target.text)
        if hits:
            kinds = sorted({h[0] for h in hits})
            combined = len(kinds) >= 2 and "network request" in kinds or any(
                c[0] == Severity.CRITICAL for c in js_combos(target.text))
            single = Severity.MEDIUM if in_nm else Severity.HIGH
            out.append(Finding("NODE-ENTRY-SIDE-EFFECT", Severity.CRITICAL if combined else single,
                               target.rel, line_of(target.text, hits[0][1]),
                               "Package entry point does work at import time",
                               snippet(target.text, hits[0][1]),
                               f"Top-level {', '.join(kinds)} runs as soon as the package is require()d "
                               "— `--ignore-scripts` does not prevent this."))


# --------------------------------------------------------------- npmrc ----

NPMRC_EXEC = re.compile(r"^\s*(git|script-shell|node-options|onload-script|shell|init-module|globalconfig|userconfig)"
                        r"\s*=\s*(.+)$", re.M | re.I)
YARNRC_EXEC = re.compile(r"^\s*(yarnPath|plugins|injectEnvironmentFiles|unsafeHttpWhitelist)\s*:\s*(.*)$", re.M)


YARNRC_V1_EXEC = re.compile(r"^\s*[\"']?(yarn-path|yarnPath)[\"']?\s+[\"']?([^\s\"']+)", re.M)


def _check_npmrc(fe: FileEntry, out: List[Finding]) -> None:
    text = fe.text or ""
    is_yarn_yml = fe.name.endswith(".yml")
    if fe.name == ".yarnrc":
        for m in YARNRC_V1_EXEC.finditer(text):
            out.append(_f("NODE-NPMRC-OVERRIDE", Severity.CRITICAL, fe, line_of(text, m.start()),
                          "Yarn config replaces the yarn binary (yarn-path)", m.group(0).strip(),
                          f"Every `yarn` command runs {m.group(2)} from this repository instead of Yarn."))
    for m in (YARNRC_EXEC if is_yarn_yml else NPMRC_EXEC).finditer(text):
        val = m.group(2).strip()
        inside = bool(re.match(r"\.{0,2}/|[\w.-]+/", val)) and not val.startswith("/usr/")
        if m.group(1) == "plugins":
            sev = Severity.HIGH
        else:
            sev = Severity.CRITICAL if inside else Severity.HIGH
        out.append(_f("NODE-NPMRC-OVERRIDE", sev, fe, line_of(text, m.start()),
                      f"Package-manager config overrides '{m.group(1)}'", m.group(0).strip(),
                      "This makes npm/yarn execute a different program (e.g. a fake git) — it runs even with "
                      "--ignore-scripts." + (" The target is inside the repository." if inside else "")))
    for m in re.finditer(r"^\s*(@[\w.-]+:)?registry\s*=\s*(\S+)|^\s*npmRegistryServer\s*:\s*(\S+)", text, re.M):
        url = (m.group(2) or m.group(3) or "").strip("'\"")
        host = urlparse(url).hostname or ""
        if host and host not in PUBLIC_REGISTRIES:
            out.append(_f("NODE-NPMRC-OVERRIDE", Severity.INFO, fe, line_of(text, m.start()),
                          "Custom registry configured", m.group(0).strip(),
                          "Packages resolve from a non-public registry (often a company registry). Private "
                          "packages are not looked up publicly."))


# ------------------------------------------------------------- lockfiles ----

def _check_lockfile(ctx: ScanContext, fe: FileEntry, out: List[Finding]) -> None:
    ctx.note("lockfiles", fe.rel)
    text = fe.text or ""
    bad_hosts, no_integ = [], []
    if fe.name in ("package-lock.json", "npm-shrinkwrap.json"):
        try:
            data = json.loads(text)
        except ValueError:
            return
        entries = data.get("packages") or data.get("dependencies") or {}
        for key, ent in entries.items():
            if not key or not isinstance(ent, dict) or ent.get("link"):
                continue
            res = ent.get("resolved") or ""
            name = key.split("node_modules/")[-1]
            if res:
                host = urlparse(res).hostname or ""
                if not res.startswith("https://") or host not in PUBLIC_REGISTRIES:
                    bad_hosts.append((name, res))
                elif not ent.get("integrity"):
                    no_integ.append(name)
    else:
        for m in re.finditer(r"(?:resolved|tarball)[\"']?\s*[:\s]\s*[\"']?((?:https?|git\+?\w*|file):[^\s\"',}]+)", text):
            res = m.group(1)
            host = urlparse(res).hostname or ""
            if host not in PUBLIC_REGISTRIES:
                bad_hosts.append(("?", res))
    for name, res in bad_hosts[:50]:
        idx = text.find(res)
        out.append(_f("NODE-LOCKFILE-SOURCE", Severity.MEDIUM, fe, line_of(text, idx) if idx >= 0 else None,
                      f"Locked package '{name}' resolves outside the public npm registry", res,
                      "Tarballs from other hosts/git are not covered by registry malware takedowns; verify the "
                      "host is expected (company registry) or treat as untrusted."))
    for name in no_integ[:50]:
        idx = text.find(f'node_modules/{name}"')
        out.append(_f("NODE-LOCKFILE-NO-INTEGRITY", Severity.LOW, fe, line_of(text, idx) if idx >= 0 else None,
                      f"Locked package '{name}' has no integrity hash", name,
                      "Without an integrity hash the tarball content is not pinned."))


# --------------------------------------------------------------- JS code ----

def _check_js(fe: FileEntry, out: List[Finding]) -> None:
    text = fe.text or ""
    minified = fe.name.endswith((".min.js", ".bundle.js")) or "/dist/" in "/" + fe.rel or \
        (len(text) > 5000 and text.count("\n") < len(text) / 2000)
    combos = js_combos(text)
    if "node_modules/" in fe.rel:  # third-party code: keep CRITICAL, soften heuristic HIGHs
        combos = [(Severity.MEDIUM if s == Severity.HIGH else s, w, i) for s, w, i in combos]
    for sev, why, idx in combos:
        out.append(_f("JS-DANGEROUS-COMBO", sev, fe, line_of(text, idx), why.capitalize(), snippet(text, idx),
                      f"{why}. This combination is typical of loaders and credential stealers.",
                      decoded=_decoded_strings(text)))
    m = AI_CLI.search(text)
    if m:
        out.append(_f("JS-AI-CLI-ABUSE", Severity.HIGH, fe, line_of(text, m.start()),
                      "Invokes a local AI coding agent with permissive flags", snippet(text, m.start()),
                      "Malware (e.g. the Nx compromise) drives installed AI CLIs to hunt for secrets."))
    if combos:
        return
    m = re.search(r"\beval\s*\(|\bnew\s+Function\s*\(|\bchild_process\b|\bvm\.runIn", text)
    if m:
        out.append(_f("JS-EXEC", Severity.LOW, fe, line_of(text, m.start()), "Dynamic code/command execution",
                      snippet(text, m.start()), "Single pattern; benign on its own. Check what feeds it."))
    m = RAW_IP_URL.search(text) or WEBHOOK_HOSTS.search(text)
    if m:
        out.append(_f("JS-NETWORK", Severity.MEDIUM, fe, line_of(text, m.start()),
                      "Contacts a raw IP or webhook/tunnel endpoint", snippet(text, m.start()),
                      "Hard-coded IPs and webhook services are common exfiltration endpoints."))
    m = SECRET_PATHS.search(text)
    if m:
        out.append(_f("JS-SECRET-READ", Severity.LOW, fe, line_of(text, m.start()), "References a credential location",
                      snippet(text, m.start()), "Check whether the code reads and sends it anywhere."))
    obf = len(OBF_IDENT.findall(text))
    blob = None
    for bm in list(B64_BLOB.finditer(text)) + list(HEX_BLOB.finditer(text)):
        if DATA_URI.search(text[max(0, bm.start() - 60): bm.start() + 1]):
            continue
        if try_base64(bm.group(0)) or try_hex(bm.group(0)):
            blob = bm
            break
    if obf >= 3 or blob:
        sev = Severity.MEDIUM if (obf >= 20 or blob) and not minified else Severity.LOW
        idx = blob.start() if blob else OBF_IDENT.search(text).start()
        out.append(_f("JS-OBFUSCATION", sev, fe, line_of(text, idx), "Obfuscated or encoded content",
                      snippet(text, idx), f"{obf} _0x identifiers" + ("; decodable encoded blob" if blob else ""),
                      decoded=_decoded_strings(text)))


def check(ctx: ScanContext) -> List[Finding]:
    out: List[Finding] = []
    for fe in ctx.files:
        if fe.text is None or fe.rel.startswith(".git/"):
            continue
        name = fe.name
        if name == "package.json":
            _check_package_json(ctx, fe, out)
        elif name in (".npmrc", ".yarnrc", ".yarnrc.yml", ".pnpmrc", "pnpm-workspace.yaml") and name != "pnpm-workspace.yaml":
            _check_npmrc(fe, out)
        elif name in LOCKFILES:
            _check_lockfile(ctx, fe, out)
        elif fe.ext in JS_EXT and not fe.name.endswith((".d.ts", ".d.mts", ".d.cts")):
            _check_js(fe, out)
    return out
