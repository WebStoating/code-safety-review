"""Git repository checks: executable config, active hooks, submodules, history anomalies. (design §7.6)

git is only invoked when .git/config defines nothing executable, and always with hooks, fsmonitor,
pagers, external diff and textconv disabled and with system/global config ignored.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Tuple

from .decode import line_of
from .model import FileEntry, Finding, ScanContext, Severity

CRITICAL_KEYS = [r"core\.fsmonitor", r"core\.hookspath", r"filter\..+\.(clean|smudge|process)", r"alias\..+",
                 r"include\.path", r"includeif\..+\.path", r"core\.sshcommand", r"protocol\.ext\.allow",
                 r"uploadpack\.packobjectshook", r"remote\..+\.(uploadpack|receivepack|vcs|proxy)",
                 r"extensions\.partialclone", r"core\.alternaterefscommand", r"submodule\..+\.update"]
HIGH_KEYS = [r"core\.pager", r"pager\..+", r"core\.editor", r"sequence\.editor", r"core\.askpass", r"core\.gitproxy",
             r"gpg\.program", r"gpg\..+\.program", r"credential\.helper", r"credential\..+\.helper",
             r"diff\..+\.(textconv|command)", r"diff\.external", r"merge\..+\.driver", r"interactive\.difffilter",
             r"core\.worktree"]
DANGEROUS_KEYS = CRITICAL_KEYS + HIGH_KEYS
SAFE_VALUES = re.compile(r"git-lfs (smudge|clean)( -- %f)?|git-lfs filter-process|true|false|cat|less( -[A-Za-z]+)?|"
                         r"vim?|nano|code --wait|osxkeychain|manager(-core)?|cache( --timeout[= ]\d+)?|store", re.I)
HISTORY_PATHSPECS = [".vscode", ".devcontainer", ".github/workflows", ":(glob)**/package.json",
                     ":(glob)**/.npmrc", ":(glob)**/setup.py", ":(glob)**/*.pth", ":(glob)**/AGENTS.md",
                     ":(glob)**/CLAUDE.md", ":(glob)**/SKILL.md", ":(glob)**/.mcp.json", ":(glob)**/.claude/**",
                     ":(glob)**/*.code-workspace", ":(glob)**/pyproject.toml"]


def parse_git_config(text: str) -> List[Tuple[str, str, str]]:
    out = []
    section = ""
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line[0] in "#;":
            continue
        m = re.match(r'^\[\s*([^\]\s"]+)(?:\s+"((?:[^"\\]|\\.)*)")?\s*\]', line)
        if m:
            section = m.group(1).lower() + (f".{m.group(2)}" if m.group(2) is not None else "")
            rest = line[m.end():].strip()
            if not rest:
                continue
            line = rest
        if "=" in line:
            k, v = line.split("=", 1)
            v = v.strip()
            if len(v) >= 2 and v[0] == v[-1] == '"':
                v = v[1:-1]
            out.append((section, k.strip().lower(), v))
        else:
            out.append((section, line.lower(), "true"))
    return out


def _key_sev(full: str, value: str) -> Optional[Severity]:
    if any(re.fullmatch(p, full) for p in CRITICAL_KEYS):
        if (full.startswith("alias.") or full.startswith("submodule.")) and not value.startswith("!"):
            return None
        if full == "extensions.partialclone":
            return Severity.HIGH  # enables lazy fetches that can run remote.*.uploadpack
        if SAFE_VALUES.fullmatch(value.strip()):
            return Severity.LOW
        return Severity.CRITICAL
    if any(re.fullmatch(p, full) for p in HIGH_KEYS):
        return Severity.LOW if SAFE_VALUES.fullmatch(value.strip()) else Severity.HIGH
    return None


def git_env() -> dict:
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update({"GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull, "GIT_TERMINAL_PROMPT": "0",
                "GIT_OPTIONAL_LOCKS": "0", "GIT_PAGER": "cat", "PAGER": "cat", "GIT_EXTERNAL_DIFF": "",
                "GIT_NO_LAZY_FETCH": "1",      # never fetch missing objects (partial-clone uploadpack abuse)
                "GIT_ALLOW_PROTOCOL": "",      # no transport may be used at all
                "GIT_NO_REPLACE_OBJECTS": "1"})
    return env


def _read_config(path: Path) -> Optional[str]:
    try:
        with open(path, "rb") as fh:
            data = fh.read(50_000_000)
    except OSError:
        return None
    return data.decode("utf-8", errors="replace")


def _git(root: Path, args: List[str]) -> Optional[str]:
    exe = shutil.which("git")
    if not exe:
        return None
    env = git_env()
    cmd = [exe, "--no-pager", "-c", "core.fsmonitor=false", "-c", f"core.hooksPath={os.devnull}",
           "-c", "core.pager=cat", "-c", "log.showSignature=false", "-c", "diff.external=",
           "-c", f"safe.directory={root}", "-C", str(root)] + args
    try:
        r = subprocess.run(cmd, capture_output=True, env=env, timeout=30, stdin=subprocess.DEVNULL)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if r.returncode != 0:
        return None
    return r.stdout.decode("utf-8", errors="replace")


def _dt(s: str) -> Optional[datetime]:
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None


def check(ctx: ScanContext) -> List[Finding]:
    out: List[Finding] = []
    if not ctx.include_git:
        return out
    root = ctx.root
    git_path = root / ".git"

    for fe in ctx.files:
        if fe.name == ".gitmodules" and fe.text:
            for m in re.finditer(r"^\s*(url|path)\s*=\s*(.+)$", fe.text, re.M):
                key, val = m.group(1), m.group(2).strip()
                if val.startswith("ext::"):
                    sev, why = Severity.CRITICAL, "ext:: transport runs an arbitrary command"
                elif val.startswith("-"):
                    sev, why = Severity.HIGH, "value starting with '-' can inject git options"
                elif key == "url" and re.match(r"(http|file|git)://|/|\.\./", val):
                    sev, why = Severity.MEDIUM, "unencrypted or local submodule source"
                else:
                    continue
                out.append(Finding("GIT-SUBMODULE", sev, fe.rel, line_of(fe.text, m.start()),
                                   f"Suspicious submodule {key}", m.group(0).strip(),
                                   f"{why}. Submodules are fetched on `git clone --recursive` / `submodule update`."))
        elif fe.name == ".gitattributes" and fe.text:
            m = re.search(r"\b(filter|diff|merge)=(\S+)", fe.text)
            if m and m.group(2) != "lfs":
                out.append(Finding("GIT-ATTRIBUTES-FILTER", Severity.LOW, fe.rel, line_of(fe.text, m.start()),
                                   ".gitattributes assigns a custom filter/driver", m.group(0),
                                   "Only dangerous if a matching driver is configured; check .git/config."))

    if git_path.is_symlink():
        target = os.path.realpath(git_path)
        out.append(Finding("GIT-CONFIG-EXEC", Severity.HIGH, ".git", None, ".git is a symlink",
                           f".git -> {os.readlink(git_path)}",
                           "A symlinked git directory hides its config from tools that skip symlinks; git would "
                           "still use it. History checks skipped."))
        root_real = os.path.realpath(root)
        if target.startswith(root_real + os.sep) and os.path.isdir(target):
            text = _read_config(Path(target) / "config") or ""
            rel_cfg = os.path.relpath(os.path.join(target, "config"), root_real)
            for section, key, value in parse_git_config(text):
                full = f"{section}.{key}" if section else key
                sev = _key_sev(full.lower(), value)
                if sev is not None:
                    out.append(Finding("GIT-CONFIG-EXEC", sev, rel_cfg, None, f"Git config behind .git symlink sets {full}",
                                       f"{full} = {value}"[:300], "Executes when git runs in this folder."))
        ctx.errors.append("git history skipped: .git is a symlink")
        return out
    if git_path.is_file():
        try:
            pointer = git_path.read_text(errors="replace").strip()
        except OSError:
            pointer = "?"
        out.append(Finding("GIT-CONFIG-EXEC", Severity.HIGH, ".git", None, ".git is a file pointing elsewhere",
                           pointer[:200], "The git directory lives outside this folder; its config/hooks were "
                                          "not inspected."))
        ctx.errors.append("git history skipped: .git is a gitdir pointer")
        return out
    if not git_path.is_dir():
        return out

    block = False
    cfg_text = _read_config(git_path / "config")  # read directly: never skipped for size/control bytes
    if cfg_text:
        for section, key, value in parse_git_config(cfg_text):
            full = f"{section}.{key}" if section else key
            sev = _key_sev(full.lower(), value)
            if sev is None:
                continue
            if sev >= Severity.HIGH:
                block = True
            idx = cfg_text.lower().find(key)
            out.append(Finding("GIT-CONFIG-EXEC", sev, ".git/config", line_of(cfg_text, idx) if idx >= 0 else None,
                               f"Repository git config sets {full}", f"{full} = {value}"[:300],
                               "Repository-local git config can execute commands when you run ordinary git "
                               "commands (status, log, diff, checkout) in this folder."))

    for fe in ctx.files:
        if fe.rel.startswith(".git/hooks/") and not fe.rel.endswith(".sample"):
            out.append(Finding("GIT-HOOK-ACTIVE", Severity.HIGH, fe.rel, None, f"Active git hook {fe.name}",
                               (fe.text or "")[:200].replace("\n", " ⏎ "),
                               "Active hooks in .git/hooks run on git operations. Repos received as folders "
                               "should not contain them."))

    if block:
        ctx.errors.append("git history skipped: repository .git/config defines executable settings")
        return out

    tracked_raw = _git(root, ["ls-files", "-z"])
    if tracked_raw is None:
        ctx.errors.append("git history skipped: git unavailable or repository unreadable")
        return out
    tracked = set(p for p in tracked_raw.split("\0") if p)
    watch = set(ctx.inventory.get("autorun_files", [])) | set(ctx.inventory.get("instruction_files", []))
    for rel in sorted(watch):
        if rel not in tracked and not rel.startswith(".git/"):
            out.append(Finding("GIT-UNTRACKED-AUTORUN", Severity.MEDIUM, rel, None,
                               "Auto-run / agent file is not tracked by git",
                               rel, "Present on disk but not in the repository history — it was added outside "
                                    "version control (or is git-ignored). Treat with extra suspicion."))

    log = _git(root, ["log", "--no-ext-diff", "--no-textconv", "--no-color", "--format=\x1e%H\x1f%an\x1f%ae\x1f%aI\x1f%cI",
                      "--name-only", "--max-count=2000", "--"] + HISTORY_PATHSPECS)
    if log:
        seen = set()
        for block_txt in log.split("\x1e"):
            if not block_txt.strip():
                continue
            head, _, files = block_txt.partition("\n")
            parts = head.split("\x1f")
            if len(parts) != 5:
                continue
            sha, an, ae, ad, cd = parts
            a, c = _dt(ad), _dt(cd)
            if not a or not c or abs((c - a).days) <= 30:
                continue
            for path in [p for p in files.splitlines() if p.strip()]:
                if path in seen:
                    continue
                seen.add(path)
                out.append(Finding("GIT-BACKDATED", Severity.MEDIUM, path, None,
                                   "Sensitive file committed with a mismatched (backdated?) author date",
                                   f"{sha[:10]} {an} <{ae}>",
                                   f"{path}: author date {ad} vs committer date {cd} in commit {sha[:10]}. "
                                   "Attackers backdate injected .vscode/package.json changes to blend in."))
    return out
