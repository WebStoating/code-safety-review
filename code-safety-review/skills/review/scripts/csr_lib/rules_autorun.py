"""Auto-execution surfaces: editor tasks/settings, devcontainers, IDE run configs,
git hooks, AI-agent configs, CI. (design §7.1)"""
from __future__ import annotations

import json
import re
from typing import Any, Iterable, List, Optional

from . import jsonc
from .decode import line_of, snippet
from .model import FileEntry, Finding, ScanContext, Severity
from .patterns import (DANGEROUS_REASONS, ENV_DUMP, NETWORK_CMD, PIPE_TO_SHELL, SECRET_PATHS, WEBHOOK_HOSTS,
                       command_risks, is_dangerous_command)

RUN_ON_RE = re.compile(r'"runOn"\s*:\s*"folderOpen"')


def _f(rule, sev, fe: FileEntry, line, title, snip, detail) -> Finding:
    return Finding(rule, sev, fe.rel, line, title, snip[:400], detail)


def _line_of_text(fe: FileEntry, needle: str, start: int = 0) -> Optional[int]:
    if fe.text is None:
        return None
    i = fe.text.find(needle, start)
    return line_of(fe.text, i) if i >= 0 else None


def _as_cmds(v: Any) -> List[str]:
    if v is None:
        return []
    if isinstance(v, str):
        return [v]
    if isinstance(v, list):
        return [" ".join(str(x) for x in v)]
    if isinstance(v, dict):
        out = []
        for x in v.values():
            out.extend(_as_cmds(x))
        return out
    return [str(v)]


def _dangerous(reasons: Iterable[str]) -> List[str]:
    return [r for r in reasons if r in DANGEROUS_REASONS]


def _load(fe: FileEntry, out: List[Finding]) -> Optional[Any]:
    try:
        return jsonc.loads(fe.text or "")
    except ValueError as e:
        out.append(_f("AUTORUN-UNPARSEABLE", Severity.MEDIUM, fe, None,
                      "Auto-run config could not be parsed; scanned as raw text",
                      fe.rel, f"Parse error: {e}. Malformed configs can hide entries from simple tools; "
                              "read this file manually."))
        return None


# --------------------------------------------------------------- VS Code ----

def _task_commands(task: dict) -> List[str]:
    cmds = []
    for scope in (task, task.get("windows") or {}, task.get("osx") or {}, task.get("linux") or {}):
        if not isinstance(scope, dict):
            continue
        c = scope.get("command")
        if c is not None:
            args = scope.get("args") or []
            if isinstance(args, list):
                args = " ".join(a if isinstance(a, str) else str(a.get("value", "")) if isinstance(a, dict) else str(a)
                                for a in args)
            cmds.append(f"{_as_cmds(c)[0]} {args}".strip())
        opts = scope.get("options") or {}
        if isinstance(opts, dict) and isinstance(opts.get("shell"), dict):
            cmds.extend(_as_cmds(opts["shell"].get("executable")))
    return cmds


def _check_tasks(fe: FileEntry, tasks: Any, rule_open: str, out: List[Finding]) -> None:
    if not isinstance(tasks, list):
        return
    text = fe.text or ""
    for task in tasks:
        if not isinstance(task, dict):
            continue
        label = str(task.get("label") or task.get("taskName") or task.get("script") or "?")
        cmds = _task_commands(task)
        reasons = sorted({r for c in cmds for r in command_risks(c)})
        danger = _dangerous(reasons)
        pres = task.get("presentation") or {}
        hidden = isinstance(pres, dict) and (pres.get("reveal") == "never" or pres.get("echo") is False) \
            or task.get("hide") is True
        ro = task.get("runOptions") or {}
        folder_open = isinstance(ro, dict) and ro.get("runOn") == "folderOpen"
        lpos = text.find(json.dumps(label))
        bad_cmd = next((c for c in cmds if _dangerous(command_risks(c))), cmds[0] if cmds else "")
        if folder_open:
            m = RUN_ON_RE.search(text, max(lpos, 0)) or RUN_ON_RE.search(text)
            line = line_of(text, m.start()) if m else None
            sev = Severity.CRITICAL if (danger or hidden) else Severity.HIGH
            why = []
            if danger:
                why.append("command " + ", ".join(danger))
            if hidden:
                why.append("output is hidden from the user (presentation.reveal=never / echo=false / hide)")
            out.append(_f(rule_open, sev, fe, line,
                          f"Task '{label}' runs automatically when the folder is opened",
                          bad_cmd or label,
                          "runOptions.runOn=folderOpen executes this task as soon as the folder is opened and "
                          "trusted in VS Code/Cursor. " + ("; ".join(why) + "." if why else
                                                            "Verify the command is expected.")
                          + (" All commands: " + " || ".join(cmds) if cmds else "")))
        elif danger:
            line = _line_of_text(fe, bad_cmd[:40], max(lpos, 0)) or (line_of(text, lpos) if lpos >= 0 else None)
            out.append(_f("AUTORUN-VSCODE-TASK-CMD", Severity.MEDIUM, fe, line,
                          f"Task '{label}' has a dangerous command (manual run)",
                          bad_cmd, "The task is not auto-run but its command " + ", ".join(danger) + "."))


SETTINGS_TERMINAL = re.compile(r"^terminal\.integrated\.(env|shell|shellArgs|profiles|automationProfile|defaultProfile)")
SETTINGS_PATHLIKE = re.compile(
    r"\.(path|paths|executable|executablePath|interpreterPath|defaultInterpreterPath|runtime|nodePath|serverPath|"
    r"tsdk|command|commandPath|binPath|bin)$", re.I)


def _flatten(d: Any, prefix: str = ""):
    if isinstance(d, dict):
        for k, v in d.items():
            key = f"{prefix}.{k}" if prefix else str(k)
            if isinstance(v, dict) and not SETTINGS_TERMINAL.match(key):
                yield from _flatten(v, key)
            else:
                yield key, v


def _repo_path(ctx: ScanContext, value: str) -> Optional[str]:
    v = value.replace("${workspaceFolder}", "").replace("${workspaceRoot}", "").lstrip("/").lstrip("\\")
    v = v[2:] if v.startswith("./") else v
    if not v or v.startswith(".."):
        return None
    if v in ctx.by_rel:
        return v
    pref = v.rstrip("/") + "/"
    return v if any(r.startswith(pref) for r in ctx.by_rel) else None


def _check_settings(ctx: ScanContext, fe: FileEntry, settings: Any, rule: str, out: List[Finding]) -> None:
    if not isinstance(settings, dict):
        return
    for key, val in _flatten(settings):
        sval = json.dumps(val) if not isinstance(val, str) else val
        line = _line_of_text(fe, f'"{key.split(".")[-1]}"') or _line_of_text(fe, key)
        if key == "task.allowAutomaticTasks" and str(val).lower() == "on":
            out.append(_f(rule, Severity.HIGH, fe, line, "Workspace enables automatic tasks",
                          f'"{key}": "{val}"', "Turns on auto-run of folderOpen tasks without prompting."))
        elif key in ("security.workspace.trust.enabled",) and val is False:
            out.append(_f(rule, Severity.HIGH, fe, line, "Workspace disables Workspace Trust",
                          f'"{key}": false', "Disables the trust prompt that guards auto-run tasks."))
        elif SETTINGS_TERMINAL.match(key):
            sev = Severity.CRITICAL if is_dangerous_command(sval) else Severity.MEDIUM
            out.append(_f(rule, sev, fe, line, "Workspace overrides integrated terminal shell/env",
                          f'"{key}": {sval}', "Terminal shell/env overrides apply to every terminal and task "
                                               "you open in this workspace."))
        elif SETTINGS_PATHLIKE.search(key) and isinstance(val, str):
            if is_dangerous_command(val):
                out.append(_f(rule, Severity.CRITICAL, fe, line, f"Setting {key} contains a dangerous command",
                              f'"{key}": {sval}', ", ".join(_dangerous(command_risks(val)))))
            else:
                inside = _repo_path(ctx, val)
                if inside and not inside.startswith("node_modules/"):
                    out.append(_f(rule, Severity.HIGH, fe, line,
                                  f"Setting {key} points to an executable shipped in the repo",
                                  f'"{key}": {sval}',
                                  f"An extension will execute {inside} from this repository. Inspect it."))
                elif inside:
                    out.append(_f(rule, Severity.MEDIUM, fe, line, f"Setting {key} points into node_modules",
                                  f'"{key}": {sval}', "Tooling will load code from the shipped node_modules."))


def _check_launch(fe: FileEntry, data: Any, out: List[Finding]) -> None:
    confs = data.get("configurations") if isinstance(data, dict) else None
    for c in confs or []:
        if not isinstance(c, dict):
            continue
        parts = []
        for k in ("runtimeExecutable", "program", "runtimeArgs", "args", "console"):
            parts.extend(_as_cmds(c.get(k)))
        cmd = " ".join(parts)
        if is_dangerous_command(cmd):
            out.append(_f("AUTORUN-VSCODE-LAUNCH", Severity.HIGH, fe, _line_of_text(fe, str(c.get("name", ""))),
                          f"Launch config '{c.get('name')}' runs a dangerous command", cmd,
                          ", ".join(_dangerous(command_risks(cmd))) + ". Runs when you start debugging (F5)."))


def _check_extensions(fe: FileEntry, data: Any, out: List[Finding]) -> None:
    recs = data.get("recommendations") if isinstance(data, dict) else None
    for r in recs or []:
        if not isinstance(r, str) or not re.fullmatch(r"[a-z0-9][a-z0-9-]*\.[a-z0-9][a-z0-9-]*", r, re.I):
            out.append(_f("AUTORUN-VSCODE-EXTENSIONS", Severity.LOW, fe, _line_of_text(fe, str(r)),
                          "Unusual extension recommendation", str(r),
                          "Recommended extension id is malformed; verify before installing."))


# ----------------------------------------------------------- devcontainer ----

DEVCONTAINER_KEYS = ["initializeCommand", "onCreateCommand", "updateContentCommand", "postCreateCommand",
                     "postStartCommand", "postAttachCommand"]


def _check_devcontainer(fe: FileEntry, data: Any, out: List[Finding]) -> None:
    if not isinstance(data, dict):
        return
    for k in DEVCONTAINER_KEYS:
        if k not in data:
            continue
        cmds = _as_cmds(data[k])
        cmd = " && ".join(cmds)
        danger = _dangerous(command_risks(cmd))
        sev = Severity.CRITICAL if danger else (Severity.HIGH if k == "initializeCommand" else Severity.MEDIUM)
        where = "on your host machine before the container starts" if k == "initializeCommand" else "inside the container"
        out.append(_f("AUTORUN-DEVCONTAINER", sev, fe, _line_of_text(fe, f'"{k}"'),
                      f"Dev container {k} runs {where}", cmd,
                      (", ".join(danger) + ". " if danger else "") + "Runs automatically when the repo is opened "
                      "in a dev container / Codespace."))


# ------------------------------------------------------------- git hooks ----

def _hook_finding(fe: FileEntry, content: str, label: str, out: List[Finding]) -> None:
    reasons = command_risks(content)
    danger = _dangerous(reasons)
    net_secret = bool(NETWORK_CMD.search(content)) and bool(SECRET_PATHS.search(content) or ENV_DUMP.search(content))
    sev = Severity.HIGH if (danger or net_secret) else Severity.LOW
    if PIPE_TO_SHELL.search(content):
        sev = Severity.CRITICAL
    first = content.strip().splitlines()[0] if content.strip() else ""
    idx = 0
    for pat in (PIPE_TO_SHELL, NETWORK_CMD, SECRET_PATHS):
        m = pat.search(content)
        if m:
            idx = m.start()
            break
    out.append(_f("AUTORUN-GIT-HOOKS", sev, fe, line_of(content, idx) if content else None,
                  f"Git hook {label}", snippet(content, idx) if content else first,
                  ("; ".join(reasons) + ". " if reasons else "") +
                  "Hooks run automatically on git operations once installed (e.g. by `prepare: husky`)."))


def _check_precommit(fe: FileEntry, out: List[Finding]) -> None:
    text = fe.text or ""
    for m in re.finditer(r"^\s*-?\s*repo:\s*(\S+)", text, re.M):
        url = m.group(1).strip("'\"")
        if url not in ("local", "meta") and not url.startswith("https://github.com/"):
            out.append(_f("AUTORUN-GIT-HOOKS", Severity.MEDIUM, fe, line_of(text, m.start()),
                          "pre-commit hook from a non-GitHub source", m.group(0).strip(),
                          "Hook code is fetched from this URL and executed on commit."))
    for m in re.finditer(r"^\s*(entry):\s*(.+)$", text, re.M):
        if is_dangerous_command(m.group(2)):
            out.append(_f("AUTORUN-GIT-HOOKS", Severity.HIGH, fe, line_of(text, m.start()),
                          "pre-commit local hook runs a dangerous command", m.group(2).strip(),
                          ", ".join(_dangerous(command_risks(m.group(2))))))


# ------------------------------------------------------------ AI agents ----

AGENT_CMD_KEYS = ("statusLine", "apiKeyHelper", "awsAuthRefresh", "awsCredentialExport", "otelHeadersHelper")


def _agent_cmd_sev(cmd: str) -> Severity:
    if is_dangerous_command(cmd):
        return Severity.CRITICAL
    if re.search(r"\b(bash|sh|zsh)\s+-c\b|\bnpx\s+(-y|--yes)\b|\b(node|python3?|bun|deno|bash|sh)\s+\.?\.?/?[\w./-]+",
                 cmd) or NETWORK_CMD.search(cmd):
        return Severity.HIGH
    return Severity.MEDIUM


def _check_claude_settings(fe: FileEntry, data: Any, out: List[Finding]) -> None:
    if not isinstance(data, dict):
        return
    hooks = data.get("hooks")
    if hooks:
        cmds = []
        for evt, groups in (hooks.items() if isinstance(hooks, dict) else []):
            for g in groups or []:
                for h in (g.get("hooks") or []) if isinstance(g, dict) else []:
                    if isinstance(h, dict) and h.get("command"):
                        cmds.append((evt, str(h["command"])))
        for evt, cmd in cmds or [("?", json.dumps(hooks)[:200])]:
            out.append(_f("AUTORUN-AGENT-CONFIG", max(_agent_cmd_sev(cmd), Severity.MEDIUM), fe,
                          _line_of_text(fe, evt), f"Claude Code hook on {evt} runs a command", cmd,
                          "Project hooks execute automatically during agent sessions in this folder."))
    for k in AGENT_CMD_KEYS:
        v = data.get(k)
        cmd = v.get("command") if isinstance(v, dict) else v
        if isinstance(cmd, str) and cmd:
            out.append(_f("AUTORUN-AGENT-CONFIG", max(_agent_cmd_sev(cmd), Severity.MEDIUM), fe,
                          _line_of_text(fe, k), f"Claude Code setting {k} runs a command", cmd,
                          "This command is executed automatically by the agent."))
    env = data.get("env")
    if isinstance(env, dict):
        for k, v in env.items():
            if re.search(r"BASE_URL|_PROXY|NODE_OPTIONS|API_KEY|AUTH_TOKEN", str(k)):
                out.append(_f("AUTORUN-AGENT-CONFIG", Severity.HIGH, fe, _line_of_text(fe, str(k)),
                              f"Agent settings override {k}", f"{k}={v}",
                              "Redirecting the API endpoint/proxy or injecting node options can leak prompts, "
                              "code and credentials."))
    if data.get("enableAllProjectMcpServers") is True:
        out.append(_f("AUTORUN-AGENT-CONFIG", Severity.MEDIUM, fe, _line_of_text(fe, "enableAllProjectMcpServers"),
                      "Auto-approves all project MCP servers", "enableAllProjectMcpServers: true",
                      "MCP server commands from this repo would start without a prompt."))
    perms = data.get("permissions")
    if isinstance(perms, dict):
        allow = perms.get("allow") or []
        risky = [a for a in allow if isinstance(a, str) and re.fullmatch(r"Bash(\(\*?\))?|Bash\(\s*\*\s*\)", a.strip())]
        if risky or perms.get("defaultMode") == "bypassPermissions":
            out.append(_f("AUTORUN-AGENT-CONFIG", Severity.MEDIUM, fe, _line_of_text(fe, "permissions"),
                          "Agent permissions pre-approve unrestricted shell", json.dumps(perms)[:200],
                          "Lets any shell command run without confirmation in this project."))


def _check_mcp(fe: FileEntry, data: Any, out: List[Finding]) -> None:
    if not isinstance(data, dict):
        return
    servers = data.get("mcpServers") or data.get("servers") or {}
    if not isinstance(servers, dict):
        return
    for name, cfg in servers.items():
        if not isinstance(cfg, dict):
            continue
        if cfg.get("command"):
            cmd = " ".join([str(cfg["command"])] + [str(a) for a in (cfg.get("args") or [])])
            sev = _agent_cmd_sev(cmd)
            out.append(_f("AUTORUN-AGENT-CONFIG", sev, fe, _line_of_text(fe, f'"{name}"'),
                          f"MCP server '{name}' launches a local command", cmd,
                          "Agents start MCP servers automatically once approved; the command runs with your "
                          "privileges."))
        elif cfg.get("url"):
            out.append(_f("AUTORUN-AGENT-CONFIG", Severity.MEDIUM, fe, _line_of_text(fe, f'"{name}"'),
                          f"MCP server '{name}' connects to a remote URL", str(cfg["url"]),
                          "Remote MCP servers receive agent context and tool calls."))


def _check_codex_toml(fe: FileEntry, out: List[Finding]) -> None:
    text = fe.text or ""
    for m in re.finditer(r"^\s*(command|notify)\s*=\s*(.+)$", text, re.M):
        cmd = m.group(2)
        out.append(_f("AUTORUN-AGENT-CONFIG", _agent_cmd_sev(cmd), fe, line_of(text, m.start()),
                      f"Codex config {m.group(1)} runs a command", m.group(0).strip(),
                      "Codex executes this command automatically (MCP server / notification hook)."))
    for m in re.finditer(r'^\s*(approval_policy\s*=\s*"never"|sandbox_mode\s*=\s*"danger-full-access")', text, re.M):
        out.append(_f("AUTORUN-AGENT-CONFIG", Severity.MEDIUM, fe, line_of(text, m.start()),
                      "Codex config disables approvals or sandbox", m.group(0).strip(),
                      "Lets the agent run commands without confirmation or sandboxing."))


# -------------------------------------------------------------------- CI ----

def _check_ci(fe: FileEntry, out: List[Finding]) -> None:
    text = fe.text or ""
    flagged = False
    for m in PIPE_TO_SHELL.finditer(text):
        seg = text[m.start():m.end()]
        if "githubusercontent.com" in seg or "github.com" in seg:
            continue
        flagged = True
        out.append(_f("AUTORUN-CI", Severity.HIGH, fe, line_of(text, m.start()),
                      "CI pipes a remote script into a shell", snippet(text, m.start()),
                      "Remote script executes in CI with access to repository secrets."))
    for m in re.finditer(r"\$\{\{\s*secrets\.[A-Z0-9_]+\s*\}\}", text):
        line_start = text.rfind("\n", 0, m.start()) + 1
        line_end = text.find("\n", m.end())
        line = text[line_start: line_end if line_end != -1 else len(text)]
        if (WEBHOOK_HOSTS.search(line) or re.search(r"\b(curl|wget)\b", line)) and "github.com" not in line:
            flagged = True
            out.append(_f("AUTORUN-CI", Severity.HIGH, fe, line_of(text, m.start()),
                          "CI sends a secret to a network endpoint", line.strip(),
                          "Secrets passed to curl/wget/webhooks can be exfiltrated."))
    if re.search(r"^\s*pull_request_target\s*:", text, re.M) and re.search(r"github\.event\.pull_request\.head", text):
        flagged = True
        out.append(_f("AUTORUN-CI", Severity.MEDIUM, fe, _line_of_text(fe, "pull_request_target"),
                      "pull_request_target checks out untrusted PR code", "pull_request_target + PR head ref",
                      "Classic 'pwn request': PR code runs with write token and secrets."))
    if not flagged:
        out.append(_f("AUTORUN-CI", Severity.INFO, fe, None, "CI workflow present", fe.rel,
                      "Runs on the CI provider, not on your machine."))


# ------------------------------------------------------------------ main ----

def check(ctx: ScanContext) -> List[Finding]:
    out: List[Finding] = []
    for fe in ctx.files:
        if fe.text is None or fe.rel.startswith(".git/"):
            continue
        rel = fe.rel
        low = rel.lower()
        name = fe.name.lower()
        parent = low.rsplit("/", 2)[-2] if "/" in low else ""

        if low.endswith(".vscode/tasks.json"):
            ctx.note("autorun_files", rel)
            data = _load(fe, out)
            if data is None:
                if RUN_ON_RE.search(fe.text):
                    m = RUN_ON_RE.search(fe.text)
                    sev = Severity.CRITICAL if is_dangerous_command(fe.text) else Severity.HIGH
                    out.append(_f("AUTORUN-VSCODE-FOLDEROPEN", sev, fe, line_of(fe.text, m.start()),
                                  "Task runs automatically when the folder is opened (unparseable file)",
                                  snippet(fe.text, m.start()),
                                  "Found runOn=folderOpen in a malformed tasks.json. "
                                  + ", ".join(_dangerous(command_risks(fe.text)))))
                else:
                    for m in PIPE_TO_SHELL.finditer(fe.text):
                        out.append(_f("AUTORUN-VSCODE-TASK-CMD", Severity.MEDIUM, fe, line_of(fe.text, m.start()),
                                      "Dangerous command in malformed tasks.json", snippet(fe.text, m.start()), ""))
                continue
            _check_tasks(fe, data.get("tasks") if isinstance(data, dict) else None, "AUTORUN-VSCODE-FOLDEROPEN", out)
        elif low.endswith(".vscode/settings.json"):
            ctx.note("autorun_files", rel)
            data = _load(fe, out)
            if data is not None:
                _check_settings(ctx, fe, data, "AUTORUN-VSCODE-SETTINGS", out)
        elif low.endswith(".vscode/launch.json"):
            ctx.note("autorun_files", rel)
            data = _load(fe, out)
            if data is not None:
                _check_launch(fe, data, out)
        elif low.endswith(".vscode/extensions.json"):
            data = _load(fe, out)
            if data is not None:
                _check_extensions(fe, data, out)
        elif low.endswith(".code-workspace"):
            ctx.note("autorun_files", rel)
            data = _load(fe, out)
            if isinstance(data, dict):
                t = data.get("tasks")
                _check_tasks(fe, t.get("tasks") if isinstance(t, dict) else t, "AUTORUN-WORKSPACE-FILE", out)
                _check_settings(ctx, fe, data.get("settings"), "AUTORUN-WORKSPACE-FILE", out)
                if isinstance(data.get("launch"), dict):
                    _check_launch(fe, data["launch"], out)
        elif name in ("devcontainer.json", ".devcontainer.json") and (".devcontainer" in low or name.startswith(".")):
            ctx.note("autorun_files", rel)
            data = _load(fe, out)
            if data is not None:
                _check_devcontainer(fe, data, out)
        elif "/.idea/" in "/" + low and low.endswith(".xml"):
            t = fe.text
            startup = re.search(r"ProjectStartup\w*Configuration|startupTasks|RunOnStartup", t)
            danger = is_dangerous_command(t)
            if startup or danger:
                ctx.note("autorun_files", rel)
                sev = Severity.CRITICAL if (startup and danger) else Severity.HIGH if danger else Severity.MEDIUM
                idx = startup.start() if startup else 0
                out.append(_f("AUTORUN-IDEA", sev, fe, line_of(t, idx), "JetBrains run configuration / startup task",
                              snippet(t, idx), ("Startup task runs on project open. " if startup else "") +
                              ", ".join(_dangerous(command_risks(t)))))
        elif name in (".gitpod.yml", ".replit", "replit.nix"):
            ctx.note("autorun_files", rel)
            danger = is_dangerous_command(fe.text)
            if danger or re.search(r"^\s*(init|before|command|run|onBoot)\s*[:=]", fe.text, re.M):
                out.append(_f("AUTORUN-GITPOD-REPLIT", Severity.CRITICAL if danger else Severity.MEDIUM, fe, None,
                              "Cloud IDE startup commands", rel,
                              ", ".join(_dangerous(command_risks(fe.text))) or "Runs on workspace start."))
        elif (low.startswith(".husky/") or "/.husky/" in low) and "/_/" not in "/" + low and not name.startswith("."):
            ctx.note("autorun_files", rel)
            _hook_finding(fe, fe.text, rel, out)
        elif low.startswith(".githooks/") or "/.githooks/" in low:
            ctx.note("autorun_files", rel)
            _hook_finding(fe, fe.text, rel, out)
        elif name in ("lefthook.yml", ".lefthook.yml", "lefthook.yaml", "lefthook-local.yml"):
            ctx.note("autorun_files", rel)
            _hook_finding(fe, fe.text, rel, out)
        elif name == ".pre-commit-config.yaml":
            ctx.note("autorun_files", rel)
            _check_precommit(fe, out)
        elif name == "package.json" and "node_modules/" not in low:
            try:
                pkg = json.loads(fe.text)
            except ValueError:
                continue
            if isinstance(pkg, dict):
                for key in ("simple-git-hooks",):
                    if isinstance(pkg.get(key), dict):
                        _hook_finding(fe, "\n".join(map(str, pkg[key].values())), f"{key} in {rel}", out)
                hk = (pkg.get("husky") or {}).get("hooks") if isinstance(pkg.get("husky"), dict) else None
                if isinstance(hk, dict):
                    _hook_finding(fe, "\n".join(map(str, hk.values())), f"husky.hooks in {rel}", out)
        elif parent == ".claude" and name in ("settings.json", "settings.local.json"):
            ctx.note("autorun_files", rel)
            data = _load(fe, out)
            if data is not None:
                _check_claude_settings(fe, data, out)
        elif name in (".mcp.json", "mcp.json") and (parent in ("", ".cursor", ".vscode", ".claude", ".gemini",
                                                                ".windsurf", ".roo") or "/" not in rel):
            ctx.note("autorun_files", rel)
            data = _load(fe, out)
            if data is not None:
                _check_mcp(fe, data, out)
        elif parent == ".codex" and name.endswith(".toml"):
            ctx.note("autorun_files", rel)
            _check_codex_toml(fe, out)
        elif re.match(r"(.*/)?\.github/workflows/[^/]+\.ya?ml$", low) or name in (".gitlab-ci.yml",
                                                                                     "azure-pipelines.yml",
                                                                                     "bitbucket-pipelines.yml"):
            _check_ci(fe, out)
    return out
