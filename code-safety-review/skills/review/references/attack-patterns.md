# Attack patterns and scanner rules

What each rule looks for, the real-world technique behind it, and what the benign version looks
like. Severities are the scanner's proposal; the agent decides the verdict
(see [triage-guide.md](triage-guide.md)). Indicators below are defanged (`[.]`).

## Contents
1. Auto-execution surfaces (editors, agents, git hooks, CI)
2. Hidden payloads and files
3. Node.js / JavaScript / TypeScript
4. Python
5. Git repository
6. Dependencies (check_deps.py)
7. Reference campaigns

---

## 1. Auto-execution surfaces

| Rule | Severity | Looks for | Benign look-alike |
|---|---|---|---|
| `AUTORUN-VSCODE-FOLDEROPEN` | HIGH → CRITICAL | `.vscode/tasks.json` task with `"runOptions": {"runOn": "folderOpen"}`. CRITICAL when the command (or its `windows`/`osx`/`linux` variant) downloads and pipes into a shell, runs an interpreter on a non-code file, is base64/encoded, touches secrets, or the task is hidden (`presentation.reveal: "never"`, `echo: false`, `hide: true`). | A visible `npm run watch` / `tsc -w` task on folder open. Still HIGH: confirm it is expected. |
| `AUTORUN-VSCODE-TASK-CMD` | MEDIUM | Dangerous command in a task that is *not* auto-run. | Build tasks invoking `npm`/`tsc`. |
| `AUTORUN-VSCODE-SETTINGS` | MEDIUM–CRITICAL | `task.allowAutomaticTasks: "on"`, `security.workspace.trust.enabled: false`, `terminal.integrated.*` shell/env/profile overrides, `*.path`/`*InterpreterPath`/`*.executable` settings pointing at a binary shipped in the repo. | Editor prefs (`formatOnSave`, `tabSize`), `python.defaultInterpreterPath` to a venv that is *not* shipped. |
| `AUTORUN-VSCODE-LAUNCH` | HIGH | `launch.json` configs whose program/runtime/args contain a dangerous command (runs on F5). | Normal `node`/`python` debug configs. |
| `AUTORUN-VSCODE-EXTENSIONS` | LOW | Malformed extension ids in `extensions.json` recommendations. | `dbaeumer.vscode-eslint`. |
| `AUTORUN-WORKSPACE-FILE` | as above | Tasks/settings embedded in `*.code-workspace`. | — |
| `AUTORUN-UNPARSEABLE` | MEDIUM | Auto-run config that is not valid JSONC; scanned with regex instead. Malformed files can hide entries from tools. | Hand-edited files with syntax slips. |
| `AUTORUN-DEVCONTAINER` | MEDIUM–CRITICAL | `initializeCommand` (runs **on the host**) and `onCreate/updateContent/postCreate/postStart/postAttachCommand`. | `postCreateCommand: npm ci`. |
| `AUTORUN-IDEA` | MEDIUM–CRITICAL | JetBrains startup tasks / run configurations with shell commands. | Shared run configs for tests. |
| `AUTORUN-GITPOD-REPLIT` | MEDIUM–CRITICAL | `.gitpod.yml` / `.replit` init/command/run/onBoot. | `npm install` on workspace start. |
| `AUTORUN-GIT-HOOKS` | LOW–CRITICAL | `.husky/*`, `.githooks/*`, `lefthook.yml`, `simple-git-hooks`, `.pre-commit-config.yaml` (non-GitHub `repo:`, local `entry:` commands). Raised when the hook downloads, pipes to a shell, or sends secrets. | `npx lint-staged`, `pre-commit` hooks from GitHub. |
| `AUTORUN-AGENT-CONFIG` | MEDIUM–CRITICAL | `.claude/settings*.json` hooks, `statusLine`/`apiKeyHelper` commands, `env` overriding `*_BASE_URL`/proxies/`NODE_OPTIONS`/keys, `enableAllProjectMcpServers`, unrestricted Bash permissions; `.mcp.json`/`.cursor/mcp.json`/`.vscode/mcp.json` server commands (`bash -c`, `npx -y`, repo scripts) or remote URLs; `.codex/*.toml` `command`/`notify`, `approval_policy = "never"`, `danger-full-access`. | A documented MCP server launched via a pinned published package. |
| `AUTORUN-CI` | INFO–HIGH | Workflows that pipe remote scripts into a shell, send `secrets.*` to curl/wget/webhooks, or `pull_request_target` + PR head checkout. | Standard actions; runs on CI, not your machine. |

Dangerous-command classifier (shared by tasks, lifecycle scripts, hooks, devcontainers):
download piped into `sh`/`bash`/`cmd`/`powershell`/`node`/`python`; `iex`/`Invoke-Expression`/
`DownloadString`; `powershell -enc`; `node -e`, `python -c`, `base64 -d`; hidden PowerShell
(`-w hidden`, `-ExecutionPolicy Bypass`); interpreter on a non-code file; embedded base64 blobs;
secret paths or whole-environment dumps; webhook/tunnel hosts or raw-IP URLs; known indicators.

## 2. Hidden payloads and files

| Rule | Severity | Looks for | Benign look-alike |
|---|---|---|---|
| `PAYLOAD-INTERPRETER-NONCODE` | MEDIUM–CRITICAL | `node`/`python`/`sh`/`bun`/`deno` run on `.woff2`, `.ttf`, `.png`, `.dict`, `.npl`, `.txt`… CRITICAL when that file is shipped and is actually text or code. MEDIUM when the file is not in the repo (it may be downloaded at runtime). | None in normal projects. |
| `PAYLOAD-EXT-MISMATCH` | MEDIUM–CRITICAL | Font/image/archive that is actually text (even if it starts with the right magic bytes, e.g. `wOF2=0;eval(…)`) is HIGH; with code/hex/base64/`_0x` obfuscation it is CRITICAL, and the decoded preview is attached. A binary file with the wrong magic bytes is MEDIUM. | Corrupt or mislabelled assets (binary mismatch = MEDIUM). |
| `PAYLOAD-CODE-IN-DATA` | MEDIUM–HIGH | Exec + obfuscation inside `.dict`, `.txt`, `.npl`, `.dat`, `.csv`, `.log`; `<script>`/`on*=` in SVG. | Word lists, CSV data. |
| `PAYLOAD-BINARY` | LOW–HIGH | `.exe .dll .so .dylib .node .bin .scr .cmd .bat .ps1 .vbs .lnk .jar .msi .pyc …`, and ELF/Mach-O/PE executables hiding under another extension (HIGH). Includes SHA-256. | Prebuilt native addons under `build/Release` or `prebuilds/` (LOW). |
| `PAYLOAD-SECRET-FILE` | MEDIUM | Shipped `.env*` (not `.env.example`), private keys, `credentials`, `.npmrc` with `_authToken`. | `.env.example`. |
| `PAYLOAD-KNOWN-IOC` | CRITICAL | Text containing an indicator from a published campaign (see §7). | — |
| `FS-CONTROL-CHARS` | MEDIUM–HIGH | NUL/control bytes in a code or config file (HIGH for auto-run/config files). Editors and parsers ignore them inside comments, but naive tools treat the file as binary and skip it; the scanner reads it as text anyway. | — |
| `FS-SYMLINK-ESCAPE` | MEDIUM | Symlink pointing outside the repository (e.g. at `~/.ssh`). Never followed. | — |

## 3. Node.js / JavaScript / TypeScript

| Rule | Severity | Looks for | Benign look-alike |
|---|---|---|---|
| `NODE-LIFECYCLE-SCRIPT` | MEDIUM → CRITICAL | `preinstall`, `install`, `postinstall`, `prepare`, `prepack`, `postpack`, `prepublish`… (inside shipped `node_modules`, only `preinstall`/`install`/`postinstall`, the scripts npm runs for registry installs). HIGH when the script runs a file from the repo (`node lib/setup.js`): **read that file**. CRITICAL when the script or its target downloads/executes, dumps env, reads secrets with network, or decodes-and-executes. | `"prepare": "husky"`, `node-gyp rebuild`, `tsc`. |
| `NODE-NPMRC-OVERRIDE` | INFO–CRITICAL | `.npmrc`/`.yarnrc(.yml)` keys `git=`, `script-shell=`, `node-options=`, `onload-script=`, `yarnPath`, `plugins`, and Yarn 1 `yarn-path "…"`. These make npm/yarn run another program and **work even with `--ignore-scripts`**. CRITICAL if they point inside the repo. A custom `registry=` is INFO (company registry). | `@acme:registry=https://npm.acme…`. |
| `NODE-LOCKFILE-SOURCE` | MEDIUM | Locked packages resolved from a non-npm host, git or file URL. | Company registry mirrors. |
| `NODE-LOCKFILE-NO-INTEGRITY` | LOW | Lock entry without an integrity hash. | Old lockfiles. |
| `NODE-DEP-NONREGISTRY` | MEDIUM | `git+…`, `github:`, `owner/repo`, `http(s):` tarball, `file:`/`link:` specs. Git deps can run `prepare` and ship an `.npmrc`. | Monorepo `file:`/`workspace:` links. |
| `NODE-ENTRY-SIDE-EFFECT` | MEDIUM–CRITICAL | `main`/`module`/`exports` entry file making calls that execute code, open network connections, read secrets or dump the environment at top level (or inside a top-level IIFE). Plain `require('https')` imports don't count, and `bin` scripts (run only when invoked) are excluded. HIGH for repo entry points, MEDIUM inside shipped `node_modules`, CRITICAL when combined. Runs on `require()`, and `--ignore-scripts` does not prevent it. | Entry files that only define and export functions. |
| `JS-DANGEROUS-COMBO` | MEDIUM–CRITICAL | Decode (base64/hex `Buffer.from`, `atob`, long `fromCharCode` chains) → `eval`/`Function`/`vm`/`child_process` within 400 chars; a network call within 800 chars of `eval`/`Function`/`vm.runIn*`/`.then(eval)` (download-and-execute); eval/exec names built from fragments (`['ev','al'].join('')`); network plus a whole-env dump or clipboard read (CRITICAL); network plus secret paths (HIGH, CRITICAL if obfuscated); `exec('…')` of a dangerous command string; anti-debug trap `constructor('while (true) {}')`; exec next to network (HIGH). | Copying `{...process.env}` for a child process is *not* a dump. |
| `JS-AI-CLI-ABUSE` | HIGH | Spawning `claude`, `gemini`, `q`, `codex`, `cursor-agent` with `--dangerously-skip-permissions`/`--yolo`/`--trust-all-tools`/`-p` (Nx-style secret hunting). | Dev tooling that documents such use. |
| `JS-EXEC` | LOW | `eval`, `new Function`, `child_process`, `vm.runIn*` on their own (`RegExp.prototype.exec` is ignored; `.d.ts` files are skipped). | Bundlers, CLIs. |
| `JS-NETWORK` | MEDIUM | Raw-IP URLs or webhook/tunnel hosts (webhook[.]site, ngrok, pipedream, Discord/Telegram bots…). | Local dev servers on 127.0.0.1 (ignored). |
| `JS-SECRET-READ` | LOW | References to credential locations (`~/.npmrc`, `.ssh/`, `.aws/`, browser profiles, wallets, keychains, `.claude.json`, `.codex/auth.json`). | Config tools that document paths. |
| `JS-OBFUSCATION` | LOW–MEDIUM | `_0x` identifiers (obfuscator.io), decodable base64/hex blobs outside `dist/`/`*.min.js`. | Minified vendor bundles (LOW). |

## 4. Python

| Rule | Severity | Looks for | Benign look-alike |
|---|---|---|---|
| `PY-SETUP-CMDCLASS` | HIGH–CRITICAL | `setup.py` classes extending `install`/`develop`/`egg_info`/`build_*`/`sdist`/`bdist_*`; CRITICAL with exec/network/decode. Decoded strings attached. | `build_ext` subclasses compiling C extensions. |
| `PY-SETUP-TOPLEVEL` | MEDIUM–CRITICAL | Module-level code in `setup.py` doing exec/network/secret access. | Reading `README.md` for `long_description`. |
| `PY-PTH-IMPORT` | HIGH–CRITICAL | `.pth` lines starting with `import`, which run at every interpreter start. | `distutils-precedence.pth` inside a venv. |
| `PY-SITECUSTOMIZE` | HIGH–CRITICAL | Module-level side effects in `sitecustomize.py`/`usercustomize.py`. | — |
| `PY-INIT-SIDE-EFFECT` | MEDIUM–CRITICAL | Module-level exec/network/secret access in `__init__.py`, `conftest.py` (runs with pytest), `noxfile.py`, `manage.py`, `__main__.py` (MEDIUM unless combined). | Imports and constants only. |
| `PY-LOCAL-BUILD-BACKEND` | MEDIUM–HIGH | `backend-path` (in-tree PEP 517 backend), Hatch custom build hooks, Poetry build scripts. All execute repo code on `pip install .`. | Projects that really need a custom build. |
| `PY-INDEX-URL` | MEDIUM–HIGH | `--extra-index-url` (dependency confusion, HIGH), `--index-url`/`-i`/`--trusted-host`/`--find-links`, uv/poetry/pdm custom indexes. | Company index with `--index-url` only. |
| `PY-DEP-NONREGISTRY` | MEDIUM | `pkg @ https://…`, `git+https://…` requirements. | Pinned internal forks. |
| `PY-DANGEROUS-COMBO` | HIGH–CRITICAL | Decode (`b64decode`, `zlib.decompress`, `marshal.loads`, rot13…) → `exec`/`eval`/`compile`/`subprocess`; network call near `exec`/`eval`/`compile` (download-and-execute); serialised `os.environ` or clipboard plus network (CRITICAL); secret paths plus network (HIGH, CRITICAL if obfuscated); `os.system('…')` with a dangerous command. | `dict(os.environ)` passed to `subprocess` is *not* a dump. |
| `PY-EXEC` | LOW | `exec`/`eval`/`compile`/`__import__`/`os.system`/`marshal.loads` alone. | Plugin loaders. |
| `PY-NETWORK` | MEDIUM | Raw-IP URLs or webhook/tunnel hosts. | — |
| `PY-SECRET-READ` | LOW | Credential locations referenced. | — |
| `PY-OBFUSCATION` | MEDIUM | Decodable base64/hex blobs, `chr()+chr()` chains. | Embedded test data. |
| `PY-UNPARSEABLE` | INFO | `setup.py`/init files that are not valid Python 3 (regex-only checks). | Python 2 projects. |

## 5. Git repository

git is only invoked when `.git/config` has nothing executable, and always with hooks, fsmonitor,
pager, external diff and textconv disabled, and with system/global config ignored.

| Rule | Severity | Looks for |
|---|---|---|
| `GIT-CONFIG-EXEC` | LOW–CRITICAL | `.git/config` keys that run commands: `core.fsmonitor`, `core.hooksPath`, `filter.*.clean/smudge/process`, `alias.* = !…`, `submodule.*.update = !…`, `include(If).path`, `core.sshCommand`, `remote.*.uploadpack/receivepack/vcs/proxy`, `extensions.partialClone` (lazy fetches), `core.alternateRefsCommand`, pager/editor/askpass, `gpg.program`, `credential.helper`, `diff.*.textconv`, `merge.*.driver`. Exact git-lfs/standard helper values are LOW. `.git` as a pointer file or a symlink is HIGH. The config is read straight from disk (no size or control-character skip). When any HIGH+ key is present, git is not run at all; otherwise git runs with hooks, fsmonitor, pagers, external diff, textconv, lazy fetching and all transports disabled. |
| `GIT-HOOK-ACTIVE` | HIGH | Non-`.sample` files in `.git/hooks/`. A folder handed to you should not contain them. |
| `GIT-SUBMODULE` | MEDIUM–CRITICAL | `.gitmodules` with `ext::` transports (command execution), option-injection values starting with `-`, `http/file/git://` sources. |
| `GIT-ATTRIBUTES-FILTER` | LOW | `.gitattributes` assigning custom filter/diff/merge drivers. |
| `GIT-BACKDATED` | MEDIUM | Commits touching `.vscode/`, `package.json`, `.npmrc`, `setup.py`, `*.pth`, agent files etc. where author date and committer date differ by more than 30 days (TasksJacker backdating). |
| `GIT-UNTRACKED-AUTORUN` | MEDIUM | Auto-run or agent files present on disk but not tracked by git (added outside history, or git-ignored). |

## 6. Dependencies (check_deps.py)

| Rule | Severity | Looks for |
|---|---|---|
| `DEP-MALWARE-ADVISORY` | CRITICAL | OSV `MAL-*` record or npm audit malware advisory for the exact version. |
| `DEP-TYPOSQUAT` | HIGH | Near-miss of a popular npm/PyPI name: edit distance 1 (or 2 for long names), separator tricks (`crossenv`), homoglyphs (`rn`→`m`, `0`→`o`), affixes (`-js`, `node-`, `-utilz`), lookalike scopes (`@typescript_eslint`). |
| `DEP-INSTALL-SCRIPT` | MEDIUM → CRITICAL | Locked package with `hasInstallScript`/`requiresBuild` not on `assets/install-script-allowlist.txt`. Raised to the worst severity found in its published tarball. |
| `DEP-DEEP-RED-FLAGS` | HIGH | Two or more of: `age<30d`, `version-age<7d`, `versions<=3`, `install-script:*`, `deps>=20`, `maintainer-changed:*`, `tarball-has-binary`, `tarball-has-env`, `not-on-public-registry`, `scan:high`. |
| `DEP-NONREGISTRY` | MEDIUM | Git/URL dependencies, including lockfile "versions" like `github:user/repo`. Never fetched (fetching an attacker URL reveals the review and can be served a clean decoy); review manually. A registry-shaped URL counts as a private registry only if the repo's own `.npmrc`/`.yarnrc` declares that host. |
| `DEP-PRIVATE` | INFO | Packages from a private registry: never looked up publicly (dependency-confusion safety). |

Known CVEs from `npm audit` and OSV (`GHSA-*`, `CVE-*`, `PYSEC-*`) are listed in the report's
dependency section and do **not** affect the verdict.

## 7. Reference campaigns

- **VS Code tasks.json infostealer (ThreatLocker).** A hidden `folderOpen` task with an OS-specific
  command fetches `vscode-load[.]onrender[.]com/settings/<os>` into `cmd`/`sh`. The bootstrap installs
  Node plus axios/request/clipboardy and pulls an `env-setup.npl` stage, served only to the axios
  user-agent. The final stage is an obfuscated stealer: file upload to `:8086/upload`, a logger on
  `:8087/api/log`, clipboard polling via `System.Windows.Forms.Clipboard`, a WebSocket "whour"
  command, and a `constructor('while (true) {}')` debugger trap. Infrastructure:
  `144[.]172[.]116[.]80` and `ip-api-check-gold[.]vercel[.]app`.
- **Contagious Interview / fake font (Lazarus).** Fake job-interview repos with a task running
  `node public/fonts/fa-brands-regular.woff2`; the "font" holds hex-encoded JS (BeaverTail, then
  the InvisibleFerret backdoor).
- **Malicious dictionary.** A `spellright.dict` file holds about 6 KB of obfuscated JS as a
  fallback loader.
- **npm lifecycle compromises.**
  - Bitwarden CLI `preinstall` → `bw_setup.js` fetches Bun from GitHub releases.
  - An axios release adds `plain-crypto-js`, whose `postinstall` runs a `setup.js` RAT loader.
  - Nx `telemetry.js` drives local AI CLIs to harvest secrets.
  - Exfiltration domain: `audit[.]checkmarx[.]cx`.
- **Import-time payloads.** PolinRider / `tailwind-autoanimation`: the payload is in `index.js`,
  so `--ignore-scripts` doesn't stop it.
- **Git dependency `.npmrc`.** A git dependency ships an `.npmrc` that swaps the `git` binary; it
  runs even with `--ignore-scripts`. Mitigation: `--allow-git=none` (npm ≥ 11.10).
- **TasksJacker.** Compromised accounts inject `.vscode/tasks.json` with backdated commits and
  spoofed authors.
- **Mini Shai-Hulud.** An npm worm that copies the `runOn: folderOpen` technique.
