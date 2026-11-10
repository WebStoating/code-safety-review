# Triage guide: benign or malicious?

The scanner proposes; you decide. For each HIGH/CRITICAL finding, open the file and answer three
questions:

1. **When does it run?** On folder open, install, import, git operation, or test run, before a
   human has had a chance to read it? Auto-run raises the stakes.
2. **What does it touch?** Credentials, the whole environment, the clipboard, browser or wallet
   data, files outside the project?
3. **Where does data or code go, and where does it come from?** Remote content executed? Data
   sent out? To an expected service, or to a raw IP, webhook, tunnel or lookalike domain?

**Malicious** = auto-run or install/import-time, *and* it executes fetched/decoded code or sends
sensitive data out. **Suspicious** = you can't establish what it does (undecodable, dynamic,
references a missing file), or it is unusual for the project's stated purpose.

## Benign look-alikes and what turns them malicious

| Looks like | Benign when | Malicious when |
|---|---|---|
| `"prepare": "husky"` / `.husky/pre-commit` | Runs `lint-staged`, tests or formatters. | The hook downloads, pipes to a shell, or reads `~/.ssh`/env and sends it out. |
| `postinstall` in esbuild, sharp, bcrypt, prisma, puppeteer, electron, core-js | Package is on the allowlist; the script fetches the vendor's binary from the vendor's host. | A lookalike name, an unexpected new version (`version-age<7d`) with a new script, or a new transitive dependency appears (e.g. a compromised release adding an unknown package with `postinstall`). |
| `"postinstall": "node scripts/postinstall.js"` in the repo itself | The script builds/copies assets, prints a banner, or checks Node version. | Its target decodes blobs, spawns shells, touches credentials, or contacts hosts. |
| `.vscode/tasks.json` | Build/test/watch tasks you start by hand, visible output. | `runOn: folderOpen`, hidden presentation, OS-specific variants, pipe-to-shell, `node <asset>`. |
| `.vscode/settings.json` | Formatting and linting preferences. | Turns on automatic tasks or disables trust, or points interpreter/tool paths at binaries shipped in the repo. |
| `devcontainer.json` `postCreateCommand: npm ci` | Standard container setup. | `initializeCommand` (runs on the **host**), or any command fetching and executing remote scripts. |
| Minified `dist/*.min.js`, vendored jQuery | Shipped as a library asset, not referenced by install/auto-run hooks. | Referenced by a lifecycle script, task or entry point, or contains `_0x` obfuscation with decode → eval. |
| `process.env.NODE_ENV`, `os.environ.get("DEBUG")` | Reading individual config vars. | Serialising the whole environment (`JSON.stringify(process.env)`, `json.dumps(dict(os.environ))`) next to a network call. |
| `{...process.env, X: 1}` / `dict(os.environ)` for `spawn`/`subprocess` | Passing env to a child process. | The copy is later sent over the network. |
| Base64 in code | Data URIs, source maps, test fixtures, embedded icons. | Decodes to a URL, shell command or JS/Python that is then executed or requested. |
| `eval` / `new Function` | Template engines, bundler runtimes. | Fed by decoded or downloaded content. |
| A `.woff2`/`.png` file | Starts with the right magic bytes (`wOF2`, `\x89PNG`). | Is text, contains hex/JS, or is passed to `node`/`python`. |
| `.npmrc` `registry=` / `@scope:registry=` | Company registry. | `git=`, `script-shell=`, `node-options=`, `onload-script=` pointing at repo files. |
| `requirements.txt --index-url https://pypi.company…` | Single private index. | `--extra-index-url` (dependency confusion) combined with unknown/unpinned internal names. |
| `conftest.py` | Fixtures and hooks. | Module-level network, exec or credential access (runs whenever pytest runs). |
| `AGENTS.md` / `CLAUDE.md` | Build/test commands and style rules for contributors. | Addresses reviewers/scanners, claims approval, hides text, asks to keep things from the user, or asks to read/send secrets. |
| Git hooks in `.git/hooks/` | Never expected in a folder handed to you. | Always report; if they execute network/shell commands, MALICIOUS. |

## Downgrading a HIGH/CRITICAL finding

Write the reason in the report's **Assessment** line, citing what you read. For example: *"Benign
because `scripts/postinstall.js` only copies `assets/` to `dist/`; no network, exec or env
access (read in full, 42 lines)."* "Looks fine" is not a reason.

## When you cannot decide

Mark the finding *Undetermined because …*, set the verdict to **SUSPICIOUS**, and list the exact
file and question in the report's manual-verification list. An honest SUSPICIOUS beats a wrong
NO INDICATORS FOUND.
