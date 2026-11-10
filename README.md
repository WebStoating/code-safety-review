# Code Safety Review

A Claude Code and Codex plugin whose `review` [Agent Skill](https://agentskills.io) statically vets an
untrusted third-party repository before you open, install, or run it. The result is a verdict
(`MALICIOUS` / `SUSPICIOUS` / `NO INDICATORS FOUND`) plus a detailed Markdown report.

What it catches:
- Malicious `.vscode/tasks.json` (`runOn: folderOpen`), settings, launch configs, and workspace files.
- devcontainer, JetBrains, and Gitpod startup commands.
- npm lifecycle scripts (`preinstall`/`install`/`postinstall`/`prepare`) and the files they run.
- Import-time payloads in package entry points.
- `.npmrc`/`.yarnrc` overrides of `git=`/`script-shell=` (these work even with `--ignore-scripts`).
- Payloads hidden in fonts, images, and `.dict`/`.npl` files, plus unexpected binaries.
- Python `setup.py` cmdclass, `.pth` files, `conftest.py`, in-tree build backends, and `--extra-index-url`.
- Obfuscation: base64/hex/`fromCharCode`/`_0x`, decoded for you.
- Typosquats, non-registry and unknown install-script dependencies, `npm audit`, and OSV.dev (`MAL-` records).
- Deep audit of flagged packages from their published tarball. The skill never installs them.
- Git config/hook abuse (`core.fsmonitor`, `hooksPath`, filters, `ext::` submodules) and backdated commits.
- Prompt injection in `SKILL.md`/`CLAUDE.md`/`AGENTS.md`/`.cursorrules`/…: override phrases, hidden
  comments, Unicode Tags, bidi, zero-width, variation-selector smuggling, and secret-exfiltration instructions.
- Claude Code hooks, MCP server commands, and Codex config.

Nothing from the reviewed repository is executed. The scripts use only the Python 3.9+ standard library.

## Install

The plugin is published in the [WebStoating skills marketplace](https://github.com/WebStoating/skills). Add the
marketplace once, then install the plugin.

**Claude Code**

```bash
claude plugin marketplace add WebStoating/skills
claude plugin install code-safety-review@webstoating-skills
```

**Codex**

```bash
codex plugin marketplace add WebStoating/skills
codex plugin add code-safety-review@webstoating-skills
```

Start a new session after installing so the agent picks up the plugin. Each agent copies only the
`code-safety-review/` plugin folder into its plugin cache; the tests in this repository are never installed.

To update, refresh the marketplace (`claude plugin marketplace update webstoating-skills` or
`codex plugin marketplace upgrade webstoating-skills`). A new plugin version reaches users only when the
version number changes.

## Use

Ask your agent: *"Use code-safety-review on /path/to/client-repo before I open it."* In Claude Code you can
also run `/code-safety-review:review /path/to/client-repo`.

Recommended VS Code user setting, independent of this skill: `"task.allowAutomaticTasks": "off"`.

## Use the scripts directly

```bash
python3 -I code-safety-review/skills/review/scripts/scan.py /path/to/repo --json out/scan.json
python3 -I code-safety-review/skills/review/scripts/check_deps.py /path/to/repo --json out/deps.json --scratch out/scratch   # add --offline for no network
python3 -I code-safety-review/skills/review/scripts/render_report.py --scan out/scan.json --deps out/deps.json --out out/report.md
```

The agent workflow in `SKILL.md` adds a mandatory manual deep review and the final verdict on top
of the draft.

## Tests

```bash
python3 -m unittest discover -s tests -t . -v           # offline, ~5 s
CSR_LIVE=1 python3 -m unittest tests.test_registry.LiveSmoke -v   # real npm audit + OSV
```

Test repositories that imitate malware are **generated at test time** into temp directories by
`tests/fixture_factory.py`. Suspicious strings are assembled from fragments, all hosts use the
reserved `.invalid` TLD, and IPs come from TEST-NET-1. No malware-like files are stored in this
repository: `tests/test_skill_md.py` self-scans the repo and fails on any HIGH/CRITICAL finding.

To inspect the fixtures manually: `python3 tests/fixture_factory.py /tmp/csr-fixtures`.

## Repository layout

| Path | Contents |
|---|---|
| `code-safety-review/` | The plugin, the only part that ships: `.claude-plugin/plugin.json` (Claude Code), `plugin.json` (Codex) and `skills/` |
| `code-safety-review/skills/review/` | The skill: `SKILL.md` (agent workflow), `scripts/` (`scan.py`, `check_deps.py`, `render_report.py`, `csr_lib/` rules), `references/` (attack catalog, prompt-injection guide, npm audit, triage guide), `assets/` (report template, popular-package lists, install-script allowlist) |
| `.agents/plugins/marketplace.json` | Dev-only Codex marketplace that installs the plugin from this working tree |
| `tests/` | unittest suite + runtime fixture factory |

## Local development

**Claude Code** loads the plugin straight from the working tree:

```bash
claude --plugin-dir code-safety-review
```

After an edit, run `/reload-plugins` in the session (or start a new one).

**Codex** has no such flag, so this repository ships a dev-only marketplace, `code-safety-review-dev`, that
points at the local plugin folder:

```bash
codex plugin marketplace add .
codex plugin add code-safety-review@code-safety-review-dev
```

Codex copies the plugin into its cache, so rerun the `codex plugin add` command after every edit, then start a
new session. Don't keep the published plugin installed while you develop, or the agent sees the skill twice.

Validate the skill and the plugin manifest:

```bash
uvx --from "git+https://github.com/agentskills/agentskills#subdirectory=skills-ref" skills-ref validate code-safety-review/skills/review
claude plugin validate --strict code-safety-review
```

See `AGENTS.md` for contributor rules.

## License

[Apache-2.0](LICENSE)
