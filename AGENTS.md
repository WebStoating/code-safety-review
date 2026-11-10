# AGENTS.md

Guidance for AI coding agents (Claude Code, Codex, others) working in this repository.

## What this repository is

The source for `code-safety-review`, a Claude Code and Codex plugin whose `review`
[Agent Skill](https://agentskills.io/specification) statically vets an untrusted third-party repository for
malware, supply-chain attacks and prompt injection before anything in it runs. The same skill must work in
Claude Code and in Codex.

## Layout

```
AGENTS.md
README.md
.agents/plugins/marketplace.json  # dev-only Codex marketplace (local source); never installed
tests/                            # unittest suite; malware-like fixtures are generated at test time
code-safety-review/               # THE PLUGIN — the only thing that ships
├── .claude-plugin/plugin.json    # Claude Code manifest
├── plugin.json                   # Codex manifest
└── skills/review/                # the skill
    ├── SKILL.md
    ├── scripts/                  # scan.py, check_deps.py, render_report.py, csr_lib/
    ├── references/
    └── assets/
```

## Commands

```bash
python3 -m unittest discover -s tests -t . -v                   # offline suite
CSR_LIVE=1 python3 -m unittest tests.test_registry.LiveSmoke -v  # real npm audit + OSV
uvx --from "git+https://github.com/agentskills/agentskills#subdirectory=skills-ref" skills-ref validate code-safety-review/skills/review
claude plugin validate --strict code-safety-review
claude --plugin-dir code-safety-review                           # load the plugin from the working tree
```

## Hard rules

**Skill format (Agent Skills standard):**
- `SKILL.md` frontmatter `name` must equal the folder name `review`.
- `description` ≤1024 chars, `compatibility` ≤500 chars, body under 500 lines, `metadata` values quoted strings.
- Reference files are linked one level deep from `SKILL.md`, with relative paths.

**Plugin packaging:**
- `code-safety-review/` is the plugin root and holds only `.claude-plugin/plugin.json`, `plugin.json` and
  `skills/`. Both agents copy the whole folder into their plugin cache, so nothing repo-only (tests, dev
  config) may go in it.
- Both manifests are identical, use `name` `code-safety-review`, and their `version` must equal `SKILL.md`
  `metadata.version`. Users get an update only when that version changes, so bump all three together.
- No symlink inside the plugin may point outside it.
- The published catalog lives in `WebStoating/skills`; `.agents/plugins/marketplace.json` here is for local
  development only.
- `tests/test_plugin_package.py` enforces these rules.

**Agent neutrality:** `SKILL.md` and `references/` use generic actions ("run", "read", "ask the user").
Never name one agent's tools.

**Skill scripts:** Python ≥3.9, standard library only, always run as `python3 -I`. Subprocess calls take an
argv list, never `shell=True`. Nothing from the reviewed repository is ever executed.

**Test data:** never commit malware-like files. Fixtures are generated at test time by
`tests/fixture_factory.py`; `tests/test_skill_md.py` self-scans the repository and fails on any HIGH or
CRITICAL finding.

## Commits

Follow [Conventional Commits 1.0.0](https://www.conventionalcommits.org/en/v1.0.0/). One logical change per
commit. No `Co-Authored-By:` trailers and no AI-attribution lines in commit messages or pull request
descriptions.
