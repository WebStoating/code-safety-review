# The 10-minute package audit (npm, with PyPI equivalents)

`check_deps.py` automates this for every **flagged** dependency. A dependency is flagged when it
has an install script that is not allowlisted, a typosquat-like name, a non-registry source, or a
malware advisory. Each one becomes an entry in `deps.json → deep_audits`. Use this page to read
those results, or to audit one more package by hand.

**Rule zero: never install to inspect.** Malicious code runs at install time (lifecycle scripts)
or at import time (entry files). Inspect metadata and the published tarball only.

**Always work from a scratch directory outside the repo** with a clean npm config. A repository
`.npmrc` can redirect the registry or replace the `git` binary.

```bash
mkdir -p <out>/scratch/manual && cd <out>/scratch/manual
printf 'registry=https://registry.npmjs.org/\n' > .npmrc
export NPM_CONFIG_USERCONFIG="$PWD/.npmrc" NPM_CONFIG_IGNORE_SCRIPTS=true NPM_CONFIG_ALLOW_GIT=none
```

| Step | Manual command (scratch dir) | Where check_deps.py records it | Red flags |
|---|---|---|---|
| 1. Metadata | `npm view <pkg> --json` | `metadata.created`, `version_published`, `versions_count`, `maintainers`, `published_by` | `age<30d`, `version-age<7d`, `versions<=3`; name close to a popular package; brand-new maintainer email on a "known" project; `maintainer-changed:*` (publisher of this version wasn't a maintainer of the first) |
| 2. Install scripts | `npm view <pkg>@<ver> scripts --json` | `metadata.scripts`, `install-script:*` flag | Any `preinstall`/`install`/`postinstall` in a small, unknown package is guilty until proven innocent. Known legitimate ones are in `assets/install-script-allowlist.txt` (esbuild, node-gyp addons, husky…). |
| 3. Tarball, not GitHub | `npm pack <pkg>@<ver> --ignore-scripts && mkdir x && tar -xzf *.tgz -C x && ls -laR x`. Only use an exact semver `<ver>`; never a `github:`/URL spec, because npm would clone the repo and can run its config. | `tarball_dir`. The script downloads `dist.tarball` straight from registry.npmjs.org (no npm process) and extracts it with path-traversal and link checks. | Code on npm ≠ code on GitHub. Look for `.env`, unexplained `.node`/`.exe` binaries, minified blobs in a "readable source" package (`tarball-has-binary`, `tarball-has-env`). |
| 4. Pattern sweep | `python3 -I <skill-dir>/scripts/scan.py x/package --json x.json` | `scan_findings` (the full scanner, not just grep) | eval/Function/child_process; `process.env`, `.npmrc`, `.ssh`, `.aws`; http/https/fetch/dns; base64, `fromCharCode`, `\x` escapes. The classic two-line stealer POSTs the whole environment to an encoded URL. |
| 5. Dependency tree | `npm view <pkg>@<ver> dependencies --json` | `metadata.dependencies_count`, `dependencies` | A tiny helper pulling in 20+ deps (`deps>=20`), or depending on another week-old unknown package. |
| 6. Second opinion | (automatic) | `npm_audit`, `osv` sections; `DEP-MALWARE-ADVISORY` | OSV `MAL-*` = known malicious. GHSA/CVE = known vulnerability (separate from malware). `osv-scanner` / `npq` may be used **only if already installed**; never via `npx` (that runs third-party code). |

A deep audit yields `DEP-DEEP-RED-FLAGS` (HIGH) with two or more red flags. `DEP-INSTALL-SCRIPT`
is raised to the worst severity found inside the package's tarball.

## PyPI equivalent

| Step | Manual | check_deps.py |
|---|---|---|
| Metadata | `https://pypi.org/pypi/<name>/json` (read in a browser or with a plain HTTP GET; nothing to install) | `metadata.created`, `versions_count`, `version_published` |
| Artifact | Download the **sdist** (shows `setup.py`) to the scratch dir; extract; don't `pip install` | sdist preferred, else first wheel; `tarball_dir` |
| Sweep | `scan.py` on the extracted dir | `scan_findings`, `scan:high` flag |

`pip download` is **not** safe for sdists: it may run the build backend to read metadata.

## Reading deep_audits

```json
{"name": "plain-crypto-js", "version": "4.2.1",
 "red_flags": ["age<30d", "versions<=3", "install-script:postinstall=node setup.js"],
 "scan_findings": [{"rule_id": "JS-DANGEROUS-COMBO", "severity": "CRITICAL", "file": "package/setup.js", ...}],
 "error": null}
```

- `error` set → the audit is incomplete. Say so in the coverage section; don't treat it as clean.
- `not-on-public-registry` → a private package, or a name squatting a private one. Verify with the
  user.
- Open the referenced file under `tarball_dir` and trace it, exactly as for repo files.

Limits of this workflow: it catches the common cases. Dependency confusion, compromised maintainer
accounts and build-pipeline injection need provenance checks and continuous monitoring. Mention
them in the report's next steps when relevant.
