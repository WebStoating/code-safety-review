import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from tests._path import ROOT  # noqa: F401

from csr_lib import scanner
from csr_lib.rules_git import parse_git_config
from csr_lib.model import Severity

HAVE_GIT = shutil.which("git") is not None


def hits(res, rule_id):
    return [f for f in res.findings if f.rule_id == rule_id]


@unittest.skipUnless(HAVE_GIT, "git not installed")
class GitTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name) / "repo"
        self.root.mkdir()
        self.env = {**os.environ, "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_NOSYSTEM": "1",
                    "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid",
                    "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.invalid"}
        self.git("init", "-q")

    def tearDown(self):
        self.tmp.cleanup()

    def git(self, *args, env=None):
        subprocess.run(["git", "-C", str(self.root), *args], check=True, capture_output=True,
                       env={**self.env, **(env or {})})

    def commit(self, rel, content, date=None):
        p = self.root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
        self.git("add", rel)
        env = {}
        if date:
            env["GIT_AUTHOR_DATE"] = date
        self.git("commit", "-q", "-m", f"add {rel}", env=env)

    def test_parse_git_config(self):
        cfg = parse_git_config('[core]\n\tfsmonitor = x\n[filter "lfs"]\n\tsmudge = git-lfs smudge %f\n')
        self.assertIn(("core", "fsmonitor", "x"), cfg)
        self.assertIn(('filter.lfs', "smudge", "git-lfs smudge %f"), cfg)

    def test_fsmonitor_config_blocks_git(self):
        self.commit("README.md", "hi\n")
        marker = Path(self.tmp.name) / "PWNED"
        with open(self.root / ".git" / "config", "a") as fh:
            fh.write(f"[core]\n\tfsmonitor = touch {marker}\n")
        res = scanner.run_scan(self.root)
        h = hits(res, "GIT-CONFIG-EXEC")
        self.assertEqual(h[0].severity, Severity.CRITICAL)
        self.assertFalse(marker.exists())
        self.assertTrue(any("git history skipped" in e for e in res.errors))

    def test_lfs_filter_is_not_critical(self):
        self.commit("README.md", "hi\n")
        with open(self.root / ".git" / "config", "a") as fh:
            fh.write('[filter "lfs"]\n\tsmudge = git-lfs smudge -- %f\n\tprocess = git-lfs filter-process\n')
        h = hits(scanner.run_scan(self.root), "GIT-CONFIG-EXEC")
        self.assertTrue(all(f.severity <= Severity.LOW for f in h))

    def test_active_hook(self):
        self.commit("README.md", "hi\n")
        hook = self.root / ".git" / "hooks" / "post-checkout"
        hook.write_text("#!/bin/sh\necho hi\n")
        h = hits(scanner.run_scan(self.root), "GIT-HOOK-ACTIVE")
        self.assertEqual(h[0].severity, Severity.HIGH)

    def test_backdated_vscode_commit(self):
        self.commit("README.md", "hi\n")
        self.commit(".vscode/tasks.json", "{}\n", date="2019-01-01T00:00:00Z")
        h = hits(scanner.run_scan(self.root), "GIT-BACKDATED")
        self.assertTrue(h)
        self.assertIn(".vscode/tasks.json", h[0].detail)

    def test_untracked_tasks_json(self):
        self.commit("README.md", "hi\n")
        (self.root / ".vscode").mkdir()
        (self.root / ".vscode" / "tasks.json").write_text("{}\n")
        h = hits(scanner.run_scan(self.root), "GIT-UNTRACKED-AUTORUN")
        self.assertTrue(h)

    def test_submodule_ext_url(self):
        self.commit(".gitmodules", '[submodule "x"]\n\tpath = x\n\turl = ext::sh -c touch% /tmp/pwned\n')
        h = hits(scanner.run_scan(self.root), "GIT-SUBMODULE")
        self.assertGreaterEqual(h[0].severity, Severity.MEDIUM)

    def test_no_git_dir_ok(self):
        plain = Path(self.tmp.name) / "plain"
        plain.mkdir()
        (plain / "a.txt").write_text("x")
        res = scanner.run_scan(plain)
        self.assertFalse([f for f in res.findings if f.rule_id.startswith("GIT-")])
        self.assertEqual(res.errors, [])

    def test_no_git_flag(self):
        self.commit("README.md", "hi\n")
        (self.root / ".git" / "hooks" / "pre-push").write_text("#!/bin/sh\n")
        res = scanner.run_scan(self.root, include_git=False)
        self.assertFalse(hits(res, "GIT-HOOK-ACTIVE"))


if __name__ == "__main__":
    unittest.main()
