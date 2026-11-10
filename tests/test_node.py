import json
import tempfile
import unittest
from pathlib import Path

from tests._path import ROOT  # noqa: F401
from tests.fixture_factory import CP, EV, FixtureDir, J

from csr_lib import scanner
from csr_lib.model import Severity


def hits(res, rule_id, file=None):
    return [f for f in res.findings if f.rule_id == rule_id and (file is None or f.file == file)]


class NodeFixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fx = FixtureDir("npm-postinstall")
        cls.root = cls.fx.__enter__()
        cls.res = scanner.run_scan(cls.root)

    @classmethod
    def tearDownClass(cls):
        cls.fx.__exit__(None, None, None)

    def test_postinstall_stealer_critical(self):
        h = hits(self.res, "NODE-LIFECYCLE-SCRIPT", "package.json")
        self.assertEqual(h[0].severity, Severity.CRITICAL)
        self.assertIn("lib/setup.js", h[0].detail)
        c = hits(self.res, "JS-DANGEROUS-COMBO", "lib/setup.js")
        self.assertEqual(c[0].severity, Severity.CRITICAL)
        self.assertIn("evil.example.invalid", c[0].decoded or "")

    def test_import_time_payload(self):
        h = hits(self.res, "NODE-ENTRY-SIDE-EFFECT", "index.js")
        self.assertTrue(h)
        self.assertGreaterEqual(h[0].severity, Severity.HIGH)
        self.assertIn("index.js", self.res.inventory["entry_points"])

    def test_npmrc_git_override(self):
        h = hits(self.res, "NODE-NPMRC-OVERRIDE", ".npmrc")
        self.assertEqual(h[0].severity, Severity.CRITICAL)

    def test_lockfile_anomalies(self):
        self.assertTrue(hits(self.res, "NODE-LOCKFILE-SOURCE", "package-lock.json"))
        self.assertTrue(hits(self.res, "NODE-LOCKFILE-NO-INTEGRITY", "package-lock.json"))
        self.assertIn("package-lock.json", self.res.inventory["lockfiles"])

    def test_git_dependency(self):
        h = hits(self.res, "NODE-DEP-NONREGISTRY", "package.json")
        self.assertTrue(any("helper" in f.snippet for f in h))


class NodeEdgeTests(unittest.TestCase):
    def _repo(self, files):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        for rel, content in files.items():
            p = root / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content)
        return root

    def test_husky_prepare_is_medium_not_high(self):
        with FixtureDir("clean-node-app") as root:
            h = hits(scanner.run_scan(root), "NODE-LIFECYCLE-SCRIPT")
            self.assertEqual([f.severity for f in h], [Severity.MEDIUM])

    def test_generic_eval_alone_is_low(self):
        root = self._repo({"lib/x.js": J("function f(s){return ", EV, "(s)}\nmodule.exports=f\n")})
        res = scanner.run_scan(root)
        self.assertTrue(hits(res, "JS-EXEC"))
        self.assertFalse([f for f in res.findings if f.severity > Severity.LOW])

    def test_benign_minified_bundle_not_high(self):
        with FixtureDir("clean-node-app") as root:
            res = scanner.run_scan(root)
            self.assertFalse([f for f in res.findings if f.file == "public/vendor.min.js"
                              and f.severity >= Severity.HIGH])

    def test_debugger_trap(self):
        root = self._repo({"a.js": "(function(j){}).constructor('while (true) {}').apply('counter');\n"})
        h = hits(scanner.run_scan(root), "JS-DANGEROUS-COMBO")
        self.assertEqual(h[0].severity, Severity.CRITICAL)

    def test_ai_cli_abuse(self):
        root = self._repo({"t.js": J("require('", CP, "').spawn('claude', ['--dangerously-skip-permissions',"
                                     " '-p', 'find secrets'])\n")})
        self.assertTrue(hits(scanner.run_scan(root), "JS-AI-CLI-ABUSE"))

    def test_iife_entry_side_effect(self):
        root = self._repo({
            "package.json": json.dumps({"name": "x", "main": "lib/main.js"}),
            "lib/main.js": J("(function(){ require('htt", "ps').get('https://198.51.100.7/x'); })();\n"),
        })
        h = hits(scanner.run_scan(root), "NODE-ENTRY-SIDE-EFFECT", "lib/main.js")
        self.assertTrue(h)

    def test_function_body_network_not_entry_side_effect(self):
        root = self._repo({
            "package.json": json.dumps({"name": "x", "main": "index.js"}),
            "index.js": "module.exports = async function get(u) {\n  return fetch(u);\n};\n",
        })
        self.assertFalse(hits(scanner.run_scan(root), "NODE-ENTRY-SIDE-EFFECT"))

    def test_env_copy_for_child_process_is_not_env_dump(self):
        root = self._repo({"cli.js": J("const cp = require('", CP, "');\n",
                                       "cp.spawn('git', ['status'], { env: { ...process.env, LANG: 'C' } });\n",
                                       "fetch('https://api.github.com/repos/x/y');\n")})
        res = scanner.run_scan(root)
        self.assertFalse([f for f in res.findings if f.severity == Severity.CRITICAL], res.findings)

    def test_secret_read_plus_network_is_high_not_critical(self):
        root = self._repo({"deploy.js": "const fs = require('fs');\nconst cfg = fs.readFileSync(os.homedir() + "
                                        "'/.aws/config');\nfetch('https://deploy.example.invalid', {method:'POST'});\n"})
        h = hits(scanner.run_scan(root), "JS-DANGEROUS-COMBO")
        self.assertEqual(h[0].severity, Severity.HIGH)

    def test_private_registry_npmrc_is_info(self):
        root = self._repo({".npmrc": "@acme:registry=https://npm.acme.example.invalid/\n"})
        h = hits(scanner.run_scan(root), "NODE-NPMRC-OVERRIDE")
        self.assertEqual(h[0].severity, Severity.INFO)


if __name__ == "__main__":
    unittest.main()
