import tempfile
import unittest
from pathlib import Path

from tests._path import ROOT
from tests.fixture_factory import FixtureDir

from csr_lib import deps, walker

ASSETS = ROOT / "assets"


def collect(root):
    files, _, _ = walker.walk(root)
    return deps.collect(root, files)


class DepsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pop_npm = deps.load_list(ASSETS / "popular-npm.txt")
        cls.pop_pypi = deps.load_list(ASSETS / "popular-pypi.txt")
        cls.allow = deps.load_list(ASSETS / "install-script-allowlist.txt")

    def test_lists_loaded(self):
        self.assertGreaterEqual(len(self.pop_npm), 300)
        self.assertGreaterEqual(len(self.pop_pypi), 300)
        self.assertIn("esbuild", self.allow)

    def test_collect_package_lock_v3(self):
        with FixtureDir("clean-node-app") as root:
            pkgs = {p.name: p for p in collect(root) if p.ecosystem == "npm"}
            self.assertEqual(pkgs["express"].version, "4.19.2")
            self.assertEqual(pkgs["express"].source, "registry")
            self.assertTrue(pkgs["express"].direct)
            self.assertTrue(pkgs["husky"].direct)

    def test_collect_npm_postinstall_fixture(self):
        with FixtureDir("npm-postinstall") as root:
            pkgs = {p.name: p for p in collect(root) if p.ecosystem == "npm"}
            self.assertEqual(pkgs["helper"].source, "git")
            # registry-shaped URL on a host the repo never declared as its registry -> untrusted URL, not private
            self.assertEqual(pkgs["left-pad"].source, "url")
            self.assertTrue(pkgs["plain-crypto-js"].has_install_script)
            self.assertFalse(pkgs["plain-crypto-js"].direct)

    def test_requirements_and_typosquat(self):
        with FixtureDir("python-pth") as root:
            pkgs = collect(root)
            deps.flag_packages(pkgs, self.allow, self.pop_npm, self.pop_pypi)
            p = next(p for p in pkgs if p.name == "reqeusts")
            self.assertEqual((p.ecosystem, p.version), ("PyPI", "2.31.0"))
            self.assertIn("typosquat:requests", p.flags)
            self.assertTrue(deps.needs_deep_audit(p))

    def test_typosquat_cases(self):
        t = lambda n: deps.typosquat_of(n, self.pop_npm)  # noqa: E731
        self.assertEqual(t("lodash-utilz"), "lodash")
        self.assertEqual(t("reakt-dom"), "react-dom")
        self.assertEqual(t("crossenv"), "cross-env")
        self.assertEqual(t("expresss"), "express")
        self.assertEqual(t("@typescript_eslint/parser"), "@typescript-eslint")
        self.assertIsNone(t("lodash"))
        self.assertIsNone(t("express"))
        self.assertIsNone(t("preact"))
        self.assertIsNone(t("my-internal-thing"))

    def test_allowlisted_install_script(self):
        pk = [deps.Package("npm", "esbuild", "0.21.5", False, "registry", None, True, "package-lock.json", []),
              deps.Package("npm", "@esbuild/darwin-arm64", "0.21.5", False, "registry", None, True,
                           "package-lock.json", []),
              deps.Package("npm", "plain-crypto-js", "4.2.1", False, "registry", None, True, "package-lock.json", [])]
        deps.flag_packages(pk, self.allow, self.pop_npm, self.pop_pypi)
        self.assertEqual(pk[0].flags, [])
        self.assertEqual(pk[1].flags, [])
        self.assertIn("install-script", pk[2].flags)

    def _repo(self, files):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        for rel, content in files.items():
            p = root / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content)
        return root

    def test_private_scope_not_deep_audited(self):
        root = self._repo({
            ".npmrc": "@acme:registry=https://npm.acme.example.invalid/\n",
            "package.json": '{"name":"x","dependencies":{"@acme/core":"1.2.3","zod":"3.23.8"}}',
        })
        pkgs = {p.name: p for p in collect(root)}
        deps.flag_packages(list(pkgs.values()), self.allow, self.pop_npm, self.pop_pypi)
        self.assertEqual(pkgs["@acme/core"].source, "private")
        self.assertFalse(deps.needs_deep_audit(pkgs["@acme/core"]))
        self.assertEqual(pkgs["zod"].version, "3.23.8")

    def test_yarn_and_pnpm_lock(self):
        root = self._repo({
            "yarn.lock": ('# yarn lockfile v1\n\n\n"@babel/core@^7.0.0", "@babel/core@^7.1.0":\n  version "7.24.0"\n'
                          '  resolved "https://registry.yarnpkg.com/@babel/core/-/core-7.24.0.tgz#abc"\n\n'
                          'chalk@^4.1.0:\n  version "4.1.2"\n  resolved "https://registry.yarnpkg.com/chalk/-/chalk-4.1.2.tgz"\n'),
            "pnpm-lock.yaml": ("lockfileVersion: '9.0'\n\npackages:\n\n  '@types/node@20.11.5':\n"
                               "    resolution: {integrity: sha512-x}\n\n  esbuild@0.20.2:\n"
                               "    resolution: {integrity: sha512-y}\n    hasBin: true\n    requiresBuild: true\n\n"
                               "snapshots:\n\n  esbuild@0.20.2: {}\n"),
        })
        got = {(p.name, p.version) for p in collect(root)}
        for exp in [("@babel/core", "7.24.0"), ("chalk", "4.1.2"), ("@types/node", "20.11.5"), ("esbuild", "0.20.2")]:
            self.assertIn(exp, got)
        es = next(p for p in collect(root) if p.name == "esbuild")
        self.assertTrue(es.has_install_script)

    def test_poetry_and_pipfile_lock(self):
        root = self._repo({
            "poetry.lock": '[[package]]\nname = "Django"\nversion = "4.2.11"\n\n[[package]]\nname = "idna"\nversion = "3.6"\n',
            "Pipfile.lock": '{"default": {"urllib3": {"version": "==2.2.1"}}, "develop": {}}',
        })
        got = {(p.name.lower(), p.version) for p in collect(root)}
        self.assertIn(("django", "4.2.11"), got)
        self.assertIn(("urllib3", "2.2.1"), got)


if __name__ == "__main__":
    unittest.main()
