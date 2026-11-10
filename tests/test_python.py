import tempfile
import unittest
from pathlib import Path

from tests._path import ROOT  # noqa: F401
from tests.fixture_factory import EX, FixtureDir, J

from csr_lib import scanner
from csr_lib.model import Severity


def hits(res, rule_id, file=None):
    return [f for f in res.findings if f.rule_id == rule_id and (file is None or f.file == file)]


class PythonFixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fx = FixtureDir("python-pth")
        cls.root = cls.fx.__enter__()
        cls.res = scanner.run_scan(cls.root)

    @classmethod
    def tearDownClass(cls):
        cls.fx.__exit__(None, None, None)

    def test_setup_cmdclass_exec_b64_critical(self):
        h = hits(self.res, "PY-SETUP-CMDCLASS", "setup.py")
        self.assertEqual(h[0].severity, Severity.CRITICAL)
        self.assertIn("c2.example.invalid", h[0].decoded or "")

    def test_pth_import_critical(self):
        h = hits(self.res, "PY-PTH-IMPORT", "src/pkg/_hook.pth")
        self.assertEqual(h[0].severity, Severity.CRITICAL)

    def test_init_side_effect(self):
        h = hits(self.res, "PY-INIT-SIDE-EFFECT", "src/pkg/__init__.py")
        self.assertGreaterEqual(h[0].severity, Severity.HIGH)
        self.assertIn("192.0.2.10", h[0].snippet + h[0].detail)

    def test_local_backend_and_index_url(self):
        self.assertEqual(hits(self.res, "PY-LOCAL-BUILD-BACKEND", "pyproject.toml")[0].severity, Severity.HIGH)
        self.assertEqual(hits(self.res, "PY-INDEX-URL", "requirements.txt")[0].severity, Severity.HIGH)

    def test_inventory(self):
        self.assertIn("requirements.txt", self.res.inventory["manifests"])
        self.assertIn("setup.py", self.res.inventory["autorun_files"])


class PythonEdgeTests(unittest.TestCase):
    def _repo(self, files):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        for rel, content in files.items():
            p = root / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content)
        return root

    def test_clean_python_no_high(self):
        with FixtureDir("clean-python-app") as root:
            res = scanner.run_scan(root)
            self.assertFalse([f for f in res.findings if f.severity >= Severity.HIGH], res.findings)

    def test_benign_setup_py(self):
        root = self._repo({"setup.py": (
            "from setuptools import setup\nwith open('README.md') as f:\n    long_description = f.read()\n"
            "setup(name='x', version='1', long_description=long_description)\n")})
        res = scanner.run_scan(root)
        self.assertFalse([f for f in res.findings if f.severity >= Severity.MEDIUM], res.findings)

    def test_decode_exec_combo(self):
        root = self._repo({"tool/x.py": J("import zlib, base64\n", EX,
                                          "(zlib.decom", "press(base64.b64", "decode(DATA)))\n")})
        h = hits(scanner.run_scan(root), "PY-DANGEROUS-COMBO")
        self.assertEqual(h[0].severity, Severity.CRITICAL)

    def test_env_copy_with_requests_not_critical(self):
        root = self._repo({"tool/run.py": "import os, subprocess, requests\nenv = dict(os.environ)\n"
                                          "subprocess.run(['make'], env=env)\nrequests.get('https://pypi.org/simple')\n"})
        res = scanner.run_scan(root)
        self.assertFalse([f for f in res.findings if f.severity == Severity.CRITICAL], res.findings)

    def test_env_serialised_and_sent_is_critical(self):
        root = self._repo({"tool/x.py": J("import os, json, requests\n",
                                          "requests.po", "st(URL, data=json.du", "mps(dict(os.envi", "ron)))\n")})
        h = hits(scanner.run_scan(root), "PY-DANGEROUS-COMBO")
        self.assertEqual(h[0].severity, Severity.CRITICAL)

    def test_function_body_not_init_side_effect(self):
        root = self._repo({"pkg/__init__.py": "import requests\n\ndef fetch(u):\n    return requests.get(u)\n"})
        self.assertFalse(hits(scanner.run_scan(root), "PY-INIT-SIDE-EFFECT"))

    def test_py2_file_unparseable_info(self):
        root = self._repo({"setup.py": "print 'hello'\n"})
        h = hits(scanner.run_scan(root), "PY-UNPARSEABLE")
        self.assertEqual(h[0].severity, Severity.INFO)


if __name__ == "__main__":
    unittest.main()
