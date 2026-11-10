import os
import tempfile
import unittest
from pathlib import Path

from tests._path import ROOT  # noqa: F401
from tests.fixture_factory import FixtureDir

from csr_lib import scanner
from csr_lib.patterns import KNOWN_IOC_LIST
from csr_lib.model import Severity


def hits(res, rule_id, file=None):
    return [f for f in res.findings if f.rule_id == rule_id and (file is None or f.file == file)]


class PayloadTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fx = FixtureDir("font-payload")
        cls.root = cls.fx.__enter__()
        cls.res = scanner.run_scan(cls.root)

    @classmethod
    def tearDownClass(cls):
        cls.fx.__exit__(None, None, None)

    def test_font_payload_critical(self):
        h = hits(self.res, "PAYLOAD-EXT-MISMATCH", "public/fonts/fa-brands-regular.woff2")
        self.assertTrue(h, self.res.findings)
        self.assertEqual(h[0].severity, Severity.CRITICAL)
        self.assertIn("c2.example.invalid", h[0].decoded or "")

    def test_interpreter_on_font(self):
        h = hits(self.res, "PAYLOAD-INTERPRETER-NONCODE", ".vscode/tasks.json")
        self.assertTrue(h)
        self.assertEqual(h[0].severity, Severity.CRITICAL)

    def test_spellright_dict(self):
        h = hits(self.res, "PAYLOAD-CODE-IN-DATA", "spellright.dict")
        self.assertTrue(h)
        self.assertGreaterEqual(h[0].severity, Severity.HIGH)

    def test_binary_and_env(self):
        b = hits(self.res, "PAYLOAD-BINARY", "bin/helper.exe")
        self.assertTrue(b)
        self.assertEqual(len(b[0].sha256 or ""), 64)
        self.assertTrue(hits(self.res, "PAYLOAD-SECRET-FILE", ".env"))


class PayloadEdgeTests(unittest.TestCase):
    def _repo(self, files):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        for rel, content in files.items():
            p = root / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(content if isinstance(content, bytes) else content.encode())
        return root

    def test_real_woff2_not_flagged(self):
        root = self._repo({"x.woff2": b"wOF2" + os.urandom(200), "y.png": b"\x89PNG\r\n\x1a\n" + os.urandom(100)})
        res = scanner.run_scan(root)
        self.assertFalse(hits(res, "PAYLOAD-EXT-MISMATCH"))

    def test_known_ioc(self):
        root = self._repo({"notes.txt": "connect to " + KNOWN_IOC_LIST[0] + " later\n"})
        h = hits(scanner.run_scan(root), "PAYLOAD-KNOWN-IOC")
        self.assertEqual(h[0].severity, Severity.CRITICAL)

    def test_env_example_not_flagged(self):
        root = self._repo({".env.example": "API_KEY=\n"})
        self.assertFalse(hits(scanner.run_scan(root), "PAYLOAD-SECRET-FILE"))

    def test_elf_disguised_as_text(self):
        root = self._repo({"docs/readme.txt": b"\x7fELF\x02\x01\x01" + os.urandom(100)})
        h = hits(scanner.run_scan(root), "PAYLOAD-BINARY")
        self.assertEqual(h[0].severity, Severity.HIGH)


if __name__ == "__main__":
    unittest.main()
