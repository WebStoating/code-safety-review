import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from tests._path import ROOT  # noqa: F401  (sets sys.path)

from csr_lib import decode, walker
from csr_lib.model import Finding, Severity
from csr_lib import scanner


class WalkerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_walk_skips_git_objects_and_caps_size(self):
        (self.root / ".git" / "objects").mkdir(parents=True)
        (self.root / ".git" / "objects" / "x").write_text("blob")
        (self.root / ".git" / "config").write_text("[core]\n")
        (self.root / "big.bin").write_bytes(b"\0" * 6_000_000)
        (self.root / "a.txt").write_text("hello")
        files, skipped, findings = walker.walk(self.root)
        rels = {f.rel for f in files}
        self.assertIn("a.txt", rels)
        self.assertIn(".git/config", rels)
        self.assertNotIn(".git/objects/x", rels)
        self.assertIn(("big.bin", "size>5000000"), {(s.rel, s.reason) for s in skipped})

    def test_symlink_outside_root_not_followed(self):
        os.symlink(os.path.expanduser("~"), self.root / "home-link")
        files, skipped, findings = walker.walk(self.root)
        self.assertFalse(any(f.rel.startswith("home-link") for f in files))
        hits = [f for f in findings if f.rule_id == "FS-SYMLINK-ESCAPE"]
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].severity, Severity.MEDIUM)

    def test_walk_20k_files_under_budget(self):
        d = self.root / "node_modules" / "pkg"
        d.mkdir(parents=True)
        for i in range(20_000):
            (d / f"f{i}.js").write_text("module.exports = 1;\n")
        t0 = time.time()
        files, _, _ = walker.walk(self.root)
        self.assertEqual(len(files), 20_000)
        self.assertLess(time.time() - t0, 20)


class DecodeTests(unittest.TestCase):
    def test_decode_text_utf16_and_bom(self):
        self.assertIn("runOn", walker.decode_text('{"runOn": 1}'.encode("utf-16")))
        self.assertEqual(walker.decode_text(b"\xef\xbb\xbf{}"), "{}")
        self.assertIsNone(walker.decode_text(bytes(range(256)) * 4))

    def test_try_base64(self):
        self.assertEqual(decode.try_base64("aHR0cHM6Ly9ldmlsLmV4YW1wbGUvYw=="), "https://evil.example/c")
        self.assertIsNone(decode.try_base64("not base64 at all!!"))

    def test_try_hex(self):
        self.assertEqual(decode.try_hex("68656c6c6f20776f726c64"), "hello world")
        self.assertEqual(decode.try_hex("\\x68\\x69\\x21"), "hi!")

    def test_decode_charcodes(self):
        self.assertEqual(decode.decode_charcodes("String.fromCharCode(104,105)"), "hi")
        self.assertEqual(decode.decode_charcodes("chr(104)+chr(105)"), "hi")

    def test_unicode_tags_and_escape(self):
        s = "ok" + "".join(chr(0xE0000 + ord(c)) for c in "rm -rf")
        self.assertEqual(decode.decode_unicode_tags(s), "rm -rf")
        self.assertEqual(decode.escape_invisible("a\u200bb"), "a<U+200B>b")
        self.assertEqual(decode.escape_invisible("x\u202ey"), "x<U+202E>y")

    def test_line_and_snippet(self):
        text = "one\ntwo\nthree four"
        idx = text.index("four")
        self.assertEqual(decode.line_of(text, idx), 3)
        self.assertIn("four", decode.snippet(text, idx))
        self.assertNotIn("\n", decode.snippet(text, idx))


class ScannerTests(unittest.TestCase):
    def test_aggregates_per_file_rule(self):
        fs = [Finding("JS-EXEC", Severity.LOW, "a.js", i + 1, "t", "s", "d") for i in range(50)]
        fs.append(Finding("JS-EXEC", Severity.LOW, "b.js", 1, "t", "s", "d"))
        out = scanner.aggregate(fs)
        by_file = {f.file: f for f in out}
        self.assertEqual(len(out), 2)
        self.assertEqual(by_file["a.js"].count, 50)
        self.assertEqual(by_file["a.js"].line, 1)

    def test_aggregate_keeps_highest_severity(self):
        fs = [Finding("R", Severity.LOW, "a.js", 1, "t", "s", "d"),
              Finding("R", Severity.HIGH, "a.js", 9, "t", "s2", "d")]
        out = scanner.aggregate(fs)
        self.assertEqual(out[0].severity, Severity.HIGH)
        self.assertEqual(out[0].line, 9)

    def test_finding_to_dict(self):
        d = Finding("X", Severity.CRITICAL, "f", 2, "t", "s", "d").to_dict()
        self.assertEqual(d["severity"], "CRITICAL")
        self.assertEqual(d["rule_id"], "X")

    def test_scan_cli_writes_json(self):
        with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as out:
            for i in range(3):
                Path(tmp, f"f{i}.py").write_text("print(1)\n")
            outfile = Path(out) / "scan.json"
            r = subprocess.run([sys.executable, "-I", str(ROOT / "scripts" / "scan.py"), tmp,
                                "--json", str(outfile)], capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)
            data = json.loads(outfile.read_text())
            for k in ("tool", "findings", "inventory", "skipped", "errors"):
                self.assertIn(k, data)
            self.assertEqual(data["inventory"]["files_scanned"], 3)
            self.assertEqual(data["inventory"]["languages"].get(".py"), 3)

    def test_scan_cli_bad_dir(self):
        r = subprocess.run([sys.executable, "-I", str(ROOT / "scripts" / "scan.py"), "/nonexistent/x"],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 1)


if __name__ == "__main__":
    unittest.main()
