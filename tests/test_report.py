import json
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime
from pathlib import Path

from tests._path import ROOT
from tests.fixture_factory import FixtureDir

from csr_lib import report, scanner

TEMPLATE = (ROOT / "assets" / "report-template.md").read_text()
SECTIONS = ["## 1. Verdict", "## 2. Summary", "## 3. Findings", "## 4. Decoded payloads", "## 5. Dependencies",
            "## 6. Prompt injection", "## 7. Indicators of compromise", "## 8. Coverage", "## 9. Safe next steps"]


def scan_json(root):
    sys.path.insert(0, str(ROOT / "scripts"))
    import scan  # noqa
    return json.loads(json.dumps(scan.result_to_json(root, scanner.run_scan(root))))


class ReportTests(unittest.TestCase):
    def render(self, name, deps=None):
        with FixtureDir(name) as root:
            s = scan_json(root)
        return report.render(s, deps, TEMPLATE, name, datetime(2026, 11, 10, 12, 0))

    def test_render_vscode_fixture(self):
        md = self.render("vscode-folderopen")
        self.assertIn("MALICIOUS", md)
        self.assertIn("AUTORUN-VSCODE-FOLDEROPEN", md)
        iocs = md.split("## 7. Indicators of compromise")[1].split("## 8.")[0]
        self.assertIn("payload.example.invalid", iocs)
        pos = [md.index(s) for s in SECTIONS]
        self.assertEqual(pos, sorted(pos))

    def test_clean_fixture_wording(self):
        md = self.render("clean-node-app")
        verdict_line = next(line for line in md.splitlines() if "Proposed verdict" in line)
        self.assertIn("NO INDICATORS FOUND", verdict_line)
        self.assertNotRegex(verdict_line.lower(), r"\b(safe|clean)\b")

    def test_invisible_chars_escaped(self):
        md = self.render("prompt-injection")
        self.assertIn("<U+E00", md)
        self.assertFalse(any(0xE0000 <= ord(c) <= 0xE007F or ord(c) in (0x200B, 0x202E) for c in md))

    def test_low_findings_capped(self):
        s = {"root": "/x", "findings": [{"rule_id": "JS-EXEC", "severity": "LOW", "file": f"f{i}.js", "line": 1,
                                         "title": "t", "snippet": "s", "detail": "d", "decoded": None, "count": 1,
                                         "sha256": None} for i in range(500)],
             "inventory": {"files_scanned": 500}, "skipped": [], "errors": []}
        md = report.render(s, None, TEMPLATE, "x", datetime(2026, 11, 10))
        rows = [line for line in md.splitlines() if line.startswith("| LOW | JS-EXEC")]
        self.assertEqual(len(rows), 200)
        self.assertIn("300 more", md)

    def test_deps_section(self):
        deps = {"npm_audit": {"ran": True, "counts": {"high": 1}, "advisories": [
                    {"name": "zod", "severity": "high", "title": "T", "url": "u", "range": "<4"}]},
                "osv": {"ran": True, "vulns": [{"ecosystem": "npm", "name": "x", "version": "1", "id": "MAL-1",
                                                "summary": "bad", "malicious": True}]},
                "packages": [], "findings": [], "deep_audits": [], "coverage": {"not_audited": [], "notes": ["n1"]}}
        with FixtureDir("clean-node-app") as root:
            s = scan_json(root)
        md = report.render(s, deps, TEMPLATE, "x", datetime(2026, 11, 10))
        sec = md.split("## 5. Dependencies")[1].split("## 6.")[0]
        self.assertIn("MAL-1", sec)
        self.assertIn("zod", sec)
        self.assertIn("n1", md)

    def test_extract_iocs(self):
        f = [{"snippet": "curl https://c2.example.invalid/x and http://192.0.2.10:8087/api", "detail": "",
              "decoded": "https://registry.npmjs.org/x", "file": "a", "sha256": "ab" * 32, "severity": "HIGH"}]
        i = report.extract_iocs(f)
        self.assertIn("c2.example.invalid", i["domains"])
        self.assertIn("192.0.2.10", i["ips"])
        self.assertNotIn("registry.npmjs.org", i["domains"])

    def test_refuses_write_inside_repo(self):
        with FixtureDir("clean-node-app") as root, tempfile.TemporaryDirectory() as tmp:
            sj = Path(tmp) / "scan.json"
            subprocess.run([sys.executable, "-I", str(ROOT / "scripts" / "scan.py"), str(root), "--json", str(sj)],
                           check=True, capture_output=True)
            r = subprocess.run([sys.executable, "-I", str(ROOT / "scripts" / "render_report.py"), "--scan", str(sj),
                                "--out", str(root / "r.md")], capture_output=True, text=True)
            self.assertEqual(r.returncode, 2)
            self.assertIn("refusing to write report inside the reviewed repository", r.stderr)
            r = subprocess.run([sys.executable, "-I", str(ROOT / "scripts" / "render_report.py"), "--scan", str(sj),
                                "--out", str(Path(tmp) / "r.md")], capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn("## 9. Safe next steps", (Path(tmp) / "r.md").read_text())


if __name__ == "__main__":
    unittest.main()
