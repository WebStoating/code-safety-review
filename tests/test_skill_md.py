import re
import unittest
from pathlib import Path

from tests._path import REPO_ROOT, ROOT

from csr_lib import scanner
from csr_lib.model import Severity

SKILL = ROOT / "SKILL.md"


def frontmatter(text):
    m = re.match(r"^---\n(.*?)\n---\n", text, re.S)
    assert m, "missing frontmatter"
    fm, cur = {}, None
    for line in m.group(1).splitlines():
        if re.match(r"^\S[^:]*:", line):
            k, v = line.split(":", 1)
            cur = k.strip()
            fm[cur] = v.strip().strip('"') if v.strip() else {}
        elif cur and isinstance(fm[cur], dict) and line.startswith("  "):
            k, v = line.strip().split(":", 1)
            fm[cur][k.strip()] = v.strip()
    return fm


class SkillMdTests(unittest.TestCase):
    def test_frontmatter_valid(self):
        fm = frontmatter(SKILL.read_text())
        self.assertEqual(fm["name"], ROOT.name)
        self.assertEqual(fm["name"], "review")
        self.assertRegex(fm["name"], r"^[a-z0-9]+(-[a-z0-9]+)*$")
        self.assertLessEqual(len(fm["name"]), 64)
        self.assertTrue(1 <= len(fm["description"]) <= 1024, len(fm["description"]))
        self.assertLessEqual(len(fm.get("compatibility", "")), 500)
        self.assertIsInstance(fm.get("metadata"), dict)
        for v in fm["metadata"].values():
            self.assertRegex(v, r'^".*"$', "metadata values must be strings (quoted)")

    def test_skill_md_under_500_lines(self):
        self.assertLess(len(SKILL.read_text().splitlines()), 500)

    def test_referenced_files_exist(self):
        text = SKILL.read_text()
        refs = set(re.findall(r"\b((?:references|scripts|assets)/[\w./-]+\.(?:md|py|txt))", text))
        self.assertTrue(refs)
        for r in refs:
            self.assertTrue((ROOT / r).is_file(), r)

    def test_rule_ids_documented(self):
        src = ""
        for p in list((ROOT / "scripts").rglob("*.py")):
            src += p.read_text()
        ids = set(re.findall(r'"((?:AUTORUN|PAYLOAD|NODE|JS|PY|PI|GIT|DEP|FS)-[A-Z0-9-]+)"', src))
        docs = (ROOT / "references" / "attack-patterns.md").read_text() + \
            (ROOT / "references" / "prompt-injection.md").read_text()
        missing = sorted(i for i in ids if i not in docs)
        self.assertEqual(missing, [])

    def test_skill_repo_self_scan_has_no_high_findings(self):
        """Nothing in this repository should look like malware (fixtures are generated at test time)."""
        res = scanner.run_scan(REPO_ROOT, include_git=False)
        bad = [(f.rule_id, f.file, f.line) for f in res.findings
               if f.severity >= Severity.HIGH and not f.file.startswith((".git/", "__pycache__"))
               and "/__pycache__/" not in f.file]
        self.assertEqual(bad, [])


if __name__ == "__main__":
    unittest.main()
