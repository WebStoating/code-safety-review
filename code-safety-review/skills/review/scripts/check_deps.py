#!/usr/bin/env python3
"""Dependency checks for an untrusted folder: inventory, typosquats, install scripts, npm audit,
OSV.dev (incl. MAL- malicious-package advisories), and deep audit of flagged packages from their
published tarballs.

Usage: python3 -I check_deps.py <repo> --json OUT [--scratch DIR] [--offline] [--max-deep 25] [--max-bytes N]

Never installs or runs anything from <repo> or from downloaded packages. npm is only ever run
inside the scratch directory, with lifecycle scripts disabled and a clean config.
"""
from __future__ import annotations

import argparse
import json
import sys
import tempfile
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

sys.path.insert(0, str(Path(__file__).resolve().parent))

from csr_lib import deps, registry, walker  # noqa: E402
from csr_lib.model import Finding, Severity  # noqa: E402

ASSETS = Path(__file__).resolve().parent.parent / "assets"
SEV_RANK = {s.name: int(s) for s in Severity}


def _finding(rule: str, sev: Severity, p: deps.Package, title: str, snippet: str, detail: str) -> dict:
    return Finding(rule, sev, p.manifest, None, title, snippet, detail).to_dict()


def _priority(p: deps.Package) -> int:
    f = " ".join(p.flags)
    if "malware-advisory" in f:
        return 0
    if "typosquat" in f:
        return 1
    if "non-registry" in f:
        return 2
    return 3


def run(root: Path, scratch: Path, offline: bool = False, max_deep: int = 25, max_bytes: int = 5_000_000,
        runner: Any = None, http: Any = None) -> Dict[str, Any]:
    runner = runner or registry.Runner()
    http = http or registry.Http()
    root = Path(root).resolve()
    scratch = Path(scratch)
    scratch.mkdir(parents=True, exist_ok=True)
    files, _, _ = walker.walk(root, max_bytes)
    pkgs = deps.collect(root, files)
    allow = deps.load_list(ASSETS / "install-script-allowlist.txt")
    pop_npm = deps.load_list(ASSETS / "popular-npm.txt")
    pop_pypi = deps.load_list(ASSETS / "popular-pypi.txt")
    deps.flag_packages(pkgs, allow, pop_npm, pop_pypi)

    coverage: Dict[str, Any] = {"not_audited": [], "notes": []}
    findings: List[dict] = []
    for p in pkgs:
        if p.source == "private":
            coverage["not_audited"].append({"name": p.name, "reason": "private registry — never looked up publicly"})
        elif p.source == "file":
            coverage["not_audited"].append({"name": p.name, "reason": "local path dependency — part of this repo"})

    npm_manifests = [f.rel for f in files if f.name == "package.json" and "node_modules/" not in f.rel]
    has_npm = any(p.ecosystem == "npm" for p in pkgs) or bool(npm_manifests)
    if offline:
        npm_audit = {"ran": False, "reason": "offline", "counts": {}, "advisories": []}
        osv = {"ran": False, "reason": "offline", "vulns": []}
        coverage["notes"].append("Offline mode: npm audit, OSV and registry deep audits were skipped.")
    else:
        if has_npm:
            npm_audit = registry.run_npm_audit(root, pkgs, runner, scratch, npm_manifests)
            for n in npm_audit.pop("not_audited", []):
                if not any(x["name"] == n for x in coverage["not_audited"]):
                    coverage["not_audited"].append({"name": n, "reason": "non-registry source — excluded from npm audit"})
        else:
            npm_audit = {"ran": False, "reason": "no npm manifests", "counts": {}, "advisories": []}
        osv = registry.osv_query(pkgs, http)

    malicious = {(v["ecosystem"], v["name"]) for v in osv.get("vulns", []) if v.get("malicious")}
    malicious |= {("npm", a["name"]) for a in npm_audit.get("advisories", []) if a.get("malware")}
    by_key = {(p.ecosystem, p.name): p for p in pkgs}
    for v in osv.get("vulns", []):
        if v.get("malicious"):
            p = by_key.get((v["ecosystem"], v["name"]))
            if p:
                findings.append(_finding("DEP-MALWARE-ADVISORY", Severity.CRITICAL, p,
                                         f"{p.name}@{p.version} is a known malicious package ({v['id']})",
                                         f"{v['id']}: {v.get('summary') or ''}",
                                         "OSV lists this exact version as malware. Do not install; treat any "
                                         "machine that installed it as compromised."))
    for a in npm_audit.get("advisories", []):
        if a.get("malware"):
            p = by_key.get(("npm", a["name"]))
            if p:
                findings.append(_finding("DEP-MALWARE-ADVISORY", Severity.CRITICAL, p,
                                         f"{a['name']} has a malware advisory", f"{a['title']} {a.get('url') or ''}",
                                         "npm audit reports malicious code in this package."))
    for p in pkgs:
        if (p.ecosystem, p.name) in malicious and "malware-advisory" not in p.flags:
            p.flags.append("malware-advisory")

    candidates = sorted([p for p in pkgs if deps.needs_deep_audit(p)], key=_priority)
    deep: List[Dict[str, Any]] = []
    if not offline:
        network_down = False
        for i, p in enumerate(candidates):
            if network_down:
                coverage["not_audited"].append({"name": p.name, "reason": "network unavailable — deep audit skipped"})
                continue
            if i >= max_deep:
                coverage["not_audited"].append({"name": p.name, "reason": "max-deep"})
                continue
            try:
                if p.source in ("git", "url"):
                    deep.append(registry.deep_audit_url(p, http, scratch, max_bytes))
                elif p.ecosystem == "npm":
                    deep.append(registry.deep_audit_npm(p, runner, http, scratch, max_bytes))
                else:
                    deep.append(registry.deep_audit_pypi(p, http, scratch, max_bytes))
            except Exception as e:  # never let one package abort the run
                deep.append({"ecosystem": p.ecosystem, "name": p.name, "version": p.version, "metadata": {},
                             "red_flags": [], "scan_findings": [], "error": f"{type(e).__name__}: {e}"})
            if deep[-1].get("network_error"):
                network_down = True
                coverage["notes"].append("Network failure during deep audits; remaining packages skipped. "
                                         "Re-run with network or use --offline.")
    else:
        for p in candidates:
            coverage["not_audited"].append({"name": p.name, "reason": "offline — deep audit skipped"})
    deep_by = {(d["ecosystem"], d["name"]): d for d in deep}

    for p in pkgs:
        d = deep_by.get((p.ecosystem, p.name))
        worst = max((SEV_RANK.get(f["severity"], 0) for f in (d or {}).get("scan_findings", [])), default=0)
        for fl in p.flags:
            if fl.startswith("typosquat:"):
                findings.append(_finding("DEP-TYPOSQUAT", Severity.HIGH, p,
                                         f"{p.name} looks like a typosquat of {fl.split(':', 1)[1]}",
                                         f"{p.name}@{p.version or '*'} ({p.ecosystem})",
                                         "Name is a near-miss of a popular package — the top delivery method for "
                                         "malicious packages. Confirm it is the package you intend."))
            elif fl == "install-script":
                sev = Severity.MEDIUM
                if worst >= Severity.CRITICAL:
                    sev = Severity.CRITICAL
                elif worst >= Severity.HIGH:
                    sev = Severity.HIGH
                findings.append(_finding("DEP-INSTALL-SCRIPT", sev, p,
                                         f"{p.name}@{p.version} runs an install script",
                                         json.dumps((d or {}).get("metadata", {}).get("scripts") or "hasInstallScript"),
                                         "Install scripts run on `npm install`. Not on the allowlist of well-known "
                                         "install-script packages." + (" Its published tarball has "
                                                                       f"{Severity(worst).name} scan findings."
                                                                       if worst >= Severity.HIGH else "")))
            elif fl == "non-registry":
                findings.append(_finding("DEP-NONREGISTRY", Severity.MEDIUM, p,
                                         f"{p.name} comes from {p.source}, not the registry", str(p.resolved)[:200],
                                         "Bypasses registry malware takedowns; git deps can ship .npmrc/prepare "
                                         "payloads that run even with --ignore-scripts."))
        if d and len(d.get("red_flags", [])) >= 2:
            findings.append(_finding("DEP-DEEP-RED-FLAGS", Severity.HIGH, p,
                                     f"{p.name}@{d.get('version')} has {len(d['red_flags'])} registry red flags",
                                     ", ".join(d["red_flags"])[:300],
                                     "Young/obscure package, install scripts, maintainer change or suspicious "
                                     "tarball contents. Review the deep-audit section."))
    private = [p.name for p in pkgs if p.source == "private"]
    if private:
        findings.append(Finding("DEP-PRIVATE", Severity.INFO, "(dependencies)", None,
                                f"{len(private)} private-registry packages not audited",
                                ", ".join(private[:20]), "Never looked up on public registries "
                                "(dependency-confusion safety).", count=len(private)).to_dict())
    coverage["notes"].append("`npm audit signatures` not run: it needs an installed node_modules tree, which this "
                             "skill never creates.")
    if not any(p.ecosystem == "PyPI" for p in pkgs) and any(f.ext == ".py" for f in files):
        coverage["notes"].append("Python files present but no Python dependency manifest/lockfile found.")
    findings.sort(key=lambda f: -SEV_RANK[f["severity"]])
    return {
        "tool": "code-safety-review/check-deps",
        "version": "1.0",
        "root": str(root),
        "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "offline": offline,
        "scratch": str(scratch),
        "packages": [asdict(p) for p in pkgs],
        "findings": findings,
        "npm_audit": npm_audit,
        "osv": osv,
        "deep_audits": deep,
        "coverage": coverage,
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Dependency checks for an untrusted folder (never installs).")
    ap.add_argument("repo")
    ap.add_argument("--json", dest="json_out", required=True)
    ap.add_argument("--scratch", help="work dir for npm audit copies and downloaded tarballs (default: new temp dir)")
    ap.add_argument("--offline", action="store_true", help="no network: skip npm audit, OSV and deep audits")
    ap.add_argument("--max-deep", type=int, default=25)
    ap.add_argument("--max-bytes", type=int, default=5_000_000)
    a = ap.parse_args(argv)
    root = Path(a.repo).expanduser()
    if not root.is_dir():
        print(f"error: {root} is not a directory", file=sys.stderr)
        return 1
    root = root.resolve()
    scratch = Path(a.scratch).resolve() if a.scratch else Path(tempfile.mkdtemp(prefix="csr-"))
    if scratch == root or root in scratch.parents:
        print("error: --scratch must be outside the reviewed repository", file=sys.stderr)
        return 1
    data = run(root, scratch, a.offline, a.max_deep, a.max_bytes)
    out = Path(a.json_out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(data, indent=2, ensure_ascii=True))
    na = data["npm_audit"]
    print(f"Packages: {len(data['packages'])} | scratch: {scratch}")
    print(f"npm audit: {'ran' if na.get('ran') else 'not run'} {na.get('counts') or ''} {na.get('reason') or ''}")
    print(f"OSV: {'ran' if data['osv'].get('ran') else 'not run'} "
          f"vulns={len(data['osv'].get('vulns', []))} {data['osv'].get('reason') or ''}")
    print(f"Deep audits: {len(data['deep_audits'])}")
    for f in data["findings"][:10]:
        print(f"  [{f['severity']}] {f['rule_id']} — {f['title']}")
    print(f"JSON written to {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
