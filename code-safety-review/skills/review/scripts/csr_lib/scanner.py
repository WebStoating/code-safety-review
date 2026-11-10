"""Scan orchestration: walk the target, run every rule module, aggregate, sort."""
from __future__ import annotations

import importlib
from pathlib import Path
from typing import Dict, List, Tuple

from . import walker
from .model import Finding, ScanContext, ScanResult, Severity, empty_inventory

# Rule modules, each exposing check(ctx) -> list[Finding]. Imported lazily by name.
RULES: List[str] = [
    "rules_autorun",
    "rules_payload",
    "rules_node",
    "rules_python",
    "rules_injection",
    "rules_git",
]


def _load_rules() -> list:
    mods = []
    for name in RULES:
        try:
            mods.append(importlib.import_module(f"csr_lib.{name}"))
        except ModuleNotFoundError as e:
            if e.name == f"csr_lib.{name}":
                continue
            raise
    return mods


def aggregate(findings: List[Finding]) -> List[Finding]:
    groups: Dict[Tuple[str, str], List[Finding]] = {}
    order: List[Tuple[str, str]] = []
    for f in findings:
        key = (f.rule_id, f.file)
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append(f)
    out = []
    for key in order:
        grp = groups[key]
        best = max(grp, key=lambda f: (int(f.severity), -(f.line or 0)))
        top = [f for f in grp if f.severity == best.severity]
        rep = min(top, key=lambda f: (f.line or 0))
        rep.count = sum(f.count for f in grp)
        out.append(rep)
    return out


def sort_findings(findings: List[Finding]) -> List[Finding]:
    return sorted(findings, key=lambda f: (-int(f.severity), f.file, f.line or 0, f.rule_id))


def run_scan(root: Path, max_bytes: int = walker.DEFAULT_MAX_BYTES, include_git: bool = True) -> ScanResult:
    root = Path(root)
    files, skipped, findings = walker.walk(root, max_bytes)
    ctx = ScanContext(root=root, files=files, by_rel={f.rel: f for f in files},
                      include_git=include_git, inventory=empty_inventory())
    inv = ctx.inventory
    inv["files_scanned"] = len(files)
    inv["bytes_scanned"] = sum(f.size for f in files)
    langs: Dict[str, int] = {}
    for f in files:
        if f.rel.startswith(".git/"):
            continue
        langs[f.ext or "(none)"] = langs.get(f.ext or "(none)", 0) + 1
    inv["languages"] = dict(sorted(langs.items(), key=lambda kv: -kv[1]))

    for mod in _load_rules():
        try:
            findings.extend(mod.check(ctx))
        except Exception as e:  # a broken rule must not hide other results
            ctx.errors.append(f"{mod.__name__} failed: {type(e).__name__}: {e}")

    findings = aggregate(findings)
    for f in findings:
        if f.sha256 is None and f.severity >= Severity.HIGH and f.file in ctx.by_rel:
            f.sha256 = ctx.by_rel[f.file].sha256()
    return ScanResult(sort_findings(findings), inv, skipped, ctx.errors)
