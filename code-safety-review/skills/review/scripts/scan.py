#!/usr/bin/env python3
"""Static malware / supply-chain / prompt-injection scan of an untrusted folder.

Usage: python3 -I scan.py <repo> [--json OUT] [--max-bytes N] [--no-git]

Never executes, imports, or installs anything from <repo>.
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from csr_lib import scanner  # noqa: E402
from csr_lib.model import Severity  # noqa: E402


def result_to_json(root: Path, res) -> dict:
    return {
        "tool": "code-safety-review/scan",
        "version": "1.0",
        "root": str(root),
        "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "findings": [f.to_dict() for f in res.findings],
        "inventory": res.inventory,
        "skipped": [{"path": s.rel, "reason": s.reason} for s in res.skipped],
        "errors": res.errors,
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("repo")
    ap.add_argument("--json", dest="json_out")
    ap.add_argument("--max-bytes", type=int, default=5_000_000)
    ap.add_argument("--no-git", action="store_true", help="skip .git config/hook/history checks")
    a = ap.parse_args(argv)

    root = Path(a.repo).expanduser()
    if not root.is_dir():
        print(f"error: {root} is not a directory", file=sys.stderr)
        return 1
    root = root.resolve()
    res = scanner.run_scan(root, a.max_bytes, include_git=not a.no_git)
    data = result_to_json(root, res)
    if a.json_out:
        out = Path(a.json_out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(data, indent=2, ensure_ascii=True))

    counts = {s.name: 0 for s in reversed(Severity)}
    for f in res.findings:
        counts[Severity(f.severity).name] += 1
    print(f"Scanned {res.inventory['files_scanned']} files in {root}")
    print("Findings: " + ", ".join(f"{k}={v}" for k, v in counts.items()))
    for f in data["findings"][:10]:
        loc = f"{f['file']}:{f['line']}" if f["line"] else f["file"]
        print(f"  [{f['severity']}] {f['rule_id']} {loc} — {f['title']}")
    if res.errors:
        print("Errors: " + "; ".join(res.errors))
    if a.json_out:
        print(f"JSON written to {a.json_out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
