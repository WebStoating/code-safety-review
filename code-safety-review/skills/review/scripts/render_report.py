#!/usr/bin/env python3
"""Render the draft Markdown report from scan.py / check_deps.py JSON output.

Usage: python3 -I render_report.py --scan scan.json [--deps deps.json] --out report.md [--repo-name NAME]
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from csr_lib import report  # noqa: E402

TEMPLATE = Path(__file__).resolve().parent.parent / "assets" / "report-template.md"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--scan", required=True)
    ap.add_argument("--deps")
    ap.add_argument("--out", required=True)
    ap.add_argument("--repo-name")
    a = ap.parse_args(argv)
    scan = json.loads(Path(a.scan).read_text())
    deps = json.loads(Path(a.deps).read_text()) if a.deps else None
    root = os.path.realpath(scan.get("root") or "/nonexistent")
    out = Path(a.out).expanduser()
    out_real = os.path.realpath(out.parent if not out.exists() else out)
    if out_real == root or out_real.startswith(root + os.sep):
        print("error: refusing to write report inside the reviewed repository", file=sys.stderr)
        return 2
    name = a.repo_name or Path(root).name
    md = report.render(scan, deps, TEMPLATE.read_text(encoding="utf-8"), name, datetime.now())
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(md, encoding="utf-8")
    verdict, reason = report.proposed_verdict(scan, deps)
    print(f"Proposed verdict: {verdict} — {reason}")
    print(f"Draft report written to {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
