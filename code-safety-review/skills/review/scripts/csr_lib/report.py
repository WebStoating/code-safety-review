"""Render scan.json (+ deps.json) into the Markdown report draft the agent completes."""
from __future__ import annotations

import re
from datetime import datetime
from typing import Dict, List, Optional, Tuple

from .decode import escape_invisible
from .patterns import IPV4, URL

SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
RANK = {s: i for i, s in enumerate(SEV_ORDER)}
IOC_EXCLUDE = re.compile(r"(^|\.)(example\.(com|org|net)|registry\.npmjs\.org|registry\.yarnpkg\.com|npmjs\.com|"
                         r"github\.com|githubusercontent\.com|pypi\.org|pythonhosted\.org|localhost|w3\.org|"
                         r"schemas?\.\w+\.\w+|json-schema\.org|nodejs\.org|python\.org|microsoft\.com|"
                         r"visualstudio\.com|osv\.dev|mozilla\.org|apache\.org|opensource\.org)$", re.I)
OTHER_LANGS = {".go": "Go", ".rs": "Rust", ".rb": "Ruby", ".java": "Java", ".kt": "Kotlin", ".php": "PHP",
               ".cs": "C#", ".swift": "Swift", ".scala": "Scala", ".ex": "Elixir", ".dart": "Dart", ".c": "C",
               ".cpp": "C++", ".lua": "Lua", ".pl": "Perl"}
LIMITATIONS = [
    "Static analysis only: nothing from the repository or its dependencies was executed. Novel or heavily "
    "obfuscated payloads can evade pattern rules — that is why the agent reads every auto-run entry point.",
    "Prompt-injection resistance is instruction-level: the reviewing agent was told to treat repository text as "
    "data. For high-risk repos, run the review in a session without secrets loaded or inside a container.",
    "Known-vulnerability and malware databases (npm audit, OSV) only know what has been reported.",
    "`npm audit signatures` was not run: it verifies an installed node_modules tree, which this skill never creates.",
]


def md_text(s: Optional[str]) -> str:
    """Make untrusted text safe for Markdown prose: no HTML, no images/links, invisible chars shown."""
    s = escape_invisible(s or "")
    s = s.replace("<", "&lt;").replace(">", "&gt;").replace("![", "!\\[").replace("](", "]\\(")
    return s.replace("\n", " ")


def fence(s: Optional[str], lang: str = "text") -> str:
    s = escape_invisible(s or "")
    longest = max((len(r) for r in re.findall(r"`+", s)), default=0)
    tick = "`" * max(3, longest + 1)  # content can never close the fence
    return f"{tick}{lang}\n{s}\n{tick}"


def extract_iocs(findings: List[dict]) -> Dict[str, list]:
    urls, domains, ips, files = [], [], [], []
    for f in findings:
        blob = " ".join(str(f.get(k) or "") for k in ("snippet", "detail", "decoded"))
        for m in URL.finditer(blob):
            u = m.group(0).rstrip(".,;'\"")
            host = re.sub(r"^[a-z]+://", "", u, flags=re.I).split("/")[0].split(":")[0].split("?")[0].lower()
            if not host or IOC_EXCLUDE.search(host):
                continue
            if u not in urls:
                urls.append(u)
            if not IPV4.fullmatch(host) and host not in domains:
                domains.append(host)
        for m in IPV4.finditer(blob):
            ip = m.group(0)
            if ip.startswith(("127.", "0.", "255.")) or ip in ips or re.match(r"^\d+\.\d+\.\d+\.\d+$", ip) is None:
                continue
            parts = [int(x) for x in ip.split(".")]
            if parts[0] < 1 or all(p < 10 for p in parts):  # version-number lookalikes like 1.2.3.4
                continue
            ips.append(ip)
        if f.get("sha256") and f.get("severity") in ("CRITICAL", "HIGH"):
            ent = {"path": f.get("file"), "sha256": f["sha256"]}
            if ent not in files:
                files.append(ent)
    return {"urls": urls[:100], "domains": domains[:100], "ips": ips[:100], "files": files[:100]}


def _all_findings(scan: dict, deps: Optional[dict]) -> List[dict]:
    fs = list(scan.get("findings") or [])
    if deps:
        fs += list(deps.get("findings") or [])
    return sorted(fs, key=lambda f: (RANK.get(f["severity"], 9), f.get("file") or "", f.get("line") or 0))


def proposed_verdict(scan: dict, deps: Optional[dict]) -> Tuple[str, str]:
    fs = _all_findings(scan, deps)
    top = fs[0] if fs else None
    if top and top["severity"] == "CRITICAL":
        return "MALICIOUS", f"{top['rule_id']} in `{top['file']}` — {md_text(top['title'])}"
    if top and top["severity"] == "HIGH":
        return "SUSPICIOUS", f"{top['rule_id']} in `{top['file']}` — {md_text(top['title'])}"
    return "NO INDICATORS FOUND", "no finding above MEDIUM within the coverage listed in section 8"


def _loc(f: dict) -> str:
    return f"{f.get('file')}:{f['line']}" if f.get("line") else str(f.get("file"))


def _findings_md(fs: List[dict]) -> str:
    major = [f for f in fs if RANK.get(f["severity"], 9) <= RANK["MEDIUM"]]
    minor = [f for f in fs if RANK.get(f["severity"], 9) > RANK["MEDIUM"]]
    out = []
    for i, f in enumerate(major, 1):
        out.append(f"### F{i}. [{f['severity']}] {f['rule_id']} — `{md_text(_loc(f))}`")
        out.append(f"**{md_text(f.get('title'))}**")
        out.append(fence(f.get("snippet")))
        out.append(md_text(f.get("detail")))
        extra = []
        if f.get("count", 1) > 1:
            extra.append(f"occurrences in file: {f['count']}")
        if f.get("decoded"):
            extra.append("decoded content: see section 4")
        if f.get("sha256"):
            extra.append(f"SHA-256 `{f['sha256']}`")
        if extra:
            out.append("- " + "\n- ".join(extra))
        out.append("**Assessment:** _pending agent review_\n")
    if not major:
        out.append("No findings at MEDIUM or above.\n")
    if minor:
        out.append(f"#### Low / informational ({len(minor)})\n")
        out.append("| Severity | Rule | Location | Title |\n|---|---|---|---|")
        for f in minor[:200]:
            out.append(f"| {f['severity']} | {f['rule_id']} | `{md_text(_loc(f))}` | {md_text(f.get('title'))} |")
        if len(minor) > 200:
            out.append(f"\n_{len(minor) - 200} more low/informational findings omitted; see the JSON output._")
    return "\n".join(out)


def _decoded_md(fs: List[dict]) -> str:
    out = []
    for f in fs:
        if f.get("decoded"):
            out.append(f"#### {f['rule_id']} — `{md_text(_loc(f))}`")
            out.append(fence(str(f["decoded"])[:2000]))
    return "\n".join(out) or "No encoded content was decoded."


def _deps_md(deps: Optional[dict], scan: dict) -> str:
    if not deps:
        return "Dependency checks were not run (no `check_deps.py` output was provided)."
    pk = deps.get("packages") or []
    out = [f"Packages inventoried: **{len(pk)}** (npm {sum(p['ecosystem'] == 'npm' for p in pk)}, "
           f"PyPI {sum(p['ecosystem'] == 'PyPI' for p in pk)}; direct {sum(bool(p.get('direct')) for p in pk)}).", ""]
    life = [f for f in scan.get("findings") or [] if f["rule_id"] == "NODE-LIFECYCLE-SCRIPT"]
    inst = [p for p in pk if "install-script" in (p.get("flags") or [])]
    out.append("**Install / lifecycle scripts**")
    if life or inst:
        out.append("| Where | Script / package | Severity |\n|---|---|---|")
        for f in life:
            out.append(f"| `{md_text(_loc(f))}` | `{md_text(f.get('snippet'))}` | {f['severity']} |")
        for p in inst:
            out.append(f"| dependency | `{md_text(p['name'])}@{md_text(p.get('version') or '*')}` | see DEP-INSTALL-SCRIPT |")
    else:
        out.append("None found.")
    nonreg = [p for p in pk if p.get("source") in ("git", "url")]
    typo = [(p, fl) for p in pk for fl in p.get("flags") or [] if fl.startswith("typosquat:")]
    out.append("\n**Non-registry sources**")
    out.append("\n".join(f"- `{md_text(p['name'])}` from {p['source']}: `{md_text(str(p.get('resolved'))[:150])}`"
                         for p in nonreg) or "None.")
    out.append("\n**Typosquat candidates**")
    out.append("\n".join(f"- `{md_text(p['name'])}` resembles `{fl.split(':', 1)[1]}`" for p, fl in typo) or "None.")
    out.append("\n**Deep audits (published tarball / sdist inspected, never installed)**")
    da = deps.get("deep_audits") or []
    if da:
        out.append("| Package | Red flags | Worst scan finding | Note |\n|---|---|---|---|")
        for d in da:
            worst = min((f["severity"] for f in d.get("scan_findings") or []), key=lambda s: RANK.get(s, 9),
                        default="—")
            out.append(f"| `{md_text(d['name'])}@{md_text(str(d.get('version')))}` | "
                       f"{md_text(', '.join(d.get('red_flags') or [])) or '—'} | {worst} | "
                       f"{md_text(d.get('error') or d.get('tarball_dir') or '')} |")
    else:
        out.append("No package needed a deep audit.")
    na = deps.get("npm_audit") or {}
    out.append("\n**npm audit** (known vulnerabilities, separate from the malware verdict)")
    if na.get("ran"):
        c = na.get("counts") or {}
        out.append(", ".join(f"{k}: {c.get(k, 0)}" for k in ("critical", "high", "moderate", "low", "info")))
        adv = na.get("advisories") or []
        if adv:
            out.append("\n| Package | Severity | Advisory | Range |\n|---|---|---|---|")
            for a in adv[:20]:
                out.append(f"| `{md_text(a.get('name'))}` | {a.get('severity')} | {md_text(a.get('title'))} "
                           f"({md_text(a.get('url') or '')}) | `{md_text(a.get('range') or '')}` |")
            if len(adv) > 20:
                out.append(f"\n_{len(adv) - 20} more advisories in the JSON output._")
    if na.get("reason"):
        out.append(f"\nnpm audit note: {md_text(na.get('reason'))}")
    osv = deps.get("osv") or {}
    out.append("\n**OSV.dev** (includes `MAL-` malicious-package records)")
    if osv.get("ran"):
        vs = osv.get("vulns") or []
        out.append(f"{len(vs)} records for {osv.get('queried', '?')} pinned packages.")
        if vs:
            out.append("\n| Package | ID | Malicious | Summary |\n|---|---|---|---|")
            for v in vs[:50]:
                out.append(f"| `{md_text(v['name'])}@{md_text(str(v.get('version')))}` ({v['ecosystem']}) | {v['id']} | "
                           f"{'**YES**' if v.get('malicious') else 'no'} | {md_text(v.get('summary') or '')} |")
    if osv.get("reason"):
        out.append(f"\nOSV note: {md_text(osv.get('reason'))}")
    return "\n".join(out)


def _pi_md(scan: dict, fs: List[dict]) -> str:
    inv = (scan.get("inventory") or {}).get("instruction_files") or []
    pi = [f for f in fs if f["rule_id"].startswith("PI-")]
    out = ["Agent instruction files found: " + (", ".join(f"`{md_text(x)}`" for x in inv) or "none") + ".", ""]
    if pi:
        out.append("| Severity | Rule | Location | What | Hidden/decoded text |\n|---|---|---|---|---|")
        for f in pi:
            out.append(f"| {f['severity']} | {f['rule_id']} | `{md_text(_loc(f))}` | {md_text(f.get('title'))} | "
                       f"{('`' + md_text(str(f.get('decoded'))[:200]) + '`') if f.get('decoded') else ''} |")
        out.append("\nThese are instructions aimed at AI agents. They were reported, not followed.")
    else:
        out.append("No prompt-injection indicators found.")
    return "\n".join(out)


def _iocs_md(fs: List[dict], deps: Optional[dict]) -> str:
    pool = list(fs)
    for d in (deps or {}).get("deep_audits") or []:
        pool += d.get("scan_findings") or []
    i = extract_iocs([f for f in pool if f.get("severity") in ("CRITICAL", "HIGH", "MEDIUM")])
    if not any(i.values()):
        return "No network indicators extracted from findings at MEDIUM or above."
    lines = []
    for k in ("domains", "ips", "urls"):
        if i[k]:
            lines.append(f"{k}:")
            lines.extend(f"  {x}" for x in i[k])
    for f in i["files"]:
        lines.append(f"file: {f['path']}  sha256={f['sha256']}")
    return "Shown as plain text on purpose — do not visit these.\n\n" + fence("\n".join(lines))


def _coverage_md(scan: dict, deps: Optional[dict]) -> str:
    inv = scan.get("inventory") or {}
    out = [f"- Files scanned: {inv.get('files_scanned', 0)} ({inv.get('bytes_scanned', 0):,} bytes)."]
    sk = scan.get("skipped") or []
    if sk:
        out.append(f"- Skipped: {len(sk)} — " + "; ".join(f"`{md_text(s['path'])}` ({md_text(s['reason'])})"
                                                          for s in sk[:30]) + (" …" if len(sk) > 30 else ""))
    for e in scan.get("errors") or []:
        out.append(f"- Scan note: {md_text(e)}")
    langs = inv.get("languages") or {}
    other = sorted({OTHER_LANGS[e] for e in langs if e in OTHER_LANGS})
    if other:
        out.append(f"- Not covered by dependency checks (code still pattern-scanned): {', '.join(other)}.")
    for k in ("manifests", "lockfiles", "autorun_files", "entry_points"):
        if inv.get(k):
            out.append(f"- {k.replace('_', ' ').capitalize()}: " + ", ".join(f"`{md_text(x)}`" for x in inv[k][:40]))
    if deps:
        for x in (deps.get("coverage") or {}).get("not_audited") or []:
            out.append(f"- Not audited: `{md_text(x['name'])}` — {md_text(x['reason'])}")
        for n in (deps.get("coverage") or {}).get("notes") or []:
            out.append(f"- {md_text(n)}")
    else:
        out.append("- Dependency checks not run.")
    out.append("\n**Limitations**")
    out.extend(f"- {x}" for x in LIMITATIONS)
    out.append("\n_Manual verification list: pending agent review_")
    return "\n".join(out)


def render(scan: dict, deps: Optional[dict], template: str, repo_name: str, now: datetime) -> str:
    fs = _all_findings(scan, deps)
    verdict, reason = proposed_verdict(scan, deps)
    counts = {s: 0 for s in SEV_ORDER}
    for f in fs:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    top = [f for f in fs if f["severity"] in ("CRITICAL", "HIGH")][:3]
    repl = {
        "{{REPO}}": md_text(repo_name),
        "{{DATE}}": now.strftime("%Y-%m-%d %H:%M"),
        "{{ROOT}}": md_text(scan.get("root")),
        "{{PROPOSED_VERDICT}}": f"**{verdict}** — {reason}",
        "{{AGENT_VERDICT}}": "_pending agent review_",
        "{{SEVERITY_COUNTS}}": "| " + " | ".join(SEV_ORDER) + " |\n|" + "---|" * len(SEV_ORDER) + "\n| "
                               + " | ".join(str(counts[s]) for s in SEV_ORDER) + " |",
        "{{TOP_FINDINGS}}": "\n".join(f"- [{f['severity']}] {f['rule_id']} `{md_text(_loc(f))}` — "
                                      f"{md_text(f.get('title'))}" for f in top) or "- No HIGH or CRITICAL findings.",
        "{{FINDINGS}}": _findings_md(fs),
        "{{DECODED}}": _decoded_md(fs + [f for d in (deps or {}).get("deep_audits") or []
                                         for f in d.get("scan_findings") or []]),
        "{{DEPENDENCIES}}": _deps_md(deps, scan),
        "{{PROMPT_INJECTION}}": _pi_md(scan, fs),
        "{{IOCS}}": _iocs_md(fs, deps),
        "{{COVERAGE}}": _coverage_md(scan, deps),
    }
    out = template
    for k, v in repl.items():
        out = out.replace(k, v)
    return escape_invisible(out)
