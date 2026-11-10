"""Network-side dependency checks: npm audit (in an isolated scratch copy), OSV.dev, npm registry and PyPI
metadata, tarball download + safe extraction + static scan. Nothing downloaded is ever executed."""
from __future__ import annotations

import json
import os
import re
import shutil
import stat
import subprocess
import tarfile
import urllib.request
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import quote

from .deps import Package

UA = "Python-urllib"  # generic client name: do not announce the review
NPM_REGISTRY = "https://registry.npmjs.org"
OSV_BATCH = "https://api.osv.dev/v1/querybatch"
OSV_VULN = "https://api.osv.dev/v1/vulns/"
MAX_EXTRACT_BYTES = 200_000_000
MAX_EXTRACT_MEMBERS = 20_000


class Runner:
    def which(self, name: str) -> Optional[str]:
        return shutil.which(name)

    def run(self, cmd: List[str], cwd: Path, env: Dict[str, str], timeout: int = 120) -> subprocess.CompletedProcess:
        return subprocess.run(cmd, cwd=str(cwd), env=env, capture_output=True, text=True, timeout=timeout,
                              stdin=subprocess.DEVNULL)


class Http:
    def _req(self, url: str, data: Optional[bytes] = None, ctype: Optional[str] = None):
        headers = {"User-Agent": UA, "Accept": "application/json"}
        if ctype:
            headers["Content-Type"] = ctype
        return urllib.request.Request(url, data=data, headers=headers)

    def get_json(self, url: str, timeout: int = 30) -> Any:
        with urllib.request.urlopen(self._req(url), timeout=timeout) as r:
            return json.loads(r.read().decode("utf-8"))

    def post_json(self, url: str, body: Any, timeout: int = 30) -> Any:
        req = self._req(url, json.dumps(body).encode(), "application/json")
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode("utf-8"))

    def download(self, url: str, dest: Path, max_bytes: int = 50_000_000) -> Path:
        dest.parent.mkdir(parents=True, exist_ok=True)
        total = 0
        with urllib.request.urlopen(self._req(url), timeout=60) as r, open(dest, "wb") as fh:
            while True:
                chunk = r.read(65536)
                if not chunk:
                    break
                total += len(chunk)
                if total > max_bytes:
                    raise ValueError(f"download exceeds {max_bytes} bytes")
                fh.write(chunk)
        return dest


# ------------------------------------------------------------------ npm env ----

def npm_env(scratch: Path) -> Dict[str, str]:
    scratch.mkdir(parents=True, exist_ok=True)
    rc = "registry=https://registry.npmjs.org/\n"
    (scratch / ".npmrc").write_text(rc)
    (scratch / "global.npmrc").write_text(rc)
    env = {k: v for k, v in os.environ.items() if not k.lower().startswith("npm_config_")
           and k not in ("NODE_OPTIONS",)}
    env.update({
        "NPM_CONFIG_USERCONFIG": str(scratch / ".npmrc"),
        "NPM_CONFIG_GLOBALCONFIG": str(scratch / "global.npmrc"),
        "NPM_CONFIG_IGNORE_SCRIPTS": "true",
        "NPM_CONFIG_AUDIT": "false",
        "NPM_CONFIG_FUND": "false",
        "NPM_CONFIG_UPDATE_NOTIFIER": "false",
        "NPM_CONFIG_CACHE": str(scratch / "npm-cache"),
        "NPM_CONFIG_REGISTRY": "https://registry.npmjs.org/",
        "NPM_CONFIG_ALLOW_GIT": "none",  # env beats any project .npmrc inside a cloned git dependency
    })
    return env


NPM_NAME = re.compile(r"^(@[a-z0-9][a-z0-9._~-]*/)?[a-zA-Z0-9][a-zA-Z0-9._~-]*$")
SEMVER = re.compile(r"^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$")


def is_network_error(e: BaseException) -> bool:
    import socket
    import urllib.error
    if isinstance(e, urllib.error.HTTPError):
        return False
    return isinstance(e, (urllib.error.URLError, socket.timeout, TimeoutError, ConnectionError))


def _safe_run(runner: Runner, cmd: List[str], cwd: Path, env: Dict[str, str], timeout: int):
    try:
        return runner.run(cmd, cwd, env, timeout=timeout), None
    except subprocess.TimeoutExpired:
        return None, f"`{' '.join(cmd[1:3])}` timed out after {timeout}s (network or proxy problem?)"
    except OSError as e:
        return None, f"`{' '.join(cmd[1:3])}` failed: {e}"


def _npm_version(runner: Runner, npm: str, scratch: Path, env: Dict[str, str]) -> tuple:
    try:
        r = runner.run([npm, "--version"], scratch, env, timeout=30)
        return tuple(int(x) for x in re.findall(r"\d+", r.stdout)[:3])
    except Exception:
        return (0, 0, 0)


# ---------------------------------------------------------------- npm audit ----

DEP_SECTIONS = ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies")


def _sanitize_manifest(pkg: dict, drop: set) -> dict:
    clean = {k: v for k, v in pkg.items() if k not in ("workspaces", "scripts", "bin", "files", "main",
                                                         "exports", "packageManager", "overrides", "resolutions")}
    clean["scripts"] = {}
    for s in DEP_SECTIONS:
        if isinstance(pkg.get(s), dict):
            clean[s] = {n: v for n, v in pkg[s].items() if n not in drop}
    return clean


def _registry_resolved(ent: Any) -> bool:
    res = (ent or {}).get("resolved") if isinstance(ent, dict) else None
    return res is None or str(res).startswith("https://registry.npmjs.org/")


def _sanitize_lock(lock: dict, drop: set) -> dict:
    pk = lock.get("packages")
    if isinstance(pk, dict):
        newpk = {}
        for key, ent in pk.items():
            name = key.rsplit("node_modules/", 1)[-1] if key else ""
            if key and (name in drop or not _registry_resolved(ent)):
                continue
            if not key and isinstance(ent, dict):
                ent = dict(ent)
                for s in DEP_SECTIONS:
                    if isinstance(ent.get(s), dict):
                        ent[s] = {n: v for n, v in ent[s].items() if n not in drop}
                ent.pop("workspaces", None)
            newpk[key] = ent
        lock = dict(lock, packages=newpk)
    if isinstance(lock.get("dependencies"), dict):
        lock = dict(lock, dependencies={n: v for n, v in lock["dependencies"].items()
                                        if n not in drop and _registry_resolved(v)})
    return lock


def _parse_audit(data: dict) -> Dict[str, Any]:
    counts = {"info": 0, "low": 0, "moderate": 0, "high": 0, "critical": 0}
    meta = (data.get("metadata") or {}).get("vulnerabilities") or {}
    for k in counts:
        counts[k] = int(meta.get(k, 0) or 0)
    advisories, seen = [], set()
    for name, v in (data.get("vulnerabilities") or {}).items():
        for via in v.get("via") or []:
            if not isinstance(via, dict):
                continue
            key = via.get("url") or f"{name}:{via.get('title')}"
            if key in seen:
                continue
            seen.add(key)
            title = via.get("title") or ""
            advisories.append({"name": via.get("name") or name, "severity": via.get("severity") or v.get("severity"),
                               "title": title, "url": via.get("url"), "range": via.get("range") or v.get("range"),
                               "malware": bool(re.search(r"malware|malicious", title, re.I))})
    for adv in (data.get("advisories") or {}).values():  # npm v6 format
        title = adv.get("title") or ""
        advisories.append({"name": adv.get("module_name"), "severity": adv.get("severity"), "title": title,
                           "url": adv.get("url"), "range": adv.get("vulnerable_versions"),
                           "malware": bool(re.search(r"malware|malicious", title, re.I))})
    order = {"critical": 0, "high": 1, "moderate": 2, "low": 3, "info": 4}
    advisories.sort(key=lambda a: order.get(str(a.get("severity")), 5))
    return {"counts": counts, "advisories": advisories}


def run_npm_audit(root: Path, pkgs: List[Package], runner: Runner, scratch: Path,
                  manifests: Optional[List[str]] = None) -> Dict[str, Any]:
    result: Dict[str, Any] = {"ran": False, "reason": None, "counts": {}, "advisories": [], "dirs": [],
                              "not_audited": []}
    npm = runner.which("npm")
    if not npm:
        result["reason"] = "npm not found"
        return result
    drop = {p.name for p in pkgs if p.ecosystem == "npm" and p.source in ("git", "url", "file", "private")}
    result["not_audited"] = sorted(drop)
    dirs = []
    for rel in manifests or ["package.json"]:
        if "node_modules/" in rel or not rel.endswith("package.json"):
            continue
        d = rel[: -len("package.json")].rstrip("/")
        if (root / d / "package.json").is_file() and (d == "" or (root / d / "package-lock.json").is_file()
                                                      or (root / d / "npm-shrinkwrap.json").is_file()):
            dirs.append(d)
    if not dirs:
        result["reason"] = "no package.json at the repository root"
        return result
    env = npm_env(scratch)
    ver = _npm_version(runner, npm, scratch, env)
    merged_counts = {"info": 0, "low": 0, "moderate": 0, "high": 0, "critical": 0}
    errors = []
    for d in dirs[:5]:
        work = scratch / "npm-audit" / (d.replace("/", "__") or "root")
        work.mkdir(parents=True, exist_ok=True)
        try:
            pkg = json.loads((root / d / "package.json").read_text(encoding="utf-8", errors="replace"))
        except ValueError as e:
            errors.append(f"{d or '.'}: package.json unparseable ({e})")
            continue
        (work / "package.json").write_text(json.dumps(_sanitize_manifest(pkg, drop), indent=2))
        lock_src = next((root / d / n for n in ("package-lock.json", "npm-shrinkwrap.json")
                         if (root / d / n).is_file()), None)
        if lock_src is not None:
            try:
                lock = json.loads(lock_src.read_text(encoding="utf-8", errors="replace"))
                (work / "package-lock.json").write_text(json.dumps(_sanitize_lock(lock, drop), indent=2))
            except ValueError:
                lock_src = None
        if lock_src is None:
            if ver < (11, 10, 0):
                errors.append(f"{d or '.'}: no package-lock.json; generating one safely needs npm >= 11.10 "
                              f"(--allow-git=none), found {'.'.join(map(str, ver)) or 'unknown'}")
                continue
            cmd = [npm, "install", "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund",
                   "--allow-git=none"]
            r, err = _safe_run(runner, cmd, work, env, 300)
            if err or r.returncode != 0 or not (work / "package-lock.json").exists():
                errors.append(f"{d or '.'}: lockfile generation failed: {err or (r.stderr or '')[-300:]}")
                if err:
                    break
                continue
        r, err = _safe_run(runner, [npm, "audit", "--json", "--package-lock-only"], work, env, 300)
        if err:
            errors.append(f"{d or '.'}: {err}")
            break
        try:
            data = json.loads(r.stdout or "")
        except ValueError:
            errors.append(f"{d or '.'}: npm audit output unparseable (exit {r.returncode}): {(r.stderr or '')[-300:]}")
            continue
        if "error" in data and not data.get("vulnerabilities") and not data.get("advisories"):
            errors.append(f"{d or '.'}: npm audit error: {json.dumps(data['error'])[:300]}")
            continue
        parsed = _parse_audit(data)
        for k, v in parsed["counts"].items():
            merged_counts[k] += v
        result["advisories"].extend(parsed["advisories"])
        result["dirs"].append(d or ".")
        result["ran"] = True
    result["counts"] = merged_counts
    if errors:
        result["reason"] = "; ".join(errors)
    return result


# --------------------------------------------------------------------- OSV ----

def osv_query(pkgs: List[Package], http: Http, max_details: int = 200) -> Dict[str, Any]:
    q = [p for p in pkgs if p.version and p.source == "registry"]
    out: Dict[str, Any] = {"ran": False, "reason": None, "vulns": [], "queried": len(q)}
    if not q:
        out["reason"] = "no pinned registry packages to query"
        return out
    vulns = []
    try:
        for i in range(0, len(q), 1000):
            chunk = q[i:i + 1000]
            body = {"queries": [{"package": {"name": p.name, "ecosystem": p.ecosystem}, "version": p.version}
                                for p in chunk]}
            res = http.post_json(OSV_BATCH, body)
            for p, r in zip(chunk, res.get("results") or []):
                for v in (r or {}).get("vulns") or []:
                    vulns.append({"ecosystem": p.ecosystem, "name": p.name, "version": p.version, "id": v.get("id"),
                                  "summary": None, "malicious": str(v.get("id", "")).startswith("MAL-")})
    except Exception as e:
        out["reason"] = f"OSV query failed: {type(e).__name__}: {e}"
        return out
    vulns.sort(key=lambda v: (not v["malicious"], v["name"]))
    for v in vulns[:max_details]:
        try:
            d = http.get_json(OSV_VULN + quote(v["id"]))
            v["summary"] = d.get("summary") or (d.get("details") or "")[:200]
        except Exception:
            pass
    out["ran"] = True
    out["vulns"] = vulns
    return out


# ------------------------------------------------------------ extraction ----

def safe_extract(archive: Path, dest: Path) -> None:
    """Extract tar/zip refusing absolute paths, '..', links and special files; size/member caps."""
    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=True)
    root = os.path.realpath(dest)
    total = 0

    def target(name: str) -> str:
        if name.startswith(("/", "\\")) or re.match(r"^[A-Za-z]:", name) or ".." in re.split(r"[/\\]", name):
            raise ValueError(f"unsafe path in archive: {name}")
        t = os.path.realpath(os.path.join(root, name))
        if not (t == root or t.startswith(root + os.sep)):
            raise ValueError(f"unsafe path in archive: {name}")
        return t

    name = str(archive)
    if zipfile.is_zipfile(name):
        with zipfile.ZipFile(name) as zf:
            infos = zf.infolist()
            if len(infos) > MAX_EXTRACT_MEMBERS:
                raise ValueError("too many archive members")
            for zi in infos:
                if stat.S_ISLNK(zi.external_attr >> 16):
                    raise ValueError(f"symlink in archive: {zi.filename}")
                t = target(zi.filename)
                if zi.is_dir():
                    os.makedirs(t, exist_ok=True)
                    continue
                total += zi.file_size
                if total > MAX_EXTRACT_BYTES:
                    raise ValueError("archive too large")
                os.makedirs(os.path.dirname(t), exist_ok=True)
                with zf.open(zi) as src, open(t, "wb") as dst:
                    shutil.copyfileobj(src, dst)
        return
    with tarfile.open(name, "r:*") as tf:
        members = tf.getmembers()
        if len(members) > MAX_EXTRACT_MEMBERS:
            raise ValueError("too many archive members")
        for m in members:
            if m.issym() or m.islnk():
                raise ValueError(f"link in archive: {m.name}")
            if not (m.isfile() or m.isdir()):
                raise ValueError(f"special file in archive: {m.name}")
            t = target(m.name)
            if m.isdir():
                os.makedirs(t, exist_ok=True)
                continue
            total += m.size
            if total > MAX_EXTRACT_BYTES:
                raise ValueError("archive too large")
            os.makedirs(os.path.dirname(t), exist_ok=True)
            src = tf.extractfile(m)
            if src is None:
                continue
            with src, open(t, "wb") as dst:
                shutil.copyfileobj(src, dst)


# ------------------------------------------------------------- deep audit ----

def _age_days(iso: Optional[str]) -> Optional[float]:
    if not iso:
        return None
    try:
        dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
    except ValueError:
        return None
    return (datetime.now(timezone.utc) - dt).total_seconds() / 86400


def npm_metadata(name: str, http: Http) -> Dict[str, Any]:
    doc = http.get_json(f"{NPM_REGISTRY}/{name.replace('/', '%2f')}")
    times = doc.get("time") or {}
    versions = doc.get("versions") or {}
    return {"created": times.get("created"), "modified": times.get("modified"), "versions_count": len(versions),
            "maintainers": [m.get("name") for m in doc.get("maintainers") or [] if isinstance(m, dict)],
            "latest": (doc.get("dist-tags") or {}).get("latest"), "repository": doc.get("repository"), "_doc": doc}


def _scan_dir(path: Path, max_bytes: int) -> List[dict]:
    from . import scanner
    res = scanner.run_scan(path, max_bytes=max_bytes, include_git=False)
    return [f.to_dict() for f in res.findings]


LIFECYCLE_KEYS = ("preinstall", "install", "postinstall", "prepare")


def deep_audit_npm(p: Package, runner: Runner, http: Http, scratch: Path, max_bytes: int) -> Dict[str, Any]:
    out: Dict[str, Any] = {"ecosystem": "npm", "name": p.name, "version": p.version, "metadata": {},
                           "red_flags": [], "scan_findings": [], "error": None}
    flags = out["red_flags"]
    if not NPM_NAME.match(p.name or "") or len(p.name) > 214:
        out["error"] = "invalid npm package name — not fetched"
        return out
    if p.version is not None and not SEMVER.match(p.version):
        out["error"] = f"version '{p.version}' is not a registry semver (git/URL/alias spec) — not fetched; review manually"
        return out
    try:
        meta = npm_metadata(p.name, http)
    except Exception as e:
        if is_network_error(e):
            out["error"] = f"network unavailable: {e}"
            out["network_error"] = True
        else:
            out["error"] = f"registry metadata unavailable: {e}"
            flags.append("not-on-public-registry")
        return out
    doc = meta.pop("_doc")
    ver = p.version or meta.get("latest")
    if not ver or not SEMVER.match(str(ver)):
        out["error"] = "no valid registry version"
        return out
    out["version"] = ver
    vers = doc.get("versions") or {}
    times = doc.get("time") or {}
    vdoc = vers.get(ver) or {}
    scripts = {k: v for k, v in (vdoc.get("scripts") or {}).items() if k in LIFECYCLE_KEYS}
    deps = vdoc.get("dependencies") or {}
    meta.update({"version_published": times.get(ver), "scripts": scripts, "dependencies_count": len(deps),
                 "dependencies": sorted(deps)[:50], "published_by": (vdoc.get("_npmUser") or {}).get("name")})
    out["metadata"] = meta
    age = _age_days(meta.get("created"))
    if age is not None and age < 30:
        flags.append("age<30d")
    vage = _age_days(meta.get("version_published"))
    if vage is not None and vage < 7:
        flags.append("version-age<7d")
    if meta.get("versions_count", 0) <= 3:
        flags.append("versions<=3")
    for k, v in scripts.items():
        flags.append(f"install-script:{k}={v}"[:200])
    if len(deps) >= 20:
        flags.append("deps>=20")
    if vers:
        first = min(vers, key=lambda v: times.get(v, "9999"))
        first_maint = {m.get("name") for m in (vers.get(first) or {}).get("maintainers") or [] if isinstance(m, dict)}
        pub = meta.get("published_by")
        if pub and first_maint and pub not in first_maint:
            flags.append(f"maintainer-changed:{pub}")
    # Download exactly what the registry serves (equivalent to `npm pack`, but without running npm,
    # which could resolve git specs and execute a cloned repo's config).
    dest = scratch / "pack" / re.sub(r"[^\w.-]", "_", f"{p.name}@{ver}")
    url = str((vdoc.get("dist") or {}).get("tarball") or "")
    from urllib.parse import urlparse
    u = urlparse(url)
    if u.scheme != "https" or u.hostname != "registry.npmjs.org":
        out["error"] = f"tarball URL not on registry.npmjs.org ({url[:120]}) — not fetched"
        return out
    try:
        tgz = http.download(url, dest / "pkg.tgz")
    except Exception as e:
        out["error"] = f"tarball download failed: {e}"
        out["network_error"] = is_network_error(e)
        return out
    extracted = dest / "extracted"
    try:
        safe_extract(tgz, extracted)
    except ValueError as e:
        flags.append(f"unsafe-tarball:{e}")
        return out
    out["tarball_dir"] = str(extracted)
    out["scan_findings"] = _scan_dir(extracted, max_bytes)
    rules = {f["rule_id"] for f in out["scan_findings"]}
    if "PAYLOAD-BINARY" in rules:
        flags.append("tarball-has-binary")
    if "PAYLOAD-SECRET-FILE" in rules:
        flags.append("tarball-has-env")
    return out


def deep_audit_pypi(p: Package, http: Http, scratch: Path, max_bytes: int) -> Dict[str, Any]:
    out: Dict[str, Any] = {"ecosystem": "PyPI", "name": p.name, "version": p.version, "metadata": {},
                           "red_flags": [], "scan_findings": [], "error": None}
    flags = out["red_flags"]
    try:
        doc = http.get_json(f"https://pypi.org/pypi/{quote(p.name)}/json")
    except Exception as e:
        out["error"] = f"PyPI metadata unavailable: {e}"
        if is_network_error(e):
            out["network_error"] = True
        else:
            flags.append("not-on-pypi")
        return out
    releases = doc.get("releases") or {}
    info = doc.get("info") or {}
    ver = p.version or info.get("version")
    out["version"] = ver
    uploads = [f.get("upload_time_iso_8601") for files in releases.values() for f in files or []
               if f.get("upload_time_iso_8601")]
    files = releases.get(ver) or doc.get("urls") or []
    out["metadata"] = {"created": min(uploads) if uploads else None, "versions_count": len(releases),
                       "author": info.get("author"), "maintainer": info.get("maintainer"),
                       "project_urls": info.get("project_urls"),
                       "version_published": min((f.get("upload_time_iso_8601") or "" for f in files), default=None)
                       or None}
    age = _age_days(out["metadata"]["created"])
    if age is not None and age < 30:
        flags.append("age<30d")
    vage = _age_days(out["metadata"]["version_published"])
    if vage is not None and vage < 7:
        flags.append("version-age<7d")
    if len(releases) <= 3:
        flags.append("versions<=3")
    pick = next((f for f in files if f.get("packagetype") == "sdist"), None) or (files[0] if files else None)
    if not pick:
        out["error"] = "no distribution files"
        return out
    dest = scratch / "pypi" / re.sub(r"[^\w.-]", "_", f"{p.name}-{ver}")
    try:
        arc = http.download(pick["url"], dest / re.sub(r"[^\w.-]", "_", pick.get("filename", "dist.bin")))
        safe_extract(arc, dest / "extracted")
    except Exception as e:
        out["error"] = f"download/extract failed: {e}"
        return out
    out["tarball_dir"] = str(dest / "extracted")
    out["scan_findings"] = _scan_dir(dest / "extracted", max_bytes)
    if any(f["severity"] in ("HIGH", "CRITICAL") for f in out["scan_findings"]):
        flags.append("scan:high")
    return out


def deep_audit_url(p: Package, http: Http, scratch: Path, max_bytes: int) -> Dict[str, Any]:
    out: Dict[str, Any] = {"ecosystem": p.ecosystem, "name": p.name, "version": p.version,
                           "metadata": {"resolved": p.resolved}, "red_flags": ["non-registry-source"],
                           "scan_findings": [], "error": None}
    # Deliberately not fetched: requesting an attacker-chosen URL reveals the review (and the reviewer's IP),
    # lets the server tailor a clean response, and can reach internal addresses.
    out["error"] = ("non-registry git/URL source — not fetched; review the source manually "
                    "(it bypasses registry malware scanning)")
    return out
