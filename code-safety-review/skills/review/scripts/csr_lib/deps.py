"""Dependency inventory from manifests and lockfiles (never by installing), typosquat detection,
flagging for deep audit."""
from __future__ import annotations

import fnmatch
import json
import posixpath
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import urlparse

from .model import FileEntry

try:  # Python 3.11+
    import tomllib  # type: ignore
except ImportError:  # pragma: no cover
    tomllib = None

NPM_PUBLIC = {"registry.npmjs.org", "registry.yarnpkg.com", "registry.npmmirror.com"}
PYPI_PUBLIC = {"pypi.org", "files.pythonhosted.org", "pypi.python.org"}


@dataclass
class Package:
    ecosystem: str          # "npm" | "PyPI"
    name: str
    version: Optional[str]
    direct: bool
    source: str             # registry | private | git | url | file
    resolved: Optional[str]
    has_install_script: Optional[bool]
    manifest: str
    flags: List[str] = field(default_factory=list)


def load_list(path: Path) -> Set[str]:
    out = set()
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            out.add(line)
    return out


def pep503(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


# ------------------------------------------------------------ npm sources ----

def _npm_source(resolved: Optional[str], name: str, scope_regs: Dict[str, str], default_reg: Optional[str]) -> str:
    if resolved:
        r = resolved.strip()
        spec = _spec_source(r)
        if spec in ("git", "file"):
            return spec
        if r.endswith(".git") or ("#" in r and "git" in r):
            return "git"
        host = urlparse(r).hostname or ""
        if host in NPM_PUBLIC:
            return "registry"
        declared = {urlparse(u).hostname for u in list(scope_regs.values()) + [default_reg or ""] if u}
        if host and host in declared:
            return "private"  # host declared as a registry in the repo's own .npmrc/.yarnrc
        return "url"
    if name.startswith("@") and name.split("/")[0] in scope_regs:
        host = urlparse(scope_regs[name.split("/")[0]]).hostname or ""
        if host not in NPM_PUBLIC:
            return "private"
    if default_reg and (urlparse(default_reg).hostname or "") not in NPM_PUBLIC:
        return "private"
    return "registry"


def _spec_source(spec: str) -> Optional[str]:
    if re.match(r"^(git\+|git:|git@|ssh://|github:|gitlab:|bitbucket:|gist:)|^[\w.-]+/[\w.-]+(#.*)?$", spec):
        return "git"
    if spec.startswith(("http://", "https://")):
        return "url"
    if spec.startswith(("file:", "link:", "portal:", "workspace:")):
        return "file"
    return None


def _npmrc_registries(files: List[FileEntry]) -> Tuple[Dict[str, str], Optional[str]]:
    scopes: Dict[str, str] = {}
    default = None
    for fe in files:
        if fe.name in (".npmrc", ".yarnrc", ".yarnrc.yml") and "node_modules/" not in fe.rel and fe.text:
            for m in re.finditer(r"^\s*(@[\w.-]+):registry\s*=\s*(\S+)", fe.text, re.M):
                scopes[m.group(1)] = m.group(2)
            m = re.search(r"^\s*registry\s*=\s*(\S+)", fe.text, re.M)
            if m:
                default = m.group(1)
            for m in re.finditer(r"^\s*npmScopes:\s*$((?:\n\s+.*)+)", fe.text, re.M):
                for s in re.finditer(r"^\s+([\w.-]+):\s*\n\s+npmRegistryServer:\s*['\"]?(\S+?)['\"]?$", m.group(1), re.M):
                    scopes["@" + s.group(1)] = s.group(2)
    return scopes, default


# ----------------------------------------------------------- npm parsers ----

def _parse_package_json(fe: FileEntry) -> List[Tuple[str, str]]:
    try:
        pkg = json.loads(fe.text or "")
    except ValueError:
        return []
    out = []
    if not isinstance(pkg, dict):
        return out
    for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        d = pkg.get(section)
        if isinstance(d, dict):
            out.extend((k, str(v)) for k, v in d.items())
    return out


def _parse_package_lock(fe: FileEntry) -> List[dict]:
    try:
        data = json.loads(fe.text or "")
    except ValueError:
        return []
    out = []
    pk = data.get("packages")
    if isinstance(pk, dict):
        for key, ent in pk.items():
            # keys without node_modules/ are workspace folders of this repo, not registry packages
            if not key or "node_modules/" not in key or not isinstance(ent, dict) or ent.get("link"):
                continue
            name = ent.get("name") or key.rsplit("node_modules/", 1)[-1]
            ver = ent.get("version")
            resolved = ent.get("resolved")
            if isinstance(ver, str) and ver and not ver[0].isdigit():
                resolved = resolved or ver  # e.g. "github:user/repo" or "npm:other@1.0.0" used as a version
            out.append({"name": name, "version": ver, "resolved": resolved,
                        "install": bool(ent.get("hasInstallScript"))})
        return out

    def walk(deps):
        for name, ent in (deps or {}).items():
            if isinstance(ent, dict):
                out.append({"name": name, "version": ent.get("version"), "resolved": ent.get("resolved"),
                            "install": None})
                walk(ent.get("dependencies"))
    walk(data.get("dependencies"))
    return out


def _parse_yarn_lock(fe: FileEntry) -> List[dict]:
    out = []
    for block in re.split(r"\n\s*\n", fe.text or ""):
        lines = [ln for ln in block.splitlines() if ln.strip() and not ln.lstrip().startswith("#")]
        if not lines or lines[0].startswith((" ", "__metadata")):
            continue
        head = lines[0].rstrip(":").split(",")[0].strip().strip('"')
        m = re.match(r"^(@?[^@]+)@", head)
        if not m:
            continue
        name = m.group(1)
        ver = re.search(r'^\s+version:?\s+"?([^"\s]+)"?', block, re.M)
        res = re.search(r'^\s+(?:resolved|resolution):?\s+"?([^"\s]+)"?', block, re.M)
        resolved = res.group(1) if res else None
        if resolved and "@npm:" in resolved:
            resolved = None  # berry registry resolution
        out.append({"name": name, "version": ver.group(1) if ver else None, "resolved": resolved, "install": None})
    return out


PNPM_KEY = re.compile(r"""^  ['"]?/?((?:@[^/@\s'"]+/)?[^/@\s'"(]+)[@/](\d[^:'"(\s]*)(?:\([^)]*\))*['"]?:\s*(\{\})?\s*$""")


def _parse_pnpm_lock(fe: FileEntry) -> List[dict]:
    text = fe.text or ""
    m = re.search(r"^packages:\s*$", text, re.M)
    if not m:
        return []
    end = re.search(r"^\S", text[m.end() + 1:], re.M)
    body = text[m.end(): m.end() + 1 + end.start()] if end else text[m.end():]
    out = []
    cur = None
    for line in body.splitlines():
        km = PNPM_KEY.match(line)
        if km:
            cur = {"name": km.group(1), "version": km.group(2), "resolved": None, "install": False}
            out.append(cur)
        elif cur is not None:
            if re.match(r"^\s+requiresBuild:\s*true", line):
                cur["install"] = True
            t = re.search(r"tarball:\s*['\"]?([^,'\"}\s]+)", line)
            if t:
                cur["resolved"] = t.group(1)
    return out


# -------------------------------------------------------- python parsers ----

REQ_LINE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*(?:(===|==|~=|>=|<=|!=|>|<)\s*([^\s;,#]+))?")


def _parse_requirements(fe: FileEntry, by_rel: Dict[str, FileEntry], seen: Set[str]) -> Tuple[List[dict], bool]:
    """Returns (entries, private_index)."""
    if fe.rel in seen:
        return [], False
    seen.add(fe.rel)
    out, private = [], False
    for raw in (fe.text or "").splitlines():
        line = raw.split(" #", 1)[0].strip()
        if not line or line.startswith("#"):
            continue
        m = re.match(r"^(-r|--requirement|-c|--constraint)\s+(\S+)", line)
        if m:
            inc = posixpath.normpath(posixpath.join(posixpath.dirname(fe.rel), m.group(2)))
            if inc in by_rel and len(seen) < 20:
                sub, p = _parse_requirements(by_rel[inc], by_rel, seen)
                out.extend(sub)
                private = private or p
            continue
        m = re.match(r"^(--index-url|-i)[\s=]+(\S+)", line)
        if m:
            if (urlparse(m.group(2)).hostname or "") not in PYPI_PUBLIC:
                private = True
            continue
        if line.startswith("-e ") or re.match(r"^(git\+|https?://|file:)", line) or " @ " in line:
            nm = re.match(r"^(?:-e\s+)?([A-Za-z0-9._-]+)\s*@", line) or re.search(r"#egg=([A-Za-z0-9._-]+)", line)
            src = "git" if "git+" in line else ("file" if "file:" in line or line.startswith("-e .") else "url")
            out.append({"name": nm.group(1) if nm else line[:60], "version": None, "source": src,
                        "resolved": line})
            continue
        if line.startswith("-"):
            continue
        m = REQ_LINE.match(line)
        if m:
            ver = m.group(4) if m.group(3) in ("==", "===") else None
            out.append({"name": m.group(1), "version": ver, "source": None, "resolved": None})
    return out, private


def _toml(text: str) -> Optional[dict]:
    if tomllib is None:
        return None
    try:
        return tomllib.loads(text)
    except Exception:
        return None


def _parse_pyproject(fe: FileEntry) -> List[dict]:
    data = _toml(fe.text or "")
    specs: List[str] = []
    out = []
    if data:
        proj = data.get("project") or {}
        specs.extend(proj.get("dependencies") or [])
        for v in (proj.get("optional-dependencies") or {}).values():
            specs.extend(v or [])
        for grp in (data.get("dependency-groups") or {}).values():
            specs.extend(x for x in grp or [] if isinstance(x, str))
        poetry = ((data.get("tool") or {}).get("poetry") or {})
        for sect in [poetry.get("dependencies") or {}, poetry.get("dev-dependencies") or {}] + \
                [g.get("dependencies") or {} for g in (poetry.get("group") or {}).values() if isinstance(g, dict)]:
            for name, spec in sect.items():
                if name.lower() == "python":
                    continue
                if isinstance(spec, dict) and (spec.get("git") or spec.get("url") or spec.get("path")):
                    out.append({"name": name, "version": None,
                                "source": "git" if spec.get("git") else ("url" if spec.get("url") else "file"),
                                "resolved": spec.get("git") or spec.get("url") or spec.get("path")})
                else:
                    v = spec if isinstance(spec, str) else (spec.get("version") if isinstance(spec, dict) else None)
                    out.append({"name": name, "version": v.lstrip("=") if v and re.fullmatch(r"=?=?\d[\w.]*", v)
                                else None, "source": None, "resolved": None})
    else:
        m = re.search(r"^dependencies\s*=\s*\[(.*?)\]", fe.text or "", re.M | re.S)
        if m:
            specs.extend(re.findall(r"[\"']([^\"']+)[\"']", m.group(1)))
    for s in specs:
        if " @ " in s or "@ " in s:
            nm = s.split("@")[0].strip()
            out.append({"name": re.split(r"[\[\s;]", nm)[0], "version": None,
                        "source": "git" if "git+" in s else "url", "resolved": s})
            continue
        m = REQ_LINE.match(s)
        if m:
            out.append({"name": m.group(1), "version": m.group(4) if m.group(3) in ("==", "===") else None,
                        "source": None, "resolved": None})
    return out


def _parse_py_lock(fe: FileEntry) -> List[dict]:
    low = fe.name.lower()
    out = []
    if low == "pipfile.lock":
        try:
            data = json.loads(fe.text or "")
        except ValueError:
            return out
        for sect in ("default", "develop"):
            for name, ent in (data.get(sect) or {}).items():
                if not isinstance(ent, dict):
                    continue
                v = ent.get("version", "")
                src = "git" if ent.get("git") else ("file" if ent.get("path") else None)
                out.append({"name": name, "version": v.lstrip("=") or None, "source": src,
                            "resolved": ent.get("git") or ent.get("path")})
        return out
    data = _toml(fe.text or "")
    if data and isinstance(data.get("package"), list):
        for ent in data["package"]:
            src_t = ent.get("source") or {}
            src = None
            resolved = None
            if isinstance(src_t, dict):
                if src_t.get("git") or src_t.get("type") == "git":
                    src, resolved = "git", src_t.get("git") or src_t.get("url")
                elif src_t.get("path") or src_t.get("editable") or src_t.get("virtual") or src_t.get("directory"):
                    src = "file"
                elif src_t.get("url") and src_t.get("type") in (None, "url", "file"):
                    src, resolved = "url", src_t.get("url")
                elif src_t.get("registry") or (src_t.get("type") == "legacy" and src_t.get("url")):
                    reg = src_t.get("registry") or src_t.get("url")
                    if (urlparse(reg).hostname or "") not in PYPI_PUBLIC:
                        src, resolved = "private", reg
            out.append({"name": ent.get("name"), "version": ent.get("version"), "source": src, "resolved": resolved})
        return out
    for m in re.finditer(r'^\[\[package\]\]\s*\nname\s*=\s*"([^"]+)"\s*\nversion\s*=\s*"([^"]+)"', fe.text or "", re.M):
        out.append({"name": m.group(1), "version": m.group(2), "source": None, "resolved": None})
    return out


# ------------------------------------------------------------------ collect ----

def collect(root: Path, files: List[FileEntry]) -> List[Package]:
    by_rel = {f.rel: f for f in files}
    scope_regs, default_reg = _npmrc_registries(files)
    pkgs: Dict[Tuple[str, str, Optional[str]], Package] = {}
    direct_npm: Dict[str, str] = {}
    direct_py: Set[str] = set()

    def add(p: Package) -> None:
        key = (p.ecosystem, p.name if p.ecosystem == "npm" else pep503(p.name), p.version)
        cur = pkgs.get(key)
        if cur is None:
            pkgs[key] = p
            return
        cur.direct = cur.direct or p.direct
        if p.has_install_script:
            cur.has_install_script = True
        if cur.resolved is None and p.resolved:
            cur.resolved = p.resolved
            cur.source = p.source

    relevant = [f for f in files if f.text is not None and "node_modules/" not in f.rel
                and not f.rel.startswith(".git/")]
    for fe in relevant:
        if fe.name == "package.json":
            for name, spec in _parse_package_json(fe):
                direct_npm[name] = spec
    npm_locked: Set[str] = set()
    for fe in relevant:
        parser = {"package-lock.json": _parse_package_lock, "npm-shrinkwrap.json": _parse_package_lock,
                  "yarn.lock": _parse_yarn_lock, "pnpm-lock.yaml": _parse_pnpm_lock}.get(fe.name)
        if not parser:
            continue
        for e in parser(fe):
            if not e.get("name"):
                continue
            src = _npm_source(e["resolved"], e["name"], scope_regs, default_reg)
            npm_locked.add(e["name"])
            add(Package("npm", e["name"], e["version"], e["name"] in direct_npm, src, e["resolved"],
                        e["install"], fe.rel))
    for fe in relevant:
        if fe.name != "package.json":
            continue
        for name, spec in _parse_package_json(fe):
            if name in npm_locked:
                continue
            src = _spec_source(spec) or _npm_source(None, name, scope_regs, default_reg)
            exact = spec if re.fullmatch(r"\d+\.\d+\.\d+([-+][\w.]+)?", spec) else None
            add(Package("npm", name, exact, True, src, spec if src in ("git", "url", "file") else None, None, fe.rel))

    seen: Set[str] = set()
    py_entries: List[Tuple[dict, str, bool]] = []
    for fe in relevant:
        low = fe.name.lower()
        if re.match(r"(requirements|constraints).*\.(txt|in)$", low):
            ents, private = _parse_requirements(fe, by_rel, seen)
            py_entries.extend((e, fe.rel, private) for e in ents)
            direct_py.update(pep503(e["name"]) for e in ents)
        elif low == "pyproject.toml":
            ents = _parse_pyproject(fe)
            py_entries.extend((e, fe.rel, False) for e in ents)
            direct_py.update(pep503(e["name"]) for e in ents)
        elif low == "setup.py" or low == "setup.cfg":
            m = re.search(r"install_requires\s*=\s*\[(.*?)\]", fe.text or "", re.S) or \
                re.search(r"^install_requires\s*=\s*((?:\n\s+.+)+)", fe.text or "", re.M)
            if m:
                for s in re.findall(r"[\"']([^\"']+)[\"']", m.group(1)) or m.group(1).split():
                    rm = REQ_LINE.match(s)
                    if rm:
                        e = {"name": rm.group(1), "version": rm.group(4) if rm.group(3) == "==" else None,
                             "source": None, "resolved": None}
                        py_entries.append((e, fe.rel, False))
                        direct_py.add(pep503(e["name"]))
    for fe in relevant:
        if fe.name.lower() in ("pipfile.lock", "poetry.lock", "uv.lock", "pdm.lock"):
            for e in _parse_py_lock(fe):
                if e.get("name"):
                    py_entries.append((e, fe.rel, False))
    pinned = {pep503(e["name"]) for e, _, _ in py_entries if e.get("version")}
    for e, manifest, private in py_entries:
        n = pep503(e["name"])
        if not e.get("version") and n in pinned and not e.get("source"):
            continue  # an unpinned spec superseded by a locked/pinned version
        src = e.get("source") or ("private" if private else "registry")
        add(Package("PyPI", e["name"], e.get("version"), n in direct_py, src, e.get("resolved"), None, manifest))
    return sorted(pkgs.values(), key=lambda p: (p.ecosystem, p.name.lower(), p.version or ""))


# --------------------------------------------------------------- typosquat ----

HOMOGLYPHS = [("rn", "m"), ("vv", "w"), ("0", "o"), ("1", "l"), ("3", "e"), ("5", "s"), ("$", "s")]
AFFIXES_PRE = ["node-", "js-", "python-", "py-", "py", "the-"]
AFFIXES_SUF = ["-js", ".js", "js", "-node", "-utilz", "-py", "-python"]


def _norm(s: str) -> str:
    return re.sub(r"[-_.]", "", s.lower())


def _glyph(s: str) -> str:
    for a, b in HOMOGLYPHS:
        s = s.replace(a, b)
    return s


def _within1(a: str, b: str) -> bool:
    if a == b:
        return False
    la, lb = len(a), len(b)
    if abs(la - lb) > 1:
        return False
    if la == lb:
        diff = [i for i in range(la) if a[i] != b[i]]
        if len(diff) == 1:
            return True
        return len(diff) == 2 and diff[1] == diff[0] + 1 and a[diff[0]] == b[diff[1]] and a[diff[1]] == b[diff[0]]
    if la > lb:
        a, b = b, a
    i = 0
    while i < len(a) and a[i] == b[i]:
        i += 1
    return a[i:] == b[i + 1:]


def _dist_le2(a: str, b: str) -> bool:
    if abs(len(a) - len(b)) > 2:
        return False
    prev2, prev = None, list(range(len(b) + 1))
    for i in range(1, len(a) + 1):
        cur = [i] + [0] * len(b)
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            if prev2 is not None and i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                cur[j] = min(cur[j], prev2[j - 2] + 1)
        if min(cur) > 2:
            return False
        prev2, prev = prev, cur
    return prev[-1] <= 2


def typosquat_of(name: str, popular: Iterable[str]) -> Optional[str]:
    pop = set(popular)
    if name in pop or name.lower() in pop:
        return None
    if name.startswith("@"):
        scope = name.split("/")[0]
        if scope in pop:
            return None
        for p in pop:
            if p.startswith("@") and "/" not in p and (_norm(p) == _norm(scope) or _within1(_norm(scope), _norm(p))):
                return p
        return None
    n = _norm(name)
    names = [p for p in pop if not p.startswith("@")]
    norm_map = {}
    for p in names:
        norm_map.setdefault(_norm(p), p)
    if n in norm_map:
        return norm_map[n]
    g = _glyph(n)
    if g != n and g in norm_map:
        return norm_map[g]
    low = name.lower()
    for pre in AFFIXES_PRE:
        if low.startswith(pre) and _norm(low[len(pre):]) in norm_map and len(low) - len(pre) >= 4:
            return norm_map[_norm(low[len(pre):])]
    for suf in AFFIXES_SUF:
        if low.endswith(suf) and _norm(low[: -len(suf)]) in norm_map and len(low) - len(suf) >= 4:
            return norm_map[_norm(low[: -len(suf)])]
    if len(n) >= 5:
        for pn, p in norm_map.items():
            if len(pn) >= 5 and _within1(n, pn):
                return p
    if len(n) >= 9:
        for pn, p in norm_map.items():
            if len(pn) >= 9 and _dist_le2(n, pn):
                return p
    return None


# ------------------------------------------------------------------ flags ----

def _allowlisted(name: str, allow: Set[str]) -> bool:
    return any(fnmatch.fnmatchcase(name, a) for a in allow)


def flag_packages(pkgs: List[Package], allowlist: Set[str], popular_npm: Set[str], popular_pypi: Set[str]) -> None:
    pypi_norm = {pep503(p) for p in popular_pypi}
    for p in pkgs:
        flags = []
        if p.source == "private":
            flags.append("private")
        if p.source in ("git", "url", "file"):
            flags.append("non-registry")
        if p.has_install_script and p.ecosystem == "npm" and not _allowlisted(p.name, allowlist):
            flags.append("install-script")
        if p.source != "private":
            pop = popular_npm if p.ecosystem == "npm" else pypi_norm
            nm = p.name if p.ecosystem == "npm" else pep503(p.name)
            t = typosquat_of(nm, pop)
            if t:
                flags.append(f"typosquat:{t}")
        p.flags = flags


def needs_deep_audit(p: Package) -> bool:
    if "private" in p.flags or p.source == "file":
        return False
    return any(f != "private" for f in p.flags)
