from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path
from typing import Dict, List, Optional


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


@dataclass
class Finding:
    rule_id: str
    severity: Severity
    file: str
    line: Optional[int]
    title: str
    snippet: str
    detail: str
    decoded: Optional[str] = None
    count: int = 1
    sha256: Optional[str] = None

    def to_dict(self) -> dict:
        from .decode import escape_invisible  # attacker-controlled text: never emit raw control/invisible chars
        esc = lambda s: escape_invisible(s) if isinstance(s, str) else s  # noqa: E731
        return {
            "rule_id": self.rule_id,
            "severity": Severity(self.severity).name,
            "file": esc(self.file),
            "line": self.line,
            "title": esc(self.title),
            "snippet": esc(self.snippet),
            "detail": esc(self.detail),
            "decoded": esc(self.decoded),
            "count": self.count,
            "sha256": self.sha256,
        }


@dataclass
class FileEntry:
    rel: str
    path: Path
    size: int
    data: bytes
    text: Optional[str]
    kind: str  # "text" | "binary"

    def sha256(self) -> str:
        """Hash of the full file on disk (text entries only keep a prefix of their bytes in memory)."""
        import hashlib
        h = hashlib.sha256()
        try:
            with open(self.path, "rb") as fh:
                for chunk in iter(lambda: fh.read(1 << 20), b""):
                    h.update(chunk)
        except OSError:
            h.update(self.data)
        return h.hexdigest()

    @property
    def name(self) -> str:
        return self.rel.rsplit("/", 1)[-1]

    @property
    def ext(self) -> str:
        n = self.name
        return ("." + n.rsplit(".", 1)[-1].lower()) if "." in n.lstrip(".") else ""


@dataclass
class Skipped:
    rel: str
    reason: str


def empty_inventory() -> dict:
    return {
        "files_scanned": 0,
        "bytes_scanned": 0,
        "languages": {},
        "manifests": [],
        "lockfiles": [],
        "instruction_files": [],
        "autorun_files": [],
        "entry_points": [],
    }


@dataclass
class ScanContext:
    root: Path
    files: List[FileEntry]
    by_rel: Dict[str, FileEntry]
    include_git: bool = True
    inventory: dict = field(default_factory=empty_inventory)
    errors: List[str] = field(default_factory=list)

    def note(self, key: str, rel: str) -> None:
        lst = self.inventory.setdefault(key, [])
        if rel not in lst:
            lst.append(rel)


@dataclass
class ScanResult:
    findings: List[Finding]
    inventory: dict
    skipped: List[Skipped]
    errors: List[str]
