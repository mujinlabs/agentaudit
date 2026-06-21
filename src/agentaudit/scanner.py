"""Filesystem walker + rule engine for agentaudit."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from .rules import RULES, SEVERITY_WEIGHT

# File-kind classification by extension / name.
CODE_EXT = {".py", ".js", ".mjs", ".cjs", ".ts", ".sh", ".bash", ".ps1", ".rb", ".go", ".php"}
DOC_EXT = {".md", ".markdown", ".txt", ".rst"}
MANIFEST_NAMES = {"mcp.json", "marketplace.json", "plugin.json", "manifest.json",
                  ".mcp.json", "config.json", "skill.json"}
MANIFEST_EXT = {".toml", ".yaml", ".yml"}

# Directories never worth scanning.
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build", ".mypy_cache"}

# Skip files larger than this (bytes) to stay fast; note them separately.
MAX_BYTES = 2_000_000


@dataclass(frozen=True)
class Finding:
    rule_id: str
    category: str
    severity: str
    message: str
    recommendation: str
    file: str
    line: int
    excerpt: str


def classify(path: Path) -> str:
    name = path.name.lower()
    if name in MANIFEST_NAMES or name == "skill.md" or name.endswith(".mcp.json"):
        return "manifest" if not name.endswith(".md") else "doc"
    ext = path.suffix.lower()
    if ext in CODE_EXT:
        return "code"
    if ext in DOC_EXT:
        return "doc"
    if ext in MANIFEST_EXT or name in MANIFEST_NAMES:
        return "manifest"
    return "other"


def _iter_files(root: Path):
    if root.is_file():
        yield root
        return
    for p in root.rglob("*"):
        if p.is_dir():
            continue
        if any(part in SKIP_DIRS for part in p.parts):
            continue
        yield p


def scan_text(kind: str, text: str, rel: str) -> list[Finding]:
    findings: list[Finding] = []
    lines = text.splitlines()
    for rule in RULES:
        if "any" not in rule.applies_to and kind not in rule.applies_to:
            continue
        for i, line in enumerate(lines, 1):
            if rule.pattern.search(line):
                excerpt = line.strip()
                if len(excerpt) > 200:
                    excerpt = excerpt[:197] + "..."
                findings.append(Finding(
                    rule.id, rule.category, rule.severity, rule.message,
                    rule.recommendation, rel, i, excerpt,
                ))
    return findings


@dataclass
class Report:
    target: str
    files_scanned: int
    findings: list[Finding]
    skipped: list[str]

    @property
    def score(self) -> int:
        penalty = sum(SEVERITY_WEIGHT.get(f.severity, 0) for f in self.findings)
        return max(0, 100 - penalty)

    @property
    def grade(self) -> str:
        s = self.score
        return ("A" if s >= 90 else "B" if s >= 75 else "C" if s >= 60
                else "D" if s >= 40 else "F")

    def counts(self) -> dict:
        out: dict = {}
        for f in self.findings:
            out[f.severity] = out.get(f.severity, 0) + 1
        return out

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "files_scanned": self.files_scanned,
            "score": self.score,
            "grade": self.grade,
            "counts": self.counts(),
            "findings": [f.__dict__ for f in self.findings],
            "skipped": self.skipped,
        }


def scan(target: str) -> Report:
    root = Path(target).expanduser()
    if not root.exists():
        raise FileNotFoundError(f"target not found: {target}")

    findings: list[Finding] = []
    skipped: list[str] = []
    scanned = 0
    for path in _iter_files(root):
        kind = classify(path)
        if kind == "other":
            continue
        try:
            if path.stat().st_size > MAX_BYTES:
                skipped.append(f"{path} (too large)")
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
        except (OSError, ValueError) as e:
            skipped.append(f"{path} ({e})")
            continue
        scanned += 1
        rel = str(path.relative_to(root)) if root.is_dir() else path.name
        findings.extend(scan_text(kind, text, rel))

    return Report(str(root), scanned, findings, skipped)
