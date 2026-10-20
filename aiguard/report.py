"""Findings model and report rendering (human-readable text + JSON)."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from enum import IntEnum
from typing import List


class Severity(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.name.lower()


SEVERITY_ORDER = ["low", "medium", "high", "critical"]


def parse_severity(name: str) -> Severity:
    try:
        return Severity[name.strip().upper()]
    except KeyError:
        raise ValueError(f"unknown severity: {name!r} (expected one of {SEVERITY_ORDER})")


@dataclass
class Finding:
    check_id: str
    severity: Severity
    file: str
    line: int
    message: str
    snippet: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = str(self.severity)
        return d


def _severity_badge(severity: Severity) -> str:
    return {
        Severity.LOW: "[low]     ",
        Severity.MEDIUM: "[medium]  ",
        Severity.HIGH: "[high]    ",
        Severity.CRITICAL: "[critical]",
    }[severity]


def render_text(findings: List[Finding], target: str) -> str:
    """Render a grouped, human-readable report."""
    out: List[str] = []
    out.append(f"AIGuard scan: {target}")
    out.append("=" * 60)

    if not findings:
        out.append("")
        out.append("No findings. Ship it. 🚢")
        out.append("")
        return "\n".join(out)

    by_file: dict = {}
    for f in findings:
        by_file.setdefault(f.file, []).append(f)

    for filename in sorted(by_file):
        out.append("")
        out.append(f"--- {filename} ---")
        for f in sorted(by_file[filename], key=lambda x: (x.line, x.check_id)):
            loc = f"{f.file}:{f.line}" if f.line else f.file
            out.append(f"{_severity_badge(f.severity)} {f.check_id}  {loc}")
            out.append(f"           {f.message}")
            if f.snippet:
                out.append(f"           > {f.snippet}")

    out.append("")
    out.append("Summary")
    out.append("-" * 60)
    counts = {s: 0 for s in Severity}
    for f in findings:
        counts[f.severity] += 1
    total = len(findings)
    parts = [f"{str(s)}={counts[s]}" for s in Severity]
    out.append(f"{total} finding(s): " + ", ".join(parts))
    out.append("")
    return "\n".join(out)


def render_json(findings: List[Finding], target: str) -> str:
    """Render machine-readable JSON: findings list + summary counts."""
    counts = {str(s): 0 for s in Severity}
    for f in findings:
        counts[str(f.severity)] += 1
    payload = {
        "tool": "aiguard",
        "target": target,
        "summary": {"total": len(findings), "by_severity": counts},
        "findings": [f.to_dict() for f in findings],
    }
    return json.dumps(payload, indent=2)
