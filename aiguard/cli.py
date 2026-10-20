"""Command-line interface: ``aiguard scan <path> [options]``."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .checks import scan_path
from .report import SEVERITY_ORDER, Finding, Severity, parse_severity, render_json, render_text

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_THRESHOLD = 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aiguard",
        description="Audit AI-generated Python code: hallucinated imports, "
        "dangerous calls, leaked secrets, weak error handling, unsafe "
        "network usage, AI tells, and risky dependencies.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="scan a file or directory")
    scan.add_argument("path", help="file or directory to scan")
    scan.add_argument(
        "--json",
        action="store_true",
        help="print machine-readable JSON instead of the text report",
    )
    scan.add_argument(
        "--fail-on",
        choices=SEVERITY_ORDER,
        default="high",
        help="exit 2 if any finding is at/above this severity (default: high)",
    )
    scan.add_argument(
        "--min-severity",
        choices=SEVERITY_ORDER,
        default="low",
        help="only report findings at/above this severity (default: low)",
    )
    scan.add_argument(
        "--exclude",
        action="append",
        default=[],
        metavar="PATTERN",
        help="glob pattern of paths to skip (repeatable), e.g. 'tests/*'",
    )
    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    target = Path(args.path)
    if not target.exists():
        print(f"aiguard: error: path does not exist: {args.path}", file=sys.stderr)
        return EXIT_ERROR

    try:
        findings = scan_path(target, exclude=args.exclude)
    except Exception as exc:  # noqa: BLE001 - surface as a clean runtime error
        print(f"aiguard: error: scan failed: {exc}", file=sys.stderr)
        return EXIT_ERROR

    min_sev = parse_severity(args.min_severity)
    fail_sev = parse_severity(args.fail_on)
    shown = [f for f in findings if f.severity >= min_sev]

    label = str(target)
    if args.json:
        print(render_json(shown, label))
    else:
        print(render_text(shown, label))

    worst: Severity = max((f.severity for f in findings), default=Severity.LOW)
    # Findings below --min-severity are hidden from the report but still
    # count toward the fail threshold: a hidden critical is still critical.
    _ = worst
    if any(f.severity >= fail_sev for f in findings):
        return EXIT_THRESHOLD
    return EXIT_OK


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
