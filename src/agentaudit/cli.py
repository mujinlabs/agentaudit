"""Command-line interface for agentaudit."""

from __future__ import annotations

import argparse
import json
import sys

from . import __version__
from .scanner import scan, Report
from .sarif import to_sarif

# ANSI colors (auto-disabled when not a TTY or NO_COLOR set).
import os
_COLOR = sys.stdout.isatty() and not os.environ.get("NO_COLOR")


def _c(code: str, s: str) -> str:
    return f"\033[{code}m{s}\033[0m" if _COLOR else s


SEV_COLOR = {"critical": "1;31", "high": "31", "medium": "33", "low": "36", "info": "37"}
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _grade_color(grade: str) -> str:
    return {"A": "1;32", "B": "32", "C": "33", "D": "31", "F": "1;31"}.get(grade, "37")


def render(report: Report) -> str:
    out: list[str] = []
    findings = sorted(report.findings, key=lambda f: (SEV_ORDER.get(f.severity, 9), f.file, f.line))
    for f in findings:
        tag = _c(SEV_COLOR.get(f.severity, "37"), f"{f.severity.upper():8}")
        out.append(f"{tag} {_c('1', f.rule_id)} {f.category}")
        out.append(f"  {f.file}:{f.line}")
        out.append(f"  {f.message}")
        out.append(f"  {_c('2', '> ' + f.excerpt)}")
        out.append(f"  {_c('2', '→ ' + f.recommendation)}")
        out.append("")

    counts = report.counts()
    summary_bits = []
    for sev in ("critical", "high", "medium", "low"):
        if counts.get(sev):
            summary_bits.append(_c(SEV_COLOR[sev], f"{counts[sev]} {sev}"))
    summary = ", ".join(summary_bits) if summary_bits else _c("32", "no issues found")

    out.append(_c("1", "─" * 56))
    out.append(f"  Target : {report.target}")
    out.append(f"  Files  : {report.files_scanned} scanned"
               + (f", {len(report.skipped)} skipped" if report.skipped else ""))
    out.append(f"  Issues : {summary}")
    out.append(f"  Score  : {_c(_grade_color(report.grade), f'{report.score}/100  (grade {report.grade})')}")
    out.append(_c("1", "─" * 56))
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="agentaudit",
        description="Security & quality audit for AI-agent extensions "
                    "(Claude Code skills, MCP servers, plugins). Scan before you install.",
    )
    parser.add_argument("--version", action="version", version=f"agentaudit {__version__}")
    sub = parser.add_subparsers(dest="command")

    p_scan = sub.add_parser("scan", help="scan a directory or file")
    p_scan.add_argument("path", help="path to an extension directory or file")
    p_scan.add_argument("--format", choices=["text", "json", "sarif"], default="text",
                        help="output format (default: text). "
                             "sarif = GitHub code-scanning / PR annotations")
    p_scan.add_argument("--json", action="store_true",
                        help="deprecated alias for --format json")
    p_scan.add_argument("--fail-on", default="high",
                        choices=["critical", "high", "medium", "low", "none"],
                        help="minimum severity that causes a non-zero exit (default: high)")

    # Windows consoles default to a legacy codepage (cp932/cp1252) that cannot
    # encode our box-drawing/arrow glyphs. Force UTF-8 so output never crashes.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass

    args = parser.parse_args(argv)
    if args.command != "scan":
        parser.print_help()
        return 0

    try:
        report = scan(args.path)
    except FileNotFoundError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    fmt = "json" if args.json else args.format
    if fmt == "json":
        print(json.dumps(report.to_dict(), indent=2))
    elif fmt == "sarif":
        print(json.dumps(to_sarif(report), indent=2))
    else:
        print(render(report))

    if args.fail_on == "none":
        return 0
    threshold = SEV_ORDER[args.fail_on]
    worst = min((SEV_ORDER.get(f.severity, 9) for f in report.findings), default=9)
    return 1 if worst <= threshold else 0


if __name__ == "__main__":
    sys.exit(main())
