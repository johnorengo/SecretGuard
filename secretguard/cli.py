"""SecretGuard command line interface."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .reporter import Colors, colorize, render_terminal_report, write_json_report
from .scanner import RepositoryScanner


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="secretguard",
        description="Scan source code repositories for accidentally exposed secrets.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"SecretGuard {__version__}",
    )

    subparsers = parser.add_subparsers(dest="command")
    scan_parser = subparsers.add_parser(
        "scan",
        help="Scan a directory for exposed secrets.",
    )
    scan_parser.add_argument("folder", help="Directory to scan.")
    scan_parser.add_argument(
        "--json",
        action="store_true",
        help="Export reports/security-report.json.",
    )
    scan_parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored terminal output.",
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command != "scan":
        parser.print_help()
        return 0

    use_color = not args.no_color
    print(colorize("SecretGuard is scanning your repository...", Colors.CYAN, use_color))

    try:
        scanner = RepositoryScanner()
        scan_result = scanner.scan(args.folder)
    except (FileNotFoundError, NotADirectoryError, PermissionError) as error:
        print(colorize(f"Error: {error}", Colors.RED, use_color), file=sys.stderr)
        return 2
    except Exception as error:  # pragma: no cover - last-resort CLI safety net
        print(colorize(f"Unexpected error: {error}", Colors.RED, use_color), file=sys.stderr)
        return 1

    print(render_terminal_report(scan_result, use_color=use_color))

    if args.json:
        report_path = write_json_report(scan_result, Path("reports"))
        print(colorize(f"JSON report written to {report_path}", Colors.GREEN, use_color))

    return 1 if scan_result.total_findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
