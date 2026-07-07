"""Terminal and JSON report generation."""

from __future__ import annotations

import json
from pathlib import Path

from .config import DEFAULT_JSON_REPORT, DEFAULT_REPORTS_DIR
from .scanner import ScanResult


class Colors:
    """ANSI colors used for readable CLI output."""

    RESET = "\033[0m"
    BOLD = "\033[1m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    CYAN = "\033[36m"


def colorize(text: str, color: str, enabled: bool = True) -> str:
    if not enabled:
        return text
    return f"{color}{text}{Colors.RESET}"


def render_terminal_report(scan_result: ScanResult, use_color: bool = True) -> str:
    """Build a professional terminal report."""
    status_color = Colors.GREEN if scan_result.total_findings == 0 else Colors.RED
    lines = [
        "================================",
        colorize("SecretGuard Security Scan", Colors.BOLD + Colors.CYAN, use_color),
        "",
        f"Files scanned: {scan_result.files_scanned}",
        f"Secrets Found: {scan_result.total_findings}",
        f"Security Status: {colorize(scan_result.risk_level, status_color, use_color)}",
        "================================",
    ]

    if not scan_result.findings:
        lines.extend(["", colorize("No exposed secrets detected.", Colors.GREEN, use_color)])
        return "\n".join(lines)

    lines.append("")
    lines.append(colorize("Findings:", Colors.BOLD, use_color))

    for finding in scan_result.findings:
        severity_color = _severity_color(finding.severity)
        lines.extend(
            [
                "",
                colorize(f"[{finding.severity}]", severity_color, use_color),
                f"{finding.rule_name} Found",
                "",
                "File:",
                finding.file_path,
                "",
                "Line:",
                str(finding.line_number),
                "",
                "Recommendation:",
                finding.recommendation,
            ]
        )

    return "\n".join(lines)


def write_json_report(
    scan_result: ScanResult,
    reports_directory: Path | str = DEFAULT_REPORTS_DIR,
    filename: str = DEFAULT_JSON_REPORT,
) -> Path:
    """Write a JSON security report and return its path."""
    output_directory = Path(reports_directory)
    output_directory.mkdir(parents=True, exist_ok=True)
    report_path = output_directory / filename
    report_path.write_text(
        json.dumps(scan_result.to_dict(), indent=2),
        encoding="utf-8",
    )
    return report_path


def _severity_color(severity: str) -> str:
    return {
        "CRITICAL": Colors.RED + Colors.BOLD,
        "HIGH": Colors.RED,
        "MEDIUM": Colors.YELLOW,
        "LOW": Colors.CYAN,
    }.get(severity.upper(), Colors.CYAN)
