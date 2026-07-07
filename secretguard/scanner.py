"""Repository scanner orchestration."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from .config import RISK_ORDER
from .detector import Finding, SecretDetector
from .utils import relative_path, safe_read_text, should_ignore_path


@dataclass(frozen=True)
class ScanResult:
    """Summary and findings produced by a scan."""

    scan_date: str
    target_directory: str
    files_scanned: int
    total_findings: int
    risk_level: str
    findings: list[Finding]

    def to_dict(self) -> dict[str, object]:
        return {
            "scan_date": self.scan_date,
            "target_directory": self.target_directory,
            "files_scanned": self.files_scanned,
            "total_findings": self.total_findings,
            "risk_level": self.risk_level,
            "findings": [finding.to_dict() for finding in self.findings],
        }


class RepositoryScanner:
    """Scan repositories recursively for exposed secrets."""

    def __init__(self, detector: SecretDetector | None = None) -> None:
        self.detector = detector or SecretDetector()

    def scan(self, directory: str | Path) -> ScanResult:
        target_directory = Path(directory).resolve()
        if not target_directory.exists():
            raise FileNotFoundError(f"Directory does not exist: {target_directory}")
        if not target_directory.is_dir():
            raise NotADirectoryError(f"Scan target is not a directory: {target_directory}")

        findings: list[Finding] = []
        files_scanned = 0

        for path in target_directory.rglob("*"):
            if should_ignore_path(path):
                continue
            if not path.is_file():
                continue

            content = safe_read_text(path)
            if content is None:
                continue

            files_scanned += 1
            display_path = relative_path(path, target_directory)
            findings.extend(self.detector.detect(content, display_path))

        return ScanResult(
            scan_date=datetime.now(timezone.utc).isoformat(),
            target_directory=str(target_directory),
            files_scanned=files_scanned,
            total_findings=len(findings),
            risk_level=calculate_risk_level(findings),
            findings=findings,
        )


def calculate_risk_level(findings: list[Finding]) -> str:
    """Calculate an overall status from finding severities."""
    if not findings:
        return "SECURE"

    highest_score = max(RISK_ORDER.get(finding.severity, 0) for finding in findings)
    if highest_score >= RISK_ORDER["CRITICAL"]:
        return "CRITICAL RISK"
    if highest_score >= RISK_ORDER["HIGH"]:
        return "HIGH RISK"
    if highest_score >= RISK_ORDER["MEDIUM"]:
        return "MEDIUM RISK"
    return "LOW RISK"
