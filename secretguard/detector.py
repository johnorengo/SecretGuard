"""Regex-based secret detection engine."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .config import RULES_PATH

GENERIC_RULE_NAMES = {"Environment Secret"}


@dataclass(frozen=True)
class DetectionRule:
    """A single secret detection rule."""

    name: str
    pattern: str
    severity: str
    recommendation: str


@dataclass(frozen=True)
class Finding:
    """A detected secret occurrence."""

    rule_name: str
    severity: str
    recommendation: str
    file_path: str
    line_number: int
    line_content: str
    matched_value: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_name": self.rule_name,
            "severity": self.severity,
            "recommendation": self.recommendation,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "line_content": self.line_content,
            "matched_value": mask_secret(self.matched_value),
        }


def mask_secret(value: str) -> str:
    """Mask a secret value while keeping enough context for remediation."""
    stripped = value.strip()
    if len(stripped) <= 8:
        return "*" * len(stripped)
    return f"{stripped[:4]}...{stripped[-4:]}"


class SecretDetector:
    """Detect secrets in text using externally configured regex rules."""

    def __init__(self, rules_path: Path | None = None) -> None:
        self.rules_path = rules_path or RULES_PATH
        self.rules = self._load_rules(self.rules_path)
        self._compiled_rules = [
            (rule, re.compile(rule.pattern, re.IGNORECASE)) for rule in self.rules
        ]

    def detect(self, content: str, file_path: str) -> list[Finding]:
        """Return all findings discovered in the provided file content."""
        findings: list[Finding] = []

        for line_number, line in enumerate(content.splitlines(), start=1):
            line_findings: list[Finding] = []
            for rule, compiled_pattern in self._compiled_rules:
                if line_findings and rule.name in GENERIC_RULE_NAMES:
                    continue
                for match in compiled_pattern.finditer(line):
                    matched_value = match.group(0)
                    line_findings.append(
                        Finding(
                            rule_name=rule.name,
                            severity=rule.severity,
                            recommendation=rule.recommendation,
                            file_path=file_path,
                            line_number=line_number,
                            line_content=line.strip(),
                            matched_value=matched_value,
                        )
                    )
            findings.extend(line_findings)

        return findings

    @staticmethod
    def _load_rules(rules_path: Path) -> list[DetectionRule]:
        if not rules_path.exists():
            raise FileNotFoundError(f"Detection rules file not found: {rules_path}")

        with rules_path.open("r", encoding="utf-8") as file_handle:
            raw_rules = json.load(file_handle)

        rules: list[DetectionRule] = []
        for name, metadata in raw_rules.items():
            rules.append(
                DetectionRule(
                    name=name,
                    pattern=metadata["pattern"],
                    severity=metadata["severity"].upper(),
                    recommendation=metadata["recommendation"],
                )
            )

        return rules
