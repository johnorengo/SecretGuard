"""Configuration constants for SecretGuard."""

from __future__ import annotations

from importlib.resources import files
from pathlib import Path

PACKAGE_ROOT = Path(__file__).resolve().parent
PROJECT_ROOT = PACKAGE_ROOT.parent
LOCAL_RULES_PATH = PROJECT_ROOT / "rules" / "patterns.json"
RULES_PATH = (
    LOCAL_RULES_PATH
    if LOCAL_RULES_PATH.exists()
    else Path(str(files("rules").joinpath("patterns.json")))
)
DEFAULT_REPORTS_DIR = PROJECT_ROOT / "reports"
DEFAULT_JSON_REPORT = "security-report.json"

IGNORED_DIRECTORIES = {
    ".git",
    "node_modules",
    "vendor",
    "__pycache__",
    "dist",
    "build",
}

IGNORED_DIRECTORY_PATHS = {
    ("storage", "framework", "views"),
    ("storage", "framework", "cache"),
    ("bootstrap", "cache"),
}

IGNORED_FILES = {
    ".env.example",
}

MAX_FILE_SIZE_BYTES = 2 * 1024 * 1024

RISK_ORDER = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}
