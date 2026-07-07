"""Shared utility helpers."""

from __future__ import annotations

from pathlib import Path

from .config import (
    IGNORED_DIRECTORIES,
    IGNORED_DIRECTORY_PATHS,
    IGNORED_FILES,
    MAX_FILE_SIZE_BYTES,
)


def should_ignore_path(path: Path) -> bool:
    """Return True when a path should be skipped during repository scanning."""
    normalized_parts = tuple(part.lower() for part in path.parts)
    parts = set(normalized_parts)
    if parts.intersection(IGNORED_DIRECTORIES):
        return True
    if _contains_path_sequence(normalized_parts, IGNORED_DIRECTORY_PATHS):
        return True
    return path.name in IGNORED_FILES


def _contains_path_sequence(
    path_parts: tuple[str, ...],
    ignored_paths: set[tuple[str, ...]],
) -> bool:
    for ignored_path in ignored_paths:
        ignored_length = len(ignored_path)
        for index in range(len(path_parts) - ignored_length + 1):
            if path_parts[index : index + ignored_length] == ignored_path:
                return True
    return False


def is_probably_text_file(path: Path) -> bool:
    """Best-effort check to avoid reading binaries and very large files."""
    try:
        if path.stat().st_size > MAX_FILE_SIZE_BYTES:
            return False
        with path.open("rb") as file_handle:
            chunk = file_handle.read(1024)
    except OSError:
        return False

    return b"\x00" not in chunk


def safe_read_text(path: Path) -> str | None:
    """Read a text file without failing the full scan on encoding issues."""
    if not is_probably_text_file(path):
        return None

    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        try:
            return path.read_text(encoding="latin-1")
        except OSError:
            return None
    except OSError:
        return None


def relative_path(path: Path, base_directory: Path) -> str:
    """Return a stable user-facing relative path."""
    try:
        return str(path.relative_to(base_directory))
    except ValueError:
        return str(path)
