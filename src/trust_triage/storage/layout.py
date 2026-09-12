"""One path contract; SHA identifies content, analysis/run IDs identify executions."""

from __future__ import annotations

import re
from pathlib import Path

LAYOUT_VERSION = "sha256-artifacts-v1"
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_IDENTIFIER = re.compile(r"[A-Za-z0-9_-]{1,128}\Z")
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")


def validate_sha256(value: str) -> str:
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        raise ValueError("sha256 must contain 64 lowercase hexadecimal characters")
    return value


def validate_identifier(value: str) -> str:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise ValueError(
            "storage identifiers must contain 1-128 ASCII letters/digits/_/-"
        )
    return value


def sample_key(sha256: str) -> str:
    return f"{validate_sha256(sha256)}/sample.bin"


def artifact_key(
    sha256: str,
    analysis_id: str,
    tool: str,
    tool_run_id: str,
    name: str = "report.json",
) -> str:
    if not isinstance(name, str) or not _NAME.fullmatch(name) or ".." in name:
        raise ValueError("artifact name must be a single safe filename")
    return (
        f"{validate_sha256(sha256)}/analyses/{validate_identifier(analysis_id)}/"
        f"{validate_identifier(tool).lower()}/{validate_identifier(tool_run_id)}/{name}"
    )


def local_object_path(root: Path, key: str) -> Path:
    """Reject redirected parents as well as traversal before any object operation."""
    root = Path(root).resolve()
    parts = key.split("/")
    if any(part in {"", ".", ".."} or "\\" in part or ":" in part for part in parts):
        raise ValueError("unsafe object path")
    target = root.joinpath(*parts)
    for parent in (target, *target.parents):
        if parent == root:
            break
        if parent.is_symlink() or not parent.resolve().is_relative_to(root):
            raise ValueError("object path is redirected outside storage")
    return target
