"""Fail-closed containment adapter for high-confidence detections."""
from __future__ import annotations

import logging
import os
from typing import Any


def _containment_folders(quarantine_utils: Any) -> tuple[str, ...]:
    return (
        quarantine_utils.QUARANTINE_FOLDER,
        os.path.join(quarantine_utils.basedir, "failed_quarantine"),
        os.path.join(
            os.path.dirname(quarantine_utils.basedir), "failed_quarantine"
        ),
    )


def _matching_artifacts(folder: str, basename: str) -> list[str]:
    try:
        names = os.listdir(folder)
    except OSError:
        return []
    return [
        os.path.join(folder, name)
        for name in names
        if (
            name == basename
            or name == basename + ".enc"
            or name.startswith(basename + "_")
            or name.startswith(basename + ".")
        )
    ]


def _artifact_paths(filepath: str) -> list[str]:
    """Return possible containment artifacts for *filepath*."""
    try:
        import quarantine_utils
    except ImportError:
        return []

    basename = os.path.basename(filepath)
    candidates: list[str] = []
    for folder in _containment_folders(quarantine_utils):
        candidates.extend(_matching_artifacts(folder, basename))
    return list(dict.fromkeys(candidates))


def verify_containment(filepath: str) -> bool:
    """Require the source to be gone and a containment artifact to exist."""
    if os.path.lexists(filepath):
        return False
    return any(os.path.isfile(path) for path in _artifact_paths(filepath))


def contain_critical_file(
    filepath: str, reason: str = "critical YARA match"
) -> bool:
    """Contain a critical file and return an explicit success boolean."""
    if not filepath or not os.path.isfile(filepath):
        return False
    try:
        import quarantine_utils
        quarantine_utils.quarantine_file(filepath, reason=reason)
    except (OSError, RuntimeError, ValueError) as exc:
        logging.warning(
            "Critical containment operation failed for %s: %s", filepath, exc
        )
        return False
    return verify_containment(filepath)
