"""Verified quarantine entry point shared by security scanners."""
from __future__ import annotations

import logging
import os
from typing import Iterable


def _folders(quarantine_utils) -> Iterable[str]:
    return (
        quarantine_utils.QUARANTINE_FOLDER,
        os.path.join(quarantine_utils.basedir, "failed_quarantine"),
        os.path.join(
            os.path.dirname(quarantine_utils.basedir), "failed_quarantine"
        ),
    )


def _artifacts(filepath: str) -> list[str]:
    try:
        import quarantine_utils
    except ImportError:
        return []

    basename = os.path.basename(filepath)
    result: list[str] = []
    for folder in _folders(quarantine_utils):
        try:
            names = os.listdir(folder)
        except OSError:
            continue
        result.extend(
            os.path.join(folder, name)
            for name in names
            if (
                name == basename
                or name == basename + ".enc"
                or name.startswith(basename + "_")
                or name.startswith(basename + ".")
            )
        )
    return list(dict.fromkeys(result))


def verify(filepath: str) -> bool:
    """Return true only after the source disappears and an artifact exists."""
    if os.path.lexists(filepath):
        return False
    return any(os.path.isfile(path) for path in _artifacts(filepath))


def quarantine_and_verify(filepath: str, *, reason: str = "") -> bool:
    """Contain a file and fail closed if containment cannot be verified."""
    if not filepath or not os.path.isfile(filepath):
        return False
    try:
        import quarantine_utils
        quarantine_utils.quarantine_file(filepath, reason=reason)
    except (OSError, RuntimeError, ValueError) as exc:
        logging.warning("Quarantine operation failed for %s: %s", filepath, exc)
        return False
    return verify(filepath)
