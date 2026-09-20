"""Verified quarantine entry point shared by security scanners."""
from __future__ import annotations

import hashlib
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


def verify(filepath: str, expected_sha256: str | None = None) -> bool:
    """Verify source removal and, when possible, exact artifact preservation."""
    if os.path.lexists(filepath):
        return False

    artifacts = [path for path in _artifacts(filepath) if os.path.isfile(path)]
    if not artifacts:
        return False
    if not expected_sha256:
        return True

    try:
        from cryptography.fernet import Fernet
        key = os.environ.get("FERNET_KEY", "").encode()
        if len(key) != 44:
            return False
        fernet = Fernet(key)
    except Exception:
        return False

    expected = str(expected_sha256).lower()
    for artifact in artifacts:
        try:
            with open(artifact, "rb") as handle:
                plaintext = fernet.decrypt(handle.read())
            if hashlib.sha256(plaintext).hexdigest().lower() == expected:
                return True
        except Exception:
            continue
    return False


def quarantine_and_verify(filepath: str, *, reason: str = "") -> bool:
    """Contain a file and fail closed if containment cannot be verified."""
    if not filepath or not os.path.isfile(filepath):
        return False
    try:
        with open(filepath, "rb") as handle:
            expected_sha256 = hashlib.sha256(handle.read()).hexdigest()
    except OSError as exc:
        logging.warning("Cannot hash quarantine candidate %s: %s", filepath, exc)
        return False

    try:
        import quarantine_utils
        quarantine_utils.quarantine_file(filepath, reason=reason)
    except (OSError, RuntimeError, ValueError) as exc:
        logging.warning("Quarantine operation failed for %s: %s", filepath, exc)
        return False
    return verify(filepath, expected_sha256=expected_sha256)
