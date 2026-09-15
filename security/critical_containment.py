"""Fail-closed containment adapter for high-confidence detections."""

import logging
import os


def _containment_folders(quarantine_utils):
    return (
        quarantine_utils.QUARANTINE_FOLDER,
        os.path.join(quarantine_utils.basedir, "failed_quarantine"),
        os.path.join(os.path.dirname(quarantine_utils.basedir), "failed_quarantine"),
    )


def _matching_artifacts(folder, basename):
    try:
        names = os.listdir(folder)
    except OSError:
        return []
    return [
        os.path.join(folder, name)
        for name in names
        if name == basename
        or name == basename + ".enc"
        or name.startswith(basename + "_")
        or name.startswith(basename + ".")
    ]


def _artifact_paths(filepath):
    """Return possible containment artifacts for *filepath*."""
    try:
        import quarantine_utils
        basename = os.path.basename(filepath)
        candidates = []
        for folder in _containment_folders(quarantine_utils):
            candidates.extend(_matching_artifacts(folder, basename))
        return list(dict.fromkeys(candidates))
    except Exception:
        return []


def verify_containment(filepath):
    """Require the original path to be gone and a containment artifact to exist."""
    if os.path.lexists(filepath):
        return False
    return any(os.path.isfile(candidate) for candidate in _artifact_paths(filepath))


def contain_critical_file(filepath, reason="critical YARA match"):
    """Contain a critical file and return an explicit success boolean."""
    if not filepath or not os.path.isfile(filepath):
        return False
    try:
        import quarantine_utils
        quarantine_utils.quarantine_file(filepath, reason=reason)
    except Exception as exc:
        logging.warning("Critical containment operation failed for %s: %s", filepath, exc)
    return verify_containment(filepath)
