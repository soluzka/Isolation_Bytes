"""Fail-closed containment adapter for high-confidence detections."""

import logging
import os


def _artifact_paths(filepath):
    """Return possible containment artifacts for *filepath*."""
    try:
        import quarantine_utils
        basename = os.path.basename(filepath)
        folders = [
            quarantine_utils.QUARANTINE_FOLDER,
            os.path.join(quarantine_utils.basedir, 'failed_quarantine'),
            os.path.join(os.path.dirname(quarantine_utils.basedir), 'failed_quarantine'),
        ]
        candidates = []
        for folder in folders:
            for name in (basename, basename + '.enc'):
                candidates.append(os.path.join(folder, name))
            try:
                for name in os.listdir(folder):
                    if name.startswith(basename + '_') or name.startswith(basename + '.'):
                        candidates.append(os.path.join(folder, name))
            except OSError:
                pass
        return list(dict.fromkeys(candidates))
    except Exception:
        return []


def verify_containment(filepath):
    """Require the original path to be gone and a containment artifact to exist."""
    if os.path.lexists(filepath):
        return False
    return any(os.path.isfile(candidate) for candidate in _artifact_paths(filepath))


def contain_critical_file(filepath, reason='critical YARA match'):
    """Contain a critical file and return an explicit success boolean.

    Scanner policy never checks FERNET_KEY. The quarantine implementation owns
    encryption and locked-file fallback. This adapter only reports success
    after independently verifying that the original path disappeared and a
    containment artifact exists.
    """
    if not filepath or not os.path.isfile(filepath):
        return False
    try:
        import quarantine_utils
        result = quarantine_utils.quarantine_file(filepath, reason=reason)
        if result is True:
            return verify_containment(filepath)
    except Exception as exc:
        logging.warning('Critical containment operation failed for %s: %s', filepath, exc)
    return verify_containment(filepath)
