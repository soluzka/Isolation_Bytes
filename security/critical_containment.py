"""Fail-closed containment adapter for high-confidence detections.

This module keeps scanner policy separate from encryption details. A critical
match must not be gated on the presence of FERNET_KEY in the scanner: the
quarantine implementation owns encryption/fallback containment and this
adapter verifies the original is no longer executable at its original path.
"""

import logging
import os


def _artifact_paths(filepath):
    """Return possible containment artifacts for *filepath*."""
    try:
        import quarantine_utils
        basename = os.path.basename(filepath)
        candidates = [
            os.path.join(quarantine_utils.QUARANTINE_FOLDER, basename + '.enc'),
            os.path.join(quarantine_utils.QUARANTINE_FOLDER, basename),
            os.path.join(os.path.dirname(quarantine_utils.basedir), 'failed_quarantine', basename),
            os.path.join(quarantine_utils.basedir, 'failed_quarantine', basename),
        ]
        # Preserve order while removing duplicates.
        return list(dict.fromkeys(candidates))
    except Exception:
        return []


def verify_containment(filepath):
    """Verify that the original path is gone and a containment artifact exists."""
    if os.path.exists(filepath):
        return False
    return any(os.path.exists(candidate) for candidate in _artifact_paths(filepath))


def contain_critical_file(filepath, reason='critical YARA match'):
    """Contain a critical file and return an explicit success boolean.

    The caller never needs to inspect FERNET_KEY. ``quarantine_file`` is
    responsible for encrypted quarantine or its protected fallback, while this
    function requires post-operation verification before reporting success.
    """
    if not filepath or not os.path.isfile(filepath):
        return False

    try:
        import quarantine_utils
        result = quarantine_utils.quarantine_file(filepath, reason=reason)
        if result is True and verify_containment(filepath):
            return True
    except Exception as exc:
        logging.warning("Critical containment operation failed for %s: %s", filepath, exc)

    # Older quarantine_file implementations returned None. Verification keeps
    # this adapter compatible while preventing a false success count.
    return verify_containment(filepath)
