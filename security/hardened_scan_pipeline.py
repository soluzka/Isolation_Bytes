"""Unified, conservative malware scanning pipeline.

This is the single scan/remediation decision path used by the filesystem
watcher. It is non-executing, scans recursively without a file-count or
100-MiB ceiling, and uses streaming behavioral evidence plus YARA/ML signals.
Audio/video files are not blanket-excluded: YARA is invoked directly here so
media containers receive the same static inspection as other files.
"""
from __future__ import annotations

import logging
import os
from typing import Dict, Iterable, List, Optional

from security.behavioral_malware_detector import analyze_file, quarantine_decision


TRAVERSAL_EXCLUSIONS = {"proc", "sys", "dev"}


def iter_files(target: str) -> Iterable[str]:
    """Yield every regular file below target; never cap file count or size."""
    if os.path.isfile(target):
        yield target
        return
    if not os.path.isdir(target):
        return
    for root, dirs, files in os.walk(target):
        dirs[:] = [d for d in dirs if d not in TRAVERSAL_EXCLUSIONS]
        for name in files:
            path = os.path.join(root, name)
            try:
                if os.path.isfile(path):
                    yield path
            except OSError:
                logging.exception("Unable to stat candidate: %s", path)


def _yara(path: str):
    """Run the rule sets directly, bypassing extension-based skip lists.

    The older security.yara_scanner.scan_file_with_yara() API intentionally
    remains available for compatibility, but the authoritative pipeline does
    not call it because it previously skipped audio/video extensions. Rules
    are matched against the path for large files and therefore do not require
    loading an entire large object into Python memory.
    """
    try:
        from security.yara_scanner import (
            load_yara_rules,
            _classify_filetype,
        )
        import warnings
        import yara

        ext = os.path.splitext(path)[1].lower()
        externals = {
            "extension": ext,
            "filename": os.path.basename(path),
            "filepath": path,
            "filetype": _classify_filetype(path),
        }
        matches = []
        for rule in load_yara_rules():
            try:
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore", RuntimeWarning)
                    matches.extend(rule.match(path, timeout=2, externals=externals, fast=True))
            except yara.TimeoutError:
                logging.warning("YARA timeout scanning %s", path)
                break
            except yara.Error as exc:
                logging.error("YARA rule error scanning %s: %s", path, exc)
        # Apply the scanner's explicit/adaptive noise policy after matching;
        # importantly, do not apply its media-extension early return.
        try:
            from security.yara_scanner import NOISY_RULE_NAMES
            matches = [m for m in matches if getattr(m, "rule", "") not in NOISY_RULE_NAMES]
        except Exception:
            pass
        try:
            from security.rule_reputation import is_suppressed
            matches = [m for m in matches if not is_suppressed(getattr(m, "rule", ""))]
        except Exception:
            pass
        return matches
    except Exception as exc:
        logging.error("YARA failed for %s: %s", path, exc)
        return None


def _yara_severity(matches) -> str:
    """Resolve severity through the canonical YARA severity helper."""
    if not matches:
        return ""
    try:
        from security.yara_scanner import get_highest_severity
        return get_highest_severity(matches)
    except Exception:
        rank = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        highest = ""
        for item in matches if isinstance(matches, (list, tuple, set)) else [matches]:
            value = getattr(item, "severity", "")
            if isinstance(item, dict):
                value = item.get("severity", "")
            value = str(value).lower()
            if rank.get(value, 0) > rank.get(highest, 0):
                highest = value
        return highest


def _ml_confidence(path: str) -> float:
    """Use existing ML only when fitted; ML failures are neutral."""
    try:
        from ml_security import security_ml
        if not security_ml._is_fitted():
            return 0.0
        features = security_ml.get_features({"path": path, "filename": os.path.basename(path)})
        _, scores = security_ml.predict(features)
        if scores is None:
            return 0.0
        return max(0.0, min(1.0, 0.5 - float(scores[0])))
    except Exception:
        return 0.0


def _contain(path: str, reason: str) -> tuple[bool, str]:
    """Contain a confirmed file and verify the original path is gone."""
    try:
        from security.verified_quarantine import quarantine_and_verify
        ok = bool(quarantine_and_verify(path, reason=reason))
        return ok, "verified_quarantine"
    except Exception:
        # Keep compatibility with quarantine_utils while preserving fail-closed
        # reporting: an exception or a surviving original path is never called
        # a successful quarantine.
        try:
            from quarantine_utils import quarantine_file
            quarantine_file(path, reason=reason)
            return not os.path.exists(path), "quarantine_utils"
        except Exception as exc:
            return False, str(exc)


def scan_file(path: str, *, quarantine: bool = True) -> Dict[str, object]:
    """Scan one file and optionally contain only corroborated detections."""
    path = os.path.abspath(path)
    evidence = analyze_file(path)
    matches = _yara(path)
    yara_severity = _yara_severity(matches)
    ml_confidence = _ml_confidence(path)

    decision = quarantine_decision(
        evidence,
        yara_severity=yara_severity,
        ml_confidence=ml_confidence,
        antivirus_confirmed=False,
    )

    result: Dict[str, object] = {
        "path": path,
        "sha256": evidence.sha256,
        "size": evidence.size,
        "extension": evidence.extension,
        "magic": evidence.magic,
        "entropy": evidence.entropy,
        "printable_ratio": evidence.printable_ratio,
        "behavioral_score": evidence.score,
        "behavioral_confidence": evidence.confidence,
        "behavioral_categories": evidence.categories,
        "indicators": evidence.indicators,
        "yara_severity": yara_severity,
        "yara_matches": len(matches or []),
        "ml_confidence": ml_confidence,
        "server_context": evidence.server_context,
        "quarantine": False,
        "quarantine_verified": False,
        "status": "clean_or_uncorroborated",
    }

    if quarantine and decision["quarantine"]:
        ok, method = _contain(path, "corroborated multi-signal malware detection")
        result["quarantine"] = ok
        result["quarantine_verified"] = ok and not os.path.exists(path)
        result["containment_method"] = method
        result["status"] = "quarantined" if result["quarantine_verified"] else "containment_unverified"
    elif evidence.suspicious or matches:
        result["status"] = "suspicious_review_or_corroboration"

    return result


def scan_target(target: str, *, quarantine: bool = True) -> List[Dict[str, object]]:
    """Scan a file or directory recursively, preserving inaccessible-file errors."""
    results: List[Dict[str, object]] = []
    for path in iter_files(os.path.abspath(target)):
        try:
            results.append(scan_file(path, quarantine=quarantine))
        except (PermissionError, OSError) as exc:
            results.append({"path": path, "status": "scan_error", "error": str(exc)})
        except Exception as exc:
            logging.exception("Unexpected scan failure for %s", path)
            results.append({"path": path, "status": "scan_error", "error": str(exc)})
    return results
