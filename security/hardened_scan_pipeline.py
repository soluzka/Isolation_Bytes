"""Unified, conservative malware scanning pipeline.

The pipeline is deliberately non-executing. It combines existing YARA/ML/AV
signals with streaming behavioral evidence and only auto-quarantines when
there is corroboration (or an explicit host-AV confirmation). It enumerates
recursively without an artificial total-file or 100-MiB ceiling.
"""
from __future__ import annotations

import logging
import os
from typing import Dict, Iterable, List, Optional

from security.behavioral_malware_detector import analyze_file, quarantine_decision


def iter_files(target: str) -> Iterable[str]:
    """Yield every accessible regular file below target; never cap file count/size."""
    if os.path.isfile(target):
        yield target
        return
    if not os.path.isdir(target):
        return
    for root, dirs, files in os.walk(target):
        dirs[:] = [d for d in dirs if d not in {"proc", "sys", "dev"}]
        for name in files:
            path = os.path.join(root, name)
            try:
                if os.path.isfile(path):
                    yield path
            except OSError:
                logging.exception("Unable to stat candidate: %s", path)


def _yara(path: str):
    try:
        from security.yara_scanner import scan_file_with_yara
        return scan_file_with_yara(path)
    except Exception as exc:
        logging.error("YARA failed for %s: %s", path, exc)
        return None


def _yara_severity(matches) -> str:
    rank = {"low": 1, "medium": 2, "high": 3, "critical": 4}
    highest = ""
    if not matches:
        return highest
    values = matches if isinstance(matches, (list, tuple, set)) else [matches]
    for item in values:
        value = item.get("severity", "") if isinstance(item, dict) else getattr(item, "severity", "")
        value = str(value).lower()
        if rank.get(value, 0) > rank.get(highest, 0):
            highest = value
    return highest


def _ml_confidence(path: str) -> float:
    """Use the existing ML model when fitted; failures are neutral."""
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


def scan_file(path: str, *, quarantine: bool = True) -> Dict[str, object]:
    """Scan one file and optionally quarantine only a corroborated detection."""
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
        "behavioral_score": evidence.score,
        "behavioral_confidence": evidence.confidence,
        "behavioral_categories": evidence.categories,
        "indicators": evidence.indicators,
        "yara_severity": yara_severity,
        "ml_confidence": ml_confidence,
        "server_context": evidence.server_context,
        "quarantine": False,
        "quarantine_verified": False,
        "status": "clean_or_uncorroborated",
    }

    if quarantine and decision["quarantine"]:
        try:
            from quarantine_utils import quarantine_file
            quarantine_file(path, reason="corroborated multi-signal malware detection")
            result["quarantine"] = True
            result["quarantine_verified"] = not os.path.exists(path)
            result["status"] = "quarantined" if result["quarantine_verified"] else "containment_unverified"
        except Exception as exc:
            logging.error("Quarantine failed for %s: %s", path, exc)
            result["status"] = "quarantine_failed"
            result["quarantine_error"] = str(exc)
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
