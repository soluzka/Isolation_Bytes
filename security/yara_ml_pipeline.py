"""YARA, static-code, ML, behavior, and exact-file discovery correlation."""
from __future__ import annotations

import logging
import math
from typing import Any, Dict, Optional

from security.code_analysis_engine import analyze_file as analyze_code
from security.code_analysis_engine import code_evidence_score, to_ml_features
from security.security_analysis_config import (
    CODE_ANALYSIS_ENABLED,
    CRITICAL_YARA_AUTHORITATIVE,
    FILE_DISCOVERY_ENABLED,
    ML_CORRELATION_ENABLED,
)
from threat_level_engine import score_threat


def _legacy_ml_features(analysis: Dict[str, Any]) -> Optional[Any]:
    """Build the fixed-width feature vector used by legacy model artifacts."""
    from ml_security import security_ml

    signals = analysis.get("signals", {}) or {}
    connection_data = {
        "bytes_sent": min(float(analysis.get("size", 0)), 2_147_483_647.0),
        "bytes_received": float(analysis.get("suspicious_strings", 0)),
        "duration": float(analysis.get("entropy", 0.0)),
        "port": 443 if signals.get("network_c2") else 0,
        "protocol": 1 if signals.get("network_c2") else 0,
        "connection_count": float(analysis.get("ast_calls", 0)),
        "packet_rate": float(analysis.get("ast_imports", 0)),
        "packet_size": float(analysis.get("ast_dynamic", 0)),
        "state": 1 if signals.get("process_exec") else 0,
        "service": 1 if signals.get("web_execution") else 0,
        "geo": 1 if signals.get("credential_access") else 0,
        "user_agent": 1 if signals.get("dynamic_code") else 0,
    }
    return security_ml.get_features(connection_data)


def _model_expected_features(model: Any) -> Optional[int]:
    fitted = getattr(model, "named_steps", {}).get("model")
    expected = getattr(fitted, "n_features_in_", None)
    return None if expected is None else int(expected)


def _ml_model_ready(model: Any, features: Any) -> bool:
    if model is None or features is None:
        return False
    expected = _model_expected_features(model)
    return expected is None or expected == int(features.shape[1])


def _normalise_anomaly_score(decision_function: Any, prediction: Any) -> float:
    """Convert IsolationForest output into bounded anomaly confidence."""
    try:
        score = float(decision_function)
    except (TypeError, ValueError):
        return 0.0
    if not math.isfinite(score):
        return 0.0
    confidence = max(0.0, min(1.0, 0.5 - score))
    return max(confidence, 0.60) if prediction == -1 else confidence


def _file_ml_features(analysis: Dict[str, Any], model: Any) -> Optional[Any]:
    """Select the file schema when supported, otherwise use legacy schema."""
    from ml_security import security_ml

    expected = _model_expected_features(model)
    if expected == 18:
        features = security_ml.get_file_features(analysis.get("filepath", ""))
        return features
    return _legacy_ml_features(analysis)


def _ml_signal(analysis: Dict[str, Any]) -> Dict[str, Any]:
    if not ML_CORRELATION_ENABLED:
        return {"available": False, "reason": "disabled_by_configuration"}
    try:
        from ml_security import security_ml

        model = getattr(security_ml, "pipeline", None)
        features = _file_ml_features(analysis, model)
        if not _ml_model_ready(model, features):
            return {"available": False, "reason": "model_not_ready_or_schema_mismatch"}

        predictions, scores = security_ml.predict(features)
        if scores is None or len(scores) == 0:
            return {"available": False, "reason": "model_not_ready"}
        prediction = int(predictions[0]) if predictions is not None else 0
        decision = float(scores[0])
        return {
            "available": True,
            "prediction": prediction,
            "decision_function": decision,
            "anomaly_confidence": _normalise_anomaly_score(decision, prediction),
            "features": to_ml_features(analysis),
        }
    except Exception as exc:
        logging.debug("Static-code ML correlation unavailable: %s", exc)
        return {"available": False, "reason": "ml_error"}


def _discovery_evidence(filepath: str, matches: Any, severity: str,
                        code_score: float, ml: Dict[str, Any],
                        threat: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    if not FILE_DISCOVERY_ENABLED:
        return None
    try:
        from security.file_discovery import discover_file

        rules = [getattr(match, "rule", "") for match in matches or []]
        return discover_file(
            filepath,
            yara_severity=severity,
            yara_rules=rules,
            code_score=code_score,
            ml_score=ml.get("anomaly_confidence", 0.0),
            threat_level=threat.get("level", "low"),
        )
    except Exception as exc:
        logging.debug("File discovery ledger unavailable: %s", exc)
        return None


def correlate_evidence(filepath: str, matches: Any,
                       *, analysis: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Correlate one YARA result with all non-executing evidence sources."""
    if analysis is None:
        analysis = (
            analyze_code(filepath)
            if CODE_ANALYSIS_ENABLED
            else {"filepath": filepath, "signals": {}, "size": 0}
        )
    analysis.setdefault("filepath", filepath)

    ml = _ml_signal(analysis)
    signals = analysis.get("signals", {}) or {}
    behavioral = {name: 75.0 for name, present in signals.items() if present}
    code_score = code_evidence_score(analysis) if CODE_ANALYSIS_ENABLED else 0.0

    from security.yara_scanner import get_highest_severity
    severity = get_highest_severity(matches)
    confirmed = CRITICAL_YARA_AUTHORITATIVE and severity == "critical"
    threat = score_threat(
        filepath,
        yara_severity=severity,
        yara_matches=matches,
        ml_confidence=(ml.get("anomaly_confidence") if ml.get("available") else None),
        code_analysis_score=code_score,
        behavioral_signals=behavioral,
        confirmed=confirmed,
    )
    discovery = _discovery_evidence(
        filepath, matches, severity, code_score, ml, threat
    )
    return {
        "filepath": filepath,
        "yara_matches": matches,
        "yara_severity": severity,
        "code_analysis": analysis,
        "code_analysis_score": code_score,
        "ml": ml,
        "discovery": discovery,
        "threat": threat,
    }


def analyze_file(filepath: str, *, timeout: int = 2) -> Dict[str, Any]:
    """Run YARA once and correlate that exact match set."""
    from security.yara_scanner import scan_file_with_yara

    matches = scan_file_with_yara(filepath, timeout=timeout)
    return correlate_evidence(filepath, matches)


def should_contain(result: Dict[str, Any]) -> bool:
    """Contain critical YARA hits or critical correlated verdicts."""
    threat = result.get("threat", {}) or {}
    return result.get("yara_severity") == "critical" or threat.get("level") == "critical"


def _artifact_candidates(filepath: str) -> list[str]:
    """Compatibility helper for callers that inspect containment artifacts."""
    import os

    from quarantine_utils import QUARANTINE_FOLDER, basedir

    basename = os.path.basename(filepath)
    folders = (
        QUARANTINE_FOLDER,
        os.path.join(basedir, "failed_quarantine"),
        os.path.join(os.path.dirname(basedir), "failed_quarantine"),
    )
    candidates = []
    for folder in folders:
        try:
            names = os.listdir(folder)
        except OSError:
            continue
        candidates.extend(
            os.path.join(folder, name)
            for name in names
            if (
                name == basename
                or name == basename + ".enc"
                or name.startswith(basename + "_")
                or name.startswith(basename + ".")
            )
        )
    return list(dict.fromkeys(candidates))


def verify_containment(filepath: str) -> bool:
    """Return true only when the source is gone and an artifact exists."""
    import os

    return not os.path.lexists(filepath) and any(
        os.path.isfile(path) for path in _artifact_candidates(filepath)
    )


def quarantine_correlated(filepath: str, *, reason: str = "") -> bool:
    """Contain a critical correlated file and persist its exact identity."""
    result = analyze_file(filepath)
    if not should_contain(result):
        return False

    try:
        from security.critical_containment import contain_critical_file

        success = bool(
            contain_critical_file(
                filepath,
                reason=reason or result.get("yara_severity", "critical"),
            )
        )
    except Exception as exc:
        logging.error("Correlated containment failed for %s: %s", filepath, exc)
        return False

    if not success:
        return False
    discovery = result.get("discovery") or {}
    sha256 = discovery.get("sha256")
    if sha256 and FILE_DISCOVERY_ENABLED:
        try:
            from security.file_discovery import ledger
            ledger.mark_contained(sha256, True)
        except Exception as exc:
            logging.debug("Could not mark discovered identity contained: %s", exc)
    return True
