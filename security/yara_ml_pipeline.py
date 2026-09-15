"""Deliberate YARA + static-code + ML correlation entry point.

This is an additive integration layer. Existing scanners remain unchanged until
callers opt into ``analyze_file``. The layer is read-only during analysis and
only asks the existing quarantine implementation to act after a critical,
corroborated verdict. It never executes target files.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from security.code_analysis_engine import analyze_file as analyze_code, to_ml_features
from security.threat_level_engine import score_threat


# The current SecurityMLModel was trained around the connection feature schema.
# We deliberately project static code evidence into that existing schema rather
# than silently feeding a differently-sized vector into a fitted PCA/model.
def _legacy_ml_features(analysis: Dict[str, Any]) -> Optional[Any]:
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
    # get_features supplies time_of_day/day_of_week and therefore preserves the
    # exact 14-column legacy schema without changing the fitted model.
    return security_ml.get_features(connection_data)


def _ml_signal(analysis: Dict[str, Any]) -> Dict[str, Any]:
    try:
        from ml_security import security_ml
        features = _legacy_ml_features(analysis)
        model = getattr(security_ml, "pipeline", None)
        fitted_model = model.named_steps.get("model") if model is not None else None
        expected = getattr(fitted_model, "n_features_in_", None)
        if expected is not None and int(expected) != int(features.shape[1]):
            return {"available": False, "reason": "model_feature_schema_mismatch"}
        predictions, scores = security_ml.predict(features)
        if scores is None or len(scores) == 0:
            return {"available": False, "reason": "model_not_ready"}
        return {
            "available": True,
            "prediction": int(predictions[0]) if predictions is not None else 0,
            "decision_function": float(scores[0]),
            "features": to_ml_features(analysis),
        }
    except Exception as exc:
        logging.debug("Static-code ML correlation unavailable: %s", exc)
        return {"available": False, "reason": "ml_error"}


def analyze_file(filepath: str, *, timeout: int = 2) -> Dict[str, Any]:
    """Correlate YARA, safe static code evidence, ML, and behavioral signals."""
    from security.yara_scanner import (
        get_highest_severity,
        scan_file_with_yara,
    )

    matches = scan_file_with_yara(filepath, timeout=timeout)
    analysis = analyze_code(filepath)
    ml = _ml_signal(analysis)
    ml_confidence = ml.get("decision_function") if ml.get("available") else None

    signals = analysis.get("signals", {}) or {}
    behavioral = {
        name: 75.0
        for name, present in signals.items()
        if present
    }
    # Static code indicators are corroborating evidence, not automatic malware
    # verdicts. YARA remains the primary signature signal.
    verdict = score_threat(
        filepath,
        yara_severity=get_highest_severity(matches),
        yara_matches=matches,
        ml_confidence=ml_confidence,
        behavioral_signals=behavioral,
    )

    return {
        "filepath": filepath,
        "yara_matches": matches,
        "yara_severity": get_highest_severity(matches),
        "code_analysis": analysis,
        "ml": ml,
        "threat": verdict,
    }


def should_contain(result: Dict[str, Any]) -> bool:
    """Return whether the correlated result is strong enough for containment."""
    threat = result.get("threat", {}) or {}
    return bool(
        result.get("yara_severity") == "critical"
        or threat.get("level") == "critical"
        or threat.get("confirmed") is True
    )


def quarantine_correlated(filepath: str, *, reason: str = "") -> bool:
    """Analyze and, when warranted, invoke the existing quarantine path.

    The quarantine function's boolean result is treated as authoritative so
    callers can increment containment counters only after successful action.
    """
    result = analyze_file(filepath)
    if not should_contain(result):
        return False
    from quarantine_utils import quarantine_file
    return bool(quarantine_file(filepath, reason=reason or result.get("yara_severity", "critical")))
