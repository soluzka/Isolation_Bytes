"""Unified indicator helpers for the Conditional Startup scan.

These helpers only normalize/report evidence already produced by the scanner;
they do not make a new quarantine decision path.
"""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any


INDICATOR_KEYS = (
    "yara_suspicious",
    "ml_detections",
    "ransomware_indicators",
    "persistence_indicators",
    "errors",
    "process_events",
)


def ensure_indicator_results(results: dict[str, Any]) -> dict[str, Any]:
    """Ensure all dashboard-visible indicator containers exist."""
    for key in INDICATOR_KEYS:
        if key not in results:
            results[key] = {} if key == "persistence_indicators" else []
    return results


def record_yara_suspicious(
    results: dict[str, Any],
    filepath: str,
    severity: str,
    rules: list[str] | None = None,
    namespaces: list[str] | None = None,
) -> dict[str, Any]:
    """Record a normalized YARA suspicious finding."""
    item = {
        "file": filepath,
        "highest_severity": severity,
        "rules": list(rules or []),
        "namespaces": list(namespaces or []),
    }
    results.setdefault("yara_suspicious", []).append(item)
    return item


def record_ml_suspicious(
    results: dict[str, Any],
    filepath: str,
    score: float,
    model: str,
) -> dict[str, Any]:
    """Record a normalized ML finding."""
    item = {
        "file": filepath,
        "anomaly_score": float(score),
        "model": model,
    }
    results.setdefault("ml_detections", []).append(item)
    return item


def record_ransomware_indicator(
    results: dict[str, Any],
    filepath: str,
    reason: str,
) -> dict[str, Any]:
    """Record a normalized ransomware indicator."""
    item = {"file": filepath, "reason": reason}
    results.setdefault("ransomware_indicators", []).append(item)
    return item


def record_persistence_indicators(
    results: dict[str, Any],
    findings: Mapping[str, Any],
) -> int:
    """Replace persistence results and return the number of indicators."""
    normalized = dict(findings or {})
    results["persistence_indicators"] = normalized
    return sum(
        len(value) if isinstance(value, (list, tuple, dict, set)) else 1
        for value in normalized.values()
    )


def record_error(
    results: dict[str, Any],
    stage: str,
    error: Any,
    filepath: str | None = None,
) -> dict[str, Any]:
    """Record a structured scanner error for the dashboard."""
    item: dict[str, Any] = {"stage": stage, "error": str(error)}
    if filepath:
        item["file"] = filepath
    results.setdefault("errors", []).append(item)
    return item


def record_process_event(
    results: dict[str, Any],
    event: Mapping[str, Any],
) -> dict[str, Any]:
    """Record a normalized process-monitor event."""
    item = dict(event)
    results.setdefault("process_events", []).append(item)
    return item


def indicator_counts(results: Mapping[str, Any]) -> dict[str, int]:
    """Return dashboard-ready counts for every indicator stream."""
    persistence = results.get("persistence_indicators") or {}
    persistence_count = (
        sum(len(v) if isinstance(v, (list, tuple, dict, set)) else 1
            for v in persistence.values())
        if isinstance(persistence, Mapping) else len(persistence)
    )
    return {
        "yara_suspicious": len(results.get("yara_suspicious") or []),
        "ml_detections": len(results.get("ml_detections") or []),
        "ransomware_indicators": len(results.get("ransomware_indicators") or []),
        "persistence_indicators": persistence_count,
        "errors": len(results.get("errors") or []),
        "process_events": len(results.get("process_events") or []),
    }
