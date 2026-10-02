"""Centralized configuration for correlated security analysis."""
from __future__ import annotations

import os


def _bool(name: str, default: bool) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _bounded_float(name: str, default: float, low: float, high: float) -> float:
    try:
        value = float(os.environ.get(name, default))
    except (TypeError, ValueError):
        value = default
    return max(low, min(high, value))


CODE_ANALYSIS_ENABLED = _bool("ISOLATION_BYTES_CODE_ANALYSIS", True)
ML_CORRELATION_ENABLED = _bool("ISOLATION_BYTES_ML_CORRELATION", True)
FILE_DISCOVERY_ENABLED = _bool("ISOLATION_BYTES_FILE_DISCOVERY", True)

# Per-file analysis guard only; this never caps recursive file enumeration.
try:
    CODE_ANALYSIS_MAX_BYTES = max(
        64 * 1024,
        int(os.environ.get("ISOLATION_BYTES_CODE_ANALYSIS_MAX_BYTES", 5 * 1024 * 1024)),
    )
except (TypeError, ValueError):
    CODE_ANALYSIS_MAX_BYTES = 5 * 1024 * 1024

CRITICAL_YARA_AUTHORITATIVE = True

# Evidence is bounded and additive; YARA remains the strongest signal.
YARA_WEIGHT = _bounded_float("ISOLATION_BYTES_YARA_WEIGHT", 0.50, 0.20, 0.80)
ML_WEIGHT = _bounded_float("ISOLATION_BYTES_ML_WEIGHT", 0.25, 0.05, 0.50)
CODE_ANALYSIS_WEIGHT = _bounded_float("ISOLATION_BYTES_CODE_ANALYSIS_WEIGHT", 0.15, 0.05, 0.35)
BEHAVIOR_WEIGHT = _bounded_float("ISOLATION_BYTES_BEHAVIOR_WEIGHT", 0.10, 0.05, 0.30)
