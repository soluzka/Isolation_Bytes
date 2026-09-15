"""Centralized safe-mode configuration for correlated security analysis.

Environment variables are intentionally opt-in/low-risk. No setting here
reduces YARA coverage or creates a file-count limit.
"""
from __future__ import annotations

import os


def _bool(name: str, default: bool) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


# Correlated analysis is enabled by default for callers using the new pipeline.
CODE_ANALYSIS_ENABLED = _bool("ISOLATION_BYTES_CODE_ANALYSIS", True)
ML_CORRELATION_ENABLED = _bool("ISOLATION_BYTES_ML_CORRELATION", True)

# Keep static analysis bounded per file; this is an analysis-memory guard, not
# a scanner enumeration cap. Files of any count can still be enumerated.
CODE_ANALYSIS_MAX_BYTES = int(os.environ.get("ISOLATION_BYTES_CODE_ANALYSIS_MAX_BYTES", 5 * 1024 * 1024))

# Critical YARA remains authoritative. ML and code evidence corroborate but do
# not downgrade a critical signature when the ML model is unavailable.
CRITICAL_YARA_AUTHORITATIVE = True
