"""Dynamic threat scoring shared by file, process, and network telemetry.

The engine deliberately keeps the score explainable: independent YARA, ML and
behavioral evidence are normalized to 0..1, combined, and retained with a
short-lived history so repeated activity can raise confidence while quiet
periods allow the score to decay.
"""
from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, Mapping, Optional


_LEVELS = ((0.85, "critical"), (0.65, "high"), (0.40, "medium"), (0.15, "low"), (0.0, "clean"))
_YARA_WEIGHTS = {"critical": 1.0, "high": 0.85, "medium": 0.55, "low": 0.25, "info": 0.05}


def _clamp(value: Any, default: float = 0.0) -> float:
    try:
        return max(0.0, min(1.0, float(value)))
    except (TypeError, ValueError):
        return default


def _yara_score(severity: Any) -> float:
    if isinstance(severity, (int, float)):
        return _clamp(severity)
    if isinstance(severity, str):
        return _YARA_WEIGHTS.get(severity.lower().strip(), 0.0)
    if isinstance(severity, Iterable) and not isinstance(severity, (str, bytes, dict)):
        return max((_yara_score(item) for item in severity), default=0.0)
    if isinstance(severity, Mapping):
        return max((_yara_score(v) for v in severity.values()), default=0.0)
    return 0.0


@dataclass
class ThreatState:
    score: float = 0.0
    updated_at: float = field(default_factory=time.time)
    history: deque = field(default_factory=lambda: deque(maxlen=20))


class ThreatLevelEngine:
    """Thread-safe, stateful threat scoring engine."""

    def __init__(self, decay_seconds: float = 300.0):
        self.decay_seconds = max(1.0, float(decay_seconds))
        self._states: Dict[str, ThreatState] = {}
        self._lock = threading.RLock()

    def score(
        self,
        entity_id: str,
        *,
        yara_severity: Any = 0.0,
        ml_confidence: Any = 0.0,
        behavioral_signals: Any = None,
        behavior_score: Any = None,
        persist: bool = True,
    ) -> Dict[str, Any]:
        """Calculate and optionally retain a threat assessment."""
        yara = _yara_score(yara_severity)
        ml = _clamp(ml_confidence)
        behavior = self._behavior_score(behavioral_signals, behavior_score)

        # Evidence weights: YARA is strongest, ML provides corroboration, and
        # behavior captures activity that may not leave a static signature.
        raw = (0.45 * yara) + (0.30 * ml) + (0.25 * behavior)

        now = time.time()
        with self._lock:
            previous = self._states.get(str(entity_id))
            previous_score = previous.score if previous else 0.0
            if previous:
                elapsed = max(0.0, now - previous.updated_at)
                decay = max(0.0, min(1.0, elapsed / self.decay_seconds))
                baseline = previous_score * (1.0 - decay)
                # New evidence dominates stale history but recent evidence can
                # accumulate instead of resetting the assessment each event.
                combined = max(raw, (0.65 * raw) + (0.35 * baseline))
            else:
                combined = raw

            state = previous or ThreatState()
            state.score = _clamp(combined)
            state.updated_at = now
            state.history.append(state.score)
            if persist:
                self._states[str(entity_id)] = state

            level = self.level_for(state.score)
            return {
                "entity_id": str(entity_id),
                "score": round(state.score, 4),
                "level": level,
                "signals": {
                    "yara": round(yara, 4),
                    "ml": round(ml, 4),
                    "behavior": round(behavior, 4),
                },
                "history": list(state.history),
                "timestamp": now,
            }

    def update(self, entity_id: str, **signals: Any) -> Dict[str, Any]:
        """Alias used by monitoring loops as new telemetry arrives."""
        return self.score(entity_id, **signals)

    def get(self, entity_id: str) -> Dict[str, Any]:
        with self._lock:
            state = self._states.get(str(entity_id))
            if not state:
                return {"entity_id": str(entity_id), "score": 0.0, "level": "clean", "signals": {}}
            return {"entity_id": str(entity_id), "score": round(state.score, 4), "level": self.level_for(state.score)}

    def reset(self, entity_id: str) -> None:
        with self._lock:
            self._states.pop(str(entity_id), None)

    @staticmethod
    def level_for(score: float) -> str:
        value = _clamp(score)
        for threshold, level in _LEVELS:
            if value >= threshold:
                return level
        return "clean"

    @staticmethod
    def _behavior_score(signals: Any, explicit: Any = None) -> float:
        if explicit is not None:
            return _clamp(explicit)
        if signals is None:
            return 0.0
        if isinstance(signals, Mapping):
            values = []
            for value in signals.values():
                if isinstance(value, bool):
                    values.append(1.0 if value else 0.0)
                elif isinstance(value, (int, float)):
                    values.append(_clamp(value))
            return max(values, default=0.0)
        if isinstance(signals, (list, tuple, set)):
            return max((_clamp(v, 1.0 if isinstance(v, bool) and v else 0.0) for v in signals), default=0.0)
        return _clamp(signals)


threat_level_engine = ThreatLevelEngine()

__all__ = ["ThreatLevelEngine", "ThreatState", "threat_level_engine"]
