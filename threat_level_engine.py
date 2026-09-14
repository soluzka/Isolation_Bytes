"""Dynamic threat scoring shared by file, process, and network monitors.

The engine combines YARA severity, ML confidence, and behavioral signals into a
bounded 0..100 score. Scores are stateful per entity and decay over time so a
single transient signal does not permanently taint an entity, while repeated
behavior raises the score naturally.
"""
from __future__ import annotations

import math
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, Mapping, Optional


_LEVELS = ((80.0, "critical"), (60.0, "high"), (35.0, "medium"), (0.0, "low"))


def _clamp(value: float, low: float = 0.0, high: float = 100.0) -> float:
    return max(low, min(high, float(value)))


def _severity_score(severity: Any) -> float:
    if severity is None:
        return 0.0
    if isinstance(severity, (int, float)):
        return _clamp(float(severity))
    return {"critical": 100.0, "high": 82.0, "medium": 55.0, "low": 25.0}.get(
        str(severity).strip().lower(), 0.0
    )


def _ml_score(confidence: Any) -> float:
    if confidence is None:
        return 0.0
    value = float(confidence)
    if value < 0.0:
        # IsolationForest decision_function is not a probability. Convert a
        # negative anomaly margin to a bounded confidence without pretending
        # it is calibrated probability.
        return _clamp(50.0 + (-value * 50.0))
    if value <= 1.0:
        return _clamp(value * 100.0)
    return _clamp(value)


@dataclass
class _State:
    score: float = 0.0
    last_seen: float = field(default_factory=time.monotonic)
    behavior: Dict[str, float] = field(default_factory=dict)


class ThreatLevelEngine:
    """Thread-safe stateful fusion of static and dynamic security signals."""

    def __init__(self, decay_seconds: float = 300.0, ema_alpha: float = 0.35):
        self.decay_seconds = max(1.0, float(decay_seconds))
        self.ema_alpha = _clamp(ema_alpha, 0.01, 1.0)
        self._states: Dict[str, _State] = {}
        self._lock = threading.RLock()

    @staticmethod
    def level(score: float) -> str:
        for threshold, name in _LEVELS:
            if score >= threshold:
                return name
        return "low"

    def score(
        self,
        entity: str,
        *,
        yara_severity: Any = None,
        yara_matches: Optional[Iterable[Any]] = None,
        ml_confidence: Any = None,
        behavioral_signals: Optional[Mapping[str, Any]] = None,
        confirmed: bool = False,
    ) -> Dict[str, Any]:
        """Fuse current signals with recent state and return a score snapshot."""
        key = str(entity or "unknown")
        now = time.monotonic()
        matches = list(yara_matches or [])
        yara_values = [_severity_score(yara_severity)]
        for match in matches:
            if isinstance(match, Mapping):
                yara_values.append(_severity_score(match.get("severity")))
            else:
                yara_values.append(_severity_score(getattr(match, "severity", None)))
        yara_component = max(yara_values, default=0.0)
        ml_component = _ml_score(ml_confidence)

        behavior_component = 0.0
        behavior_details: Dict[str, float] = {}
        for name, raw in (behavioral_signals or {}).items():
            try:
                magnitude = _clamp(float(raw))
            except (TypeError, ValueError):
                magnitude = 0.0 if not raw else 50.0
            behavior_details[str(name)] = magnitude
            behavior_component = max(behavior_component, magnitude)

        # Weighted fusion: YARA is strongest because it can represent an
        # explicit signature; ML and behavior provide corroboration.
        instantaneous = (
            yara_component * 0.50 + ml_component * 0.25 + behavior_component * 0.25
        )
        if confirmed:
            instantaneous = max(instantaneous, 90.0)

        with self._lock:
            state = self._states.setdefault(key, _State())
            elapsed = max(0.0, now - state.last_seen)
            decay = math.exp(-elapsed / self.decay_seconds)
            state.score *= decay
            for name in list(state.behavior):
                state.behavior[name] *= decay
                if state.behavior[name] < 0.01:
                    del state.behavior[name]
            for name, magnitude in behavior_details.items():
                state.behavior[name] = state.behavior.get(name, 0.0) + magnitude
            state.last_seen = now
            state.score = (
                state.score * (1.0 - self.ema_alpha)
                + instantaneous * self.ema_alpha
            )
            if confirmed:
                state.score = max(state.score, 90.0)
            score = _clamp(state.score)
            return {
                "entity": key,
                "score": round(score, 2),
                "level": self.level(score),
                "yara_score": round(yara_component, 2),
                "ml_score": round(ml_component, 2),
                "behavior_score": round(behavior_component, 2),
                "behavioral_signals": behavior_details,
                "confirmed": bool(confirmed),
                "timestamp": time.time(),
            }

    def get(self, entity: str) -> Dict[str, Any]:
        with self._lock:
            state = self._states.get(str(entity))
            if not state:
                return {"entity": str(entity), "score": 0.0, "level": "low"}
            elapsed = max(0.0, time.monotonic() - state.last_seen)
            score = _clamp(state.score * math.exp(-elapsed / self.decay_seconds))
            return {"entity": str(entity), "score": round(score, 2), "level": self.level(score)}

    def reset(self, entity: Optional[str] = None) -> None:
        with self._lock:
            if entity is None:
                self._states.clear()
            else:
                self._states.pop(str(entity), None)


threat_level_engine = ThreatLevelEngine()


def score_threat(entity: str, **signals: Any) -> Dict[str, Any]:
    """Convenience wrapper used by monitoring loops."""
    return threat_level_engine.score(entity, **signals)
