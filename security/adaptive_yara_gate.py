"""Adaptive YARA gating.

Broad rules remain loaded and scanned, but are treated as corroborating evidence
until the file has enough independent evidence to justify activating them.
Rule reputation then learns from clean and confirmed-malware outcomes.
"""
from __future__ import annotations

import logging
from typing import Iterable, Mapping, Optional

# These rules are intentionally *not* removed from the rule corpus.  The set is
# imported lazily so this module cannot create a yara_scanner <-> reputation
# import cycle.
def _seed_noisy_rules() -> set[str]:
    try:
        from security.yara_scanner import NOISY_RULE_NAMES
        return set(NOISY_RULE_NAMES)
    except Exception:
        return set()


def is_broad_rule(rule_name: str) -> bool:
    return str(rule_name or "") in _seed_noisy_rules()


def _rule_name(match) -> str:
    return str(getattr(match, "rule", "") or "")


def filter_for_decision(
    matches: Iterable[object],
    *,
    behavioral_score: float = 0.0,
    ml_confidence: float = 0.0,
    code_analysis_score: float = 0.0,
    confirmed: bool = False,
) -> list[object]:
    """Return matches eligible to drive the containment decision.

    Broad rules are promoted when independent evidence is strong. Otherwise
    they stay visible as telemetry but do not become a standalone quarantine
    trigger. Dynamically unsuppressed rules are always eligible.
    """
    try:
        from security.rule_reputation import is_suppressed
    except Exception:
        is_suppressed = lambda _name: False

    independent = (
        float(behavioral_score or 0.0) >= 55.0
        or float(ml_confidence or 0.0) >= 0.80
        or float(code_analysis_score or 0.0) >= 55.0
        or confirmed
    )
    result: list[object] = []
    for match in matches or []:
        name = _rule_name(match)
        if is_suppressed(name):
            # A rule suppressed by reputation stays out unless a confirmed
            # malware result explicitly reactivates it.
            if confirmed:
                result.append(match)
            continue
        if is_broad_rule(name) and not independent:
            continue
        result.append(match)
    return result


def record_clean_matches(matches: Iterable[object]) -> None:
    try:
        from security.rule_reputation import record_clean_hit
        for match in matches or []:
            name = _rule_name(match)
            if name:
                record_clean_hit(name)
    except Exception as exc:
        logging.debug("Adaptive YARA clean-hit recording unavailable: %s", exc)


def record_confirmed_malware(matches: Iterable[object]) -> None:
    try:
        from security.rule_reputation import confirm_malware_hit
        names = [_rule_name(match) for match in matches or []]
        confirm_malware_hit(name for name in names if name)
    except Exception as exc:
        logging.debug("Adaptive YARA malware-hit recording unavailable: %s", exc)


def explain(matches: Iterable[object]) -> Mapping[str, int]:
    """Return counts useful to dashboards without hiding broad-rule matches."""
    total = broad = suppressed = 0
    try:
        from security.rule_reputation import is_suppressed
    except Exception:
        is_suppressed = lambda _name: False
    for match in matches or []:
        total += 1
        name = _rule_name(match)
        broad += int(is_broad_rule(name))
        suppressed += int(is_suppressed(name))
    return {"total": total, "broad": broad, "suppressed": suppressed}
