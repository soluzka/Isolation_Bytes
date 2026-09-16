"""Adaptive YARA gating.

Broad rules remain loaded and scanned, but are treated as corroborating evidence
until independent evidence activates them. Rule reputation learns from clean and
confirmed-malware outcomes; an otherwise suppressed rule can be reactivated for
the current decision when independent evidence says it is needed.
"""
from __future__ import annotations

import logging
from typing import Iterable, Mapping


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


def _independent_evidence(behavioral_score: float, ml_confidence: float,
                          code_analysis_score: float, confirmed: bool) -> bool:
    """Whether non-YARA evidence is strong enough to activate broad rules."""
    return (
        float(behavioral_score or 0.0) >= 55.0
        or float(ml_confidence or 0.0) >= 0.80
        or float(code_analysis_score or 0.0) >= 55.0
        or bool(confirmed)
    )


def filter_for_decision(
    matches: Iterable[object],
    *,
    behavioral_score: float = 0.0,
    ml_confidence: float = 0.0,
    code_analysis_score: float = 0.0,
    confirmed: bool = False,
) -> list[object]:
    """Return YARA matches eligible to drive containment.

    Every match is still observed by the scanner. Broad/static-noisy rules are
    merely held as telemetry until independent evidence activates them. A rule
    suppressed by reputation is also reactivated for the current decision when
    strong behavioral/ML/code evidence or confirmation says it is needed. This
    prevents reputation suppression from masking a genuinely changing threat.
    """
    try:
        from security.rule_reputation import is_suppressed
    except Exception:
        is_suppressed = lambda _name: False

    independent = _independent_evidence(
        behavioral_score, ml_confidence, code_analysis_score, confirmed
    )
    result: list[object] = []
    for match in matches or []:
        name = _rule_name(match)
        suppressed = bool(is_suppressed(name))

        # Dynamic suppression is not an absolute block: strong independent
        # evidence reactivates the rule for this scan.
        if suppressed and not independent:
            continue

        # Static broad/noisy rules remain scanned and observable, but cannot
        # independently cause containment. Independent evidence promotes them.
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
        names = {_rule_name(match) for match in matches or []}
        names.discard("")
        # Pass actual rule-name strings, not a generator, so every matched rule
        # is reliably recorded and dynamically unsuppressed by reputation.
        if names:
            confirm_malware_hit(names)
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
