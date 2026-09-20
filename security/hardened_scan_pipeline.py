"""Unified, conservative malware scanning pipeline with adaptive YARA gating."""
from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Dict, Iterable, List

from security.behavioral_malware_detector import analyze_file, quarantine_decision
from security.static_analysis import analyze_file as analyze_static_file
from security.yara_behavior import behavior_signals

TRAVERSAL_EXCLUSIONS = {"proc", "sys", "dev"}
_RULE_SOURCE_SUFFIXES = {".yar", ".yara"}
_REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
_SECURITY_RULE_ROOT = (_REPOSITORY_ROOT / "security" / "yara_rules").resolve()


def _is_security_rule_asset(path: str) -> bool:
    try:
        candidate = Path(path).resolve()
        return candidate.suffix.lower() in _RULE_SOURCE_SUFFIXES and _SECURITY_RULE_ROOT in candidate.parents
    except (OSError, RuntimeError, ValueError):
        return False


def iter_files(target: str) -> Iterable[str]:
    """Yield every regular file below target; no file-count or size ceiling."""
    if os.path.isfile(target):
        yield target
        return
    if not os.path.isdir(target):
        return
    def _on_walk_error(exc: OSError) -> None:
        logging.error("Unable to traverse %s: %s", getattr(exc, "filename", target), exc)
    for root, dirs, files in os.walk(target, onerror=_on_walk_error):
        dirs[:] = [d for d in dirs if d.lower() not in TRAVERSAL_EXCLUSIONS]
        for name in files:
            path = os.path.join(root, name)
            try:
                if os.path.isfile(path):
                    yield path
            except OSError as exc:
                logging.error("Unable to stat candidate %s: %s", path, exc)


def _yara(path: str):
    """Run every loaded rule; adaptive gating happens after all signals exist."""
    try:
        from security.yara_scanner import load_yara_rules, _classify_filetype
        import warnings
        import yara
        ext = os.path.splitext(path)[1].lower()
        externals = {"extension": ext, "filename": os.path.basename(path), "filepath": path, "filetype": _classify_filetype(path)}
        matches = []
        for rule in load_yara_rules():
            try:
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore", RuntimeWarning)
                    matches.extend(rule.match(path, timeout=2, externals=externals, fast=True))
            except yara.TimeoutError:
                logging.warning("YARA timeout scanning %s", path)
                continue
            except yara.Error as exc:
                logging.error("YARA rule error scanning %s: %s", path, exc)
        return matches
    except Exception as exc:
        logging.error("YARA failed for %s: %s", path, exc)
        return None


def _yara_severity(matches) -> str:
    if not matches:
        return ""
    try:
        from security.yara_scanner import get_highest_severity
        return get_highest_severity(matches)
    except Exception:
        rank = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        highest = ""
        for item in matches if isinstance(matches, (list, tuple, set)) else [matches]:
            value = item.get("severity", "") if isinstance(item, dict) else getattr(item, "severity", "")
            value = str(value).lower()
            if rank.get(value, 0) > rank.get(highest, 0):
                highest = value
        return highest


def _ml_confidence(path: str, yara_matches=None) -> float:
    try:
        from ml_security import security_ml
        return float(security_ml.file_anomaly_confidence(path, yara_matches=yara_matches))
    except Exception:
        return 0.0


def _contain(path: str, reason: str) -> tuple[bool, str]:
    try:
        from security.verified_quarantine import quarantine_and_verify
        ok = bool(quarantine_and_verify(path, reason=reason))
        return ok, "verified_quarantine"
    except Exception:
        try:
            from quarantine_utils import quarantine_file
            quarantine_file(path, reason=reason)
            return not os.path.exists(path), "quarantine_utils"
        except Exception as exc:
            return False, str(exc)


def scan_file(path: str, *, quarantine: bool = True) -> Dict[str, object]:
    """Scan one file; broad rules are weak evidence until independently corroborated."""
    path = os.path.abspath(path)
    research_asset = _is_security_rule_asset(path)
    evidence = analyze_file(path)
    static = analyze_static_file(path)
    all_matches = _yara(path) or []
    ml_confidence = _ml_confidence(path, yara_matches=all_matches)

    # Correlate independent static-analysis helpers with the behavioral
    # detector. Entropy/import evidence is never proof by itself.
    static_signals = static.get("behavioral_signals", {})
    static_score = 0.0
    for value in static_signals.values():
        try:
            static_score = max(static_score, float(value) * 100.0)
        except (TypeError, ValueError):
            continue

    behavior = behavior_signals(
        events=[path],
        persistence_values=[path, *evidence.indicators],
    )
    correlated_behavior = dict(evidence.categories)
    if behavior.get("ransomware", 0.0) > 0:
        correlated_behavior["ransomware_behavior"] = behavior["ransomware"]
    if behavior.get("persistence", 0.0) > 0:
        correlated_behavior["persistence_behavior"] = behavior["persistence"]

    # Broad/noisy rules are still executed and retained. They only become
    # decision-grade when independent behavior/ML evidence supports them.
    from security.adaptive_yara_gate import filter_for_decision, explain
    decision_matches = filter_for_decision(
        all_matches,
        behavioral_score=evidence.score,
        ml_confidence=ml_confidence,
        code_analysis_score=static_score,
        confirmed=evidence.suspicious,
    )
    yara_severity = _yara_severity(decision_matches)

    # Dynamic reputation learns from outcomes. A clean/unconfirmed file makes
    # repeated broad matches more suppressible; confirmed malware immediately
    # gives matching rules a chance to return to the active set.
    if evidence.suspicious:
        from security.adaptive_yara_gate import record_confirmed_malware
        record_confirmed_malware(all_matches)
    elif all_matches:
        from security.adaptive_yara_gate import record_clean_matches
        record_clean_matches(all_matches)

    try:
        from threat_level_engine import score_threat
        threat = score_threat(
            path,
            yara_severity=yara_severity,
            yara_matches=decision_matches,
            ml_confidence=ml_confidence,
            code_analysis_score=static_score,
            behavioral_signals={
                **{f"category_{k}": min(100.0, float(v) * 25.0) for k, v in evidence.categories.items()},
                **{k: float(v) * 100.0 for k, v in behavior.items() if isinstance(v, (int, float))},
            },
            behavior_score=evidence.score,
            confirmed=evidence.suspicious,
        )
    except Exception:
        threat = {"level": yara_severity or "low", "score": 0.0}

    decision = quarantine_decision(
        evidence,
        yara_severity=yara_severity,
        ml_confidence=ml_confidence,
        antivirus_confirmed=False,
    )
    independent_decision = (
        quarantine_decision(evidence, yara_severity="", ml_confidence=ml_confidence, antivirus_confirmed=False)
        if research_asset else decision
    )

    rule_stats = explain(all_matches)
    result: Dict[str, object] = {
        "path": path,
        "sha256": evidence.sha256,
        "size": evidence.size,
        "extension": evidence.extension,
        "magic": evidence.magic,
        "entropy": evidence.entropy,
        "static_entropy": static.get("entropy", {}),
        "suspicious_strings": static.get("strings", []),
        "pe_imports": static.get("imports", {}),
        "printable_ratio": evidence.printable_ratio,
        "behavioral_score": evidence.score,
        "behavioral_confidence": evidence.confidence,
        "behavioral_categories": correlated_behavior,
        "yara_behavior": behavior,
        "static_behavioral_signals": static_signals,
        "code_analysis_score": static_score,
        "indicators": evidence.indicators,
        "yara_severity": yara_severity,
        "yara_matches": len(decision_matches),
        "yara_matches_observed": len(all_matches),
        "yara_broad_matches": rule_stats["broad"],
        "yara_suppressed_matches": rule_stats["suppressed"],
        "ml_confidence": ml_confidence,
        "threat_level": threat.get("level", "low"),
        "threat_score": threat.get("score", 0.0),
        "server_context": evidence.server_context,
        "security_research_asset": research_asset,
        "research_asset_yara_only": bool(research_asset and decision["quarantine"] and not independent_decision["quarantine"]),
        "quarantine": False,
        "quarantine_verified": False,
        "status": "clean_or_uncorroborated",
    }

    if quarantine and independent_decision["quarantine"]:
        ok, method = _contain(path, "corroborated multi-signal malware detection")
        result["quarantine"] = ok
        result["quarantine_verified"] = ok and not os.path.exists(path)
        result["containment_method"] = method
        result["status"] = "quarantined" if result["quarantine_verified"] else "containment_unverified"
    elif research_asset and (evidence.suspicious or all_matches):
        result["status"] = "security_research_asset_review"
    elif evidence.suspicious or all_matches:
        result["status"] = "suspicious_review_or_corroboration"
    return result


def scan_target(target: str, *, quarantine: bool = True) -> List[Dict[str, object]]:
    results: List[Dict[str, object]] = []
    target = os.path.abspath(target)
    if not os.path.exists(target):
        return [{"path": target, "status": "scan_error", "error": "target does not exist"}]
    for path in iter_files(target):
        try:
            results.append(scan_file(path, quarantine=quarantine))
        except (PermissionError, OSError) as exc:
            results.append({"path": path, "status": "scan_error", "error": str(exc)})
        except Exception as exc:
            logging.exception("Unexpected scan failure for %s", path)
            results.append({"path": path, "status": "scan_error", "error": str(exc)})
    return results
