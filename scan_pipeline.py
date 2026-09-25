"""Shared file/YARA finding pipeline used by all scanner entry points.

The pipeline deliberately keeps detection separate from remediation: a YARA
match is always normalized into a finding, and a failed quarantine never
removes that finding.
"""
from __future__ import annotations

import hashlib
from typing import Any


def normalize_yara_matches(filepath: str, matches: list[Any]) -> list[dict[str, Any]]:
    """Convert every real YARA match into a dashboard-safe finding."""
    findings = []
    try:
        file_hash = hashlib.sha256()
        with open(filepath, "rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                file_hash.update(chunk)
        digest = file_hash.hexdigest()
    except Exception:
        digest = ""

    for match in matches or []:
        tags = list(getattr(match, "tags", None) or [])
        meta = dict(getattr(match, "meta", None) or {})
        rule = str(getattr(match, "rule", "unknown"))
        namespace = str(getattr(match, "namespace", "default"))
        severity = str(meta.get("severity", "medium")).lower()
        if severity not in {"low", "medium", "high", "critical"}:
            severity = "medium"
        string_matches = []
        for string_match in list(getattr(match, "strings", None) or []):
            try:
                string_matches.append({
                    "identifier": str(getattr(string_match, "identifier", "")),
                    "offset": int(getattr(string_match, "offset", 0)),
                    "data": repr(getattr(string_match, "data", b""))[:512],
                })
            except Exception:
                continue
        findings.append({
            "path": filepath,
            "severity": severity,
            "reason": f"YARA rule matched: {rule}",
            "hash": digest,
            "rule": rule,
            "namespace": namespace,
            "tags": tags,
            "meta": meta,
            "strings": string_matches,
            "threat_type": "yara_match",
            "description": str(meta.get("description", meta.get("Description", "")) or ""),
            "quarantined": False,
            "blocked": False,
        })
    return findings


def scan_file_yara(filepath: str, scanner=None) -> tuple[list[Any], list[dict[str, Any]]]:
    """Run the authoritative YARA scanner and return raw + normalized matches."""
    if scanner is None:
        from security.yara_scanner import scan_file_with_yara
        scanner = scan_file_with_yara
    matches = scanner(filepath) or []
    return matches, normalize_yara_matches(filepath, matches)
