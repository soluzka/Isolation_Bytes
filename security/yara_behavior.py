"""Behavioral indicators complementary to static YARA matches."""
from __future__ import annotations

import os
import re
from typing import Any, Dict, Iterable


RANSOMWARE_EXTENSION_PATTERN = re.compile(r'\.(?:locked|lockbit|encrypted|enc|crypt|crypto|wncry|ryk|akira|clop|blackcat)$', re.I)
SHADOW_COPY_PATTERNS = (
    re.compile(r'vssadmin(?:\.exe)?\s+delete\s+shadows', re.I),
    re.compile(r'wmic(?:\.exe)?.*shadowcopy.*delete', re.I),
    re.compile(r'wmic(?:\.exe)?.*shadowcopy.*call\s+delete', re.I),
    re.compile(r'Get-WmiObject.*Win32_ShadowCopy.*Remove', re.I),
)
PERSISTENCE_PATTERNS = (
    re.compile(r'\\Run(?:Once)?\\', re.I),
    re.compile(r'\\CurrentVersion\\Run(?:Once)?', re.I),
    re.compile(r'\\Microsoft\\Windows\\Start Menu\\Programs\\Startup', re.I),
    re.compile(r'\\Services\\', re.I),
    re.compile(r'schtasks(?:\.exe)?\s+/create', re.I),
    re.compile(r'New-Service\b', re.I),
)


def ransomware_behavior(events: Iterable[Any]) -> Dict[str, Any]:
    """Score extension-change and shadow-copy deletion activity."""
    extension_changes = 0
    shadow_deletes = 0
    for event in events or []:
        text = str(event.get('command', event) if isinstance(event, dict) else event)
        if RANSOMWARE_EXTENSION_PATTERN.search(text):
            extension_changes += 1
        if any(pattern.search(text) for pattern in SHADOW_COPY_PATTERNS):
            shadow_deletes += 1
    score = min(1.0, (0.15 * min(extension_changes, 4)) + (0.55 if shadow_deletes else 0.0))
    return {
        'extension_changes': extension_changes,
        'shadow_copy_deletions': shadow_deletes,
        'score': score,
        'confirmed_ransomware_behavior': shadow_deletes > 0 and extension_changes > 0,
    }


def persistence_markers(values: Iterable[Any]) -> Dict[str, Any]:
    hits = []
    for value in values or []:
        text = str(value)
        if any(pattern.search(text) for pattern in PERSISTENCE_PATTERNS):
            if text not in hits:
                hits.append(text)
    return {
        'matches': hits,
        'score': min(1.0, 0.25 * len(hits)),
        'persistence_detected': bool(hits),
    }


def behavior_signals(events=None, persistence_values=None) -> Dict[str, float]:
    ransomware = ransomware_behavior(events or [])
    persistence = persistence_markers(persistence_values or [])
    return {
        'ransomware': ransomware['score'],
        'persistence': persistence['score'],
        'confirmed_ransomware': 1.0 if ransomware['confirmed_ransomware_behavior'] else 0.0,
    }
