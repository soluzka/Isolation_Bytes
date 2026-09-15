"""Safe static code analysis for YARA/ML correlation.

This module is intentionally additive: it never executes inspected code and it
never changes the existing YARA scanner's decision by itself.  It produces a
small, stable feature vector from file structure, imports/strings, entropy,
and source-code indicators so the ML layer can use evidence from the same file
that YARA inspected.
"""
from __future__ import annotations

import ast
import hashlib
import math
import os
import re
import struct
from typing import Any, Dict, Iterable, List, Tuple


MAX_ANALYSIS_BYTES = 5 * 1024 * 1024
_ENTROPY_BUCKETS = 16


# Deliberately conservative indicators.  These are evidence, not verdicts.
_CODE_PATTERNS = {
    "process_exec": re.compile(r"\b(?:subprocess\.(?:Popen|run|call)|os\.system|CreateProcess|WinExec)\b", re.I),
    "memory_injection": re.compile(r"\b(?:VirtualAlloc(?:Ex)?|WriteProcessMemory|CreateRemoteThread|ptrace)\b", re.I),
    "credential_access": re.compile(r"\b(?:sekurlsa|lsass|LogonUser|CredRead|keyring)\b", re.I),
    "persistence": re.compile(r"\b(?:RunOnce|CurrentVersion\\Run|schtasks|crontab|systemctl\s+enable|Startup)\b", re.I),
    "network_c2": re.compile(r"\b(?:socket\.socket|requests\.(?:get|post)|urllib\.request|WinHttp|InternetOpen|WebClient)\b", re.I),
    "dynamic_code": re.compile(r"\b(?:eval|exec|compile|__import__|base64\.(?:b64decode|decodebytes))\b", re.I),
    "web_execution": re.compile(r"(?:cmd\.exe|powershell(?:\.exe)?|/bin/(?:sh|bash)|Runtime\.getRuntime\(\))", re.I),
}


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    length = float(len(data))
    return -sum((count / length) * math.log2(count / length) for count in counts if count)


def _string_stats(data: bytes) -> Tuple[int, int, int]:
    ascii_strings = re.findall(rb"[\x20-\x7e]{5,}", data)
    utf16_strings = re.findall(rb"(?:[\x20-\x7e]\x00){4,}", data)
    suspicious = 0
    for value in ascii_strings + utf16_strings:
        text = value.decode("utf-8", errors="ignore")
        if any(pattern.search(text) for pattern in _CODE_PATTERNS.values()):
            suspicious += 1
    return len(ascii_strings), len(utf16_strings), suspicious


def _pe_import_count(data: bytes) -> int:
    """Best-effort PE import count without loading or executing the binary."""
    if len(data) < 64 or data[:2] != b"MZ":
        return 0
    try:
        pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
        if pe_offset + 24 > len(data) or data[pe_offset:pe_offset + 4] != b"PE\x00\x00":
            return 0
        optional_offset = pe_offset + 24
        magic = struct.unpack_from("<H", data, optional_offset)[0]
        data_dir_offset = optional_offset + (112 if magic == 0x20B else 96)
        if data_dir_offset + 16 > len(data):
            return 0
        import_rva, import_size = struct.unpack_from("<II", data, data_dir_offset + 8)
        if not import_rva or not import_size:
            return 0
        # We intentionally only expose a bounded presence/count signal here;
        # resolving RVAs requires a full PE parser and is outside this safe,
        # lightweight feature extractor.
        return 1
    except (IndexError, struct.error, ValueError):
        return 0


def _python_ast_features(data: bytes) -> Dict[str, int]:
    try:
        source = data.decode("utf-8", errors="strict")
        tree = ast.parse(source)
    except (UnicodeDecodeError, SyntaxError, ValueError, MemoryError):
        return {"ast_imports": 0, "ast_calls": 0, "ast_dynamic": 0}

    imports = 0
    calls = 0
    dynamic = 0
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            imports += 1
        elif isinstance(node, ast.Call):
            calls += 1
            if isinstance(node.func, ast.Name) and node.func.id in {"eval", "exec", "compile", "__import__"}:
                dynamic += 1
    return {"ast_imports": imports, "ast_calls": calls, "ast_dynamic": dynamic}


def analyze_file(filepath: str) -> Dict[str, Any]:
    """Return bounded static-analysis evidence for *filepath*.

    The function is read-only and never imports, parses, or executes the target
    as a program.  Large files are sampled from the beginning and end so the
    feature extractor cannot become a hidden file-size bottleneck.
    """
    result: Dict[str, Any] = {
        "path": os.path.abspath(filepath),
        "extension": os.path.splitext(filepath)[1].lower(),
        "size": 0,
        "sha256": "",
        "entropy": 0.0,
        "ascii_strings": 0,
        "utf16_strings": 0,
        "suspicious_strings": 0,
        "pe_import_present": 0,
        "signals": {},
        "ast_imports": 0,
        "ast_calls": 0,
        "ast_dynamic": 0,
    }

    try:
        result["size"] = os.path.getsize(filepath)
        with open(filepath, "rb") as handle:
            if result["size"] <= MAX_ANALYSIS_BYTES:
                data = handle.read(MAX_ANALYSIS_BYTES)
            else:
                head = handle.read(MAX_ANALYSIS_BYTES // 2)
                handle.seek(max(0, result["size"] - MAX_ANALYSIS_BYTES // 2))
                data = head + handle.read(MAX_ANALYSIS_BYTES // 2)
    except (OSError, IOError):
        return result

    result["sha256"] = hashlib.sha256(data).hexdigest()
    result["entropy"] = round(_entropy(data), 4)
    ascii_count, utf16_count, suspicious_count = _string_stats(data)
    result["ascii_strings"] = ascii_count
    result["utf16_strings"] = utf16_count
    result["suspicious_strings"] = suspicious_count
    result["pe_import_present"] = _pe_import_count(data)
    result.update(_python_ast_features(data))

    text = data.decode("utf-8", errors="ignore")
    for name, pattern in _CODE_PATTERNS.items():
        result["signals"][name] = int(bool(pattern.search(text)))

    return result


def to_ml_features(analysis: Dict[str, Any]) -> List[float]:
    """Convert analysis evidence to a stable numeric vector for ML fusion."""
    signals = analysis.get("signals", {}) or {}
    return [
        float(analysis.get("size", 0)),
        float(analysis.get("entropy", 0.0)),
        float(analysis.get("ascii_strings", 0)),
        float(analysis.get("utf16_strings", 0)),
        float(analysis.get("suspicious_strings", 0)),
        float(analysis.get("pe_import_present", 0)),
        float(analysis.get("ast_imports", 0)),
        float(analysis.get("ast_calls", 0)),
        float(analysis.get("ast_dynamic", 0)),
        *[float(bool(signals.get(name))) for name in sorted(_CODE_PATTERNS)],
    ]
