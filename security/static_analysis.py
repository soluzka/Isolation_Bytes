"""Lightweight static-analysis helpers for files that evade simple signatures."""
from __future__ import annotations

import math
import os
import re
from collections import Counter
from typing import Any, Dict, List


SUSPICIOUS_STRING_PATTERNS = [
    re.compile(rb'powershell(?:\.exe)?\s+[^\r\n]{0,200}(?:-enc|-encodedcommand|-nop|-w\s+hidden)', re.I),
    re.compile(rb'(?:invoke-expression|downloadstring|frombase64string|rundll32|regsvr32)', re.I),
    re.compile(rb'(?:schtasks|wmic|bitsadmin|certutil|mshta|reg\s+add)', re.I),
    re.compile(rb'(?:vssadmin|wmic[^\r\n]{0,100}shadowcopy[^\r\n]{0,100}delete)', re.I),
]


def calculate_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum((n / length) * math.log2(n / length) for n in counts.values())


def entropy_analysis(path: str, chunk_size: int = 1024 * 1024) -> Dict[str, Any]:
    """Calculate file entropy and flag unusually high-entropy executable files."""
    size = os.path.getsize(path)
    sample = bytearray()
    with open(path, 'rb') as handle:
        sample.extend(handle.read(min(chunk_size, size)))
    entropy = calculate_entropy(bytes(sample))
    extension = os.path.splitext(path)[1].lower()
    executable = extension in {'.exe', '.dll', '.sys', '.scr', '.com', '.cpl', '.ocx'}
    return {
        'entropy': round(entropy, 4),
        'sample_size': len(sample),
        'high_entropy': entropy >= 7.2,
        'executable': executable,
        'packing_suspected': executable and entropy >= 7.2,
    }


def extract_suspicious_strings(path: str, max_strings: int = 200) -> List[str]:
    """Extract printable ASCII/UTF-16 strings matching malware-relevant patterns."""
    with open(path, 'rb') as handle:
        data = handle.read(8 * 1024 * 1024)
    hits = []
    for pattern in SUSPICIOUS_STRING_PATTERNS:
        for match in pattern.finditer(data):
            value = match.group(0)[:512]
            try:
                text = value.decode('utf-8', errors='ignore').strip()
            except Exception:
                text = repr(value)
            if text and text not in hits:
                hits.append(text)
                if len(hits) >= max_strings:
                    return hits
    return hits


def analyze_pe_imports(path: str) -> Dict[str, Any]:
    """Inspect PE imports when pefile is available; safely no-op for other files."""
    result = {'is_pe': False, 'imports': [], 'suspicious_imports': []}
    try:
        import pefile
        pe = pefile.PE(path, fast_load=True)
        result['is_pe'] = True
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']])
        suspicious = {
            'VirtualAlloc', 'VirtualProtect', 'WriteProcessMemory', 'CreateRemoteThread',
            'NtWriteVirtualMemory', 'NtCreateThreadEx', 'WinExec', 'ShellExecuteA',
            'ShellExecuteW', 'URLDownloadToFileA', 'URLDownloadToFileW', 'WinHttpOpen',
            'InternetOpenUrlA', 'InternetOpenUrlW', 'RegSetValueExA', 'RegSetValueExW',
            'CreateServiceA', 'CreateServiceW', 'OpenSCManagerA', 'OpenSCManagerW',
        }
        for entry in getattr(pe, 'DIRECTORY_ENTRY_IMPORT', []):
            dll = entry.dll.decode(errors='ignore') if entry.dll else ''
            for imported in entry.imports:
                name = imported.name.decode(errors='ignore') if imported.name else ''
                result['imports'].append({'dll': dll, 'name': name})
                if name in suspicious:
                    result['suspicious_imports'].append({'dll': dll, 'name': name})
        pe.close()
    except Exception:
        return result
    return result


def analyze_file(path: str) -> Dict[str, Any]:
    """Return normalized static-analysis signals for the threat engine."""
    entropy = entropy_analysis(path)
    strings = extract_suspicious_strings(path)
    imports = analyze_pe_imports(path)
    behavior = {}
    if entropy['packing_suspected']:
        behavior['packed_executable'] = 0.75
    if strings:
        behavior['suspicious_strings'] = min(1.0, 0.25 + 0.10 * len(strings))
    if imports['suspicious_imports']:
        behavior['suspicious_imports'] = min(1.0, 0.30 + 0.12 * len(imports['suspicious_imports']))
    return {
        'entropy': entropy,
        'strings': strings,
        'imports': imports,
        'behavioral_signals': behavior,
    }
