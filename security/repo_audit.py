#!/usr/bin/env python3
"""Repository compromise audit for Isolation Bytes.

This is an evidence collector, not a malware verdict. It inventories files, hashes
source files, flags high-risk execution/persistence/network patterns, and records
findings as JSON. A finding requires review; it is never treated as proof of malware
by itself.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
MAX_FILE = 16 * 1024 * 1024
TEXT_EXTS = {
    ".py", ".ps1", ".psm1", ".bat", ".cmd", ".vbs", ".js", ".ts", ".tsx",
    ".sh", ".yml", ".yaml", ".json", ".toml", ".ini", ".cfg", ".conf",
    ".spec", ".yar", ".yara", ".txt", ".md",
}
SKIP_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__", ".pytest_cache"}

# These are intentionally high-signal patterns. Legitimate security/installer code
# can match them, so the report distinguishes "review" from "critical" evidence.
RULES = [
    ("encoded_powershell", re.compile(r"(?i)(?:powershell(?:\.exe)?[^\n]{0,300}(?:-enc(?:odedcommand)?|frombase64string))"), "review"),
    ("download_execute", re.compile(r"(?i)(?:downloadstring|downloadfile|urlmon|bitsadmin|certutil[^\n]{0,120}(?:url|http)|invoke-webrequest|start-bitstransfer)"), "review"),
    ("process_injection", re.compile(r"(?i)(?:writeprocessmemory|createremotethread|ntwritevirtualmemory|ntcreatethreadex|virtualalloc(?:ex)?|virtualprotect(?:ex)?)"), "review"),
    ("persistence", re.compile(r"(?i)(?:runonce|\\software\\microsoft\\windows\\currentversion\\run|schtasks(?:\.exe)?\s+/create|new-service|createservice(?:a|w)?\b|startup(?: folder)?|system32\\tasks)"), "review"),
    ("credential_or_secret_access", re.compile(r"(?i)(?:lsass|sam\\|security\\|credential(?:s)?\\|sekurlsa|mimikatz|dpapi|browser.*(?:password|cookie))"), "review"),
    ("destructive_command", re.compile(r"(?i)(?:vssadmin[^\n]{0,160}delete|wbadmin[^\n]{0,160}delete|format(?:\.com)?\s+[a-z]:|diskpart[^\n]{0,100}(?:clean|delete))"), "high"),
    ("acl_tampering", re.compile(r"(?i)icacls(?:\.exe)?[^\n]{0,240}(?:/grant|/deny)[^\n]{0,100}(?:system32|advapi32|kernel32|ntdll)"), "high"),
    ("obfuscated_python", re.compile(r"(?i)(?:exec\s*\(|eval\s*\(|__import__\s*\(|marshal\.loads\s*\(|codecs\.decode\s*\([^\n]{0,120}base64)"), "review"),
    ("raw_socket_or_c2", re.compile(r"(?i)(?:socket\.socket|socket\.create_connection|websocket|reverse[_ -]?shell|bind[_ -]?shell)"), "review"),
]

SECRET_RULES = [
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    ("github_token", re.compile(r"gh[pousr]_[A-Za-z0-9_]{20,}")),
    ("cloud_secret", re.compile(r"(?i)(?:aws_access_key_id|aws_secret_access_key|azure[_-]client[_-]secret|client_secret)\s*[:=]\s*['\"][^'\"]{12,}['\"]")),
]


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def iter_files() -> list[Path]:
    files: list[Path] = []
    for base, dirs, names in os.walk(ROOT):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for name in names:
            p = Path(base) / name
            try:
                if p.is_file() and p.stat().st_size <= MAX_FILE:
                    files.append(p)
            except OSError:
                continue
    return sorted(files)


def text_for(path: Path) -> str | None:
    if path.suffix.lower() not in TEXT_EXTS and path.name not in {"Dockerfile", "Makefile"}:
        return None
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return None


def git_context(path: Path) -> dict[str, Any]:
    rel = path.relative_to(ROOT).as_posix()
    result: dict[str, Any] = {"path": rel}
    try:
        out = subprocess.check_output(
            ["git", "log", "-1", "--format=%H|%aI|%an", "--", rel],
            cwd=ROOT, text=True, stderr=subprocess.DEVNULL,
        ).strip()
        if out:
            commit, date, author = out.split("|", 2)
            result.update(last_commit=commit, last_change=date, last_author=author)
    except Exception:
        pass
    return result


def audit() -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    manifest: list[dict[str, Any]] = []
    for path in iter_files():
        rel = path.relative_to(ROOT).as_posix()
        try:
            size = path.stat().st_size
            digest = sha256(path)
        except OSError:
            continue
        manifest.append({"path": rel, "size": size, "sha256": digest})
        text = text_for(path)
        if text is None:
            continue
        for rule, pattern, severity in RULES:
            for match in pattern.finditer(text):
                line = text.count("\n", 0, match.start()) + 1
                findings.append({**git_context(path), "rule": rule, "severity": severity, "line": line, "match": match.group(0)[:300]})
                if len(findings) >= 2000:
                    break
        for rule, pattern in SECRET_RULES:
            match = pattern.search(text)
            if match:
                line = text.count("\n", 0, match.start()) + 1
                findings.append({**git_context(path), "rule": rule, "severity": "critical", "line": line, "match": "REDACTED"})

    high = [f for f in findings if f["severity"] in {"high", "critical"}]
    review = [f for f in findings if f["severity"] == "review"]
    return {
        "schema": "isolation-bytes/repo-audit-v1",
        "root": str(ROOT),
        "files_hashed": len(manifest),
        "findings": findings,
        "summary": {"critical_or_high": len(high), "review": len(review), "total_findings": len(findings)},
        "manifest": manifest,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default="repo-audit.json")
    parser.add_argument("--fail-on-high", action="store_true")
    args = parser.parse_args()
    report = audit()
    output = ROOT / args.output
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report["summary"], sort_keys=True))
    for finding in report["findings"][:50]:
        print(f"{finding['severity']}: {finding['path']}:{finding['line']} {finding['rule']}")
    return 1 if args.fail_on_high and report["summary"]["critical_or_high"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
