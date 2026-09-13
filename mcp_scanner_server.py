"""
mcp_scanner_server.py

MCP server exposing MalwareScanner as tools callable from Claude Desktop
(or any MCP client). Review this fully before running or connecting it —
it executes file-system scans when its tools are invoked.

Suggested location: my_mcp_server/server.py (or wherever your MCP project lives)

Requires:
    pip install "mcp[cli]" yara-python

Run standalone for testing:
    uv run mcp_scanner_server.py

Test interactively:
    mcp dev mcp_scanner_server.py
"""

from __future__ import annotations

import sys
from pathlib import Path

from mcp.server.fastmcp import FastMCP

# Adjust this import path to wherever malware_scanner.py actually lives
# relative to this file once you place both in your project.
sys.path.insert(0, str(Path(__file__).parent))
from malware_scanner import MalwareScanner  # noqa: E402

# Point this at wherever you keep malware_detection_rules.yar in your repo,
# e.g. security/yara_rules relative to the antivirus project root.
RULES_DIR = Path(__file__).parent / "yara_rules"

mcp = FastMCP("isolation-bytes-scanner")

_scanner: MalwareScanner | None = None


def _get_scanner() -> MalwareScanner:
    global _scanner
    if _scanner is None:
        _scanner = MalwareScanner(rules_dir=RULES_DIR)
    return _scanner


@mcp.tool()
def scan_file(file_path: str) -> str:
    """
    Scan a single file for web shells and other malware indicators
    using YARA rules. Returns a JSON summary of any matches found.
    """
    scanner = _get_scanner()
    results = scanner.scan_file(file_path)
    if not results:
        return f"No matches found in {file_path}"
    return scanner.results_to_json(results)


@mcp.tool()
def scan_folder(folder_path: str, recursive: bool = True) -> str:
    """
    Scan every file in a specific folder for malware indicators.
    Use this for a folder you explicitly choose (e.g. a download you
    want checked) rather than a full-system sweep.
    """
    scanner = _get_scanner()
    try:
        results = scanner.scan_directory(folder_path, recursive=recursive)
    except NotADirectoryError as e:
        return str(e)
    if not results:
        return f"No matches found in {folder_path}"
    return scanner.results_to_json(results)


@mcp.tool()
def scan_common_locations() -> str:
    """
    Scan realistic high-risk locations on this machine — Downloads,
    Desktop, Documents, Temp folders, browser caches, and startup
    folders — for web shells and other malware indicators. This is
    intentionally scoped rather than a full-disk scan, to keep runtime
    reasonable and avoid false positives from system files.
    """
    scanner = _get_scanner()
    results = scanner.scan_common_locations()
    if not results:
        return "No matches found in common scan locations."
    return scanner.results_to_json(results)


@mcp.tool()
def list_scan_locations() -> str:
    """
    List the specific folders that scan_common_locations() would check
    on this machine, without actually scanning them. Useful to confirm
    scope before running a scan.
    """
    scanner = _get_scanner()
    locations = scanner.get_common_scan_locations()
    return "\n".join(str(p) for p in locations) or "No valid scan locations found."


if __name__ == "__main__":
    mcp.run()
