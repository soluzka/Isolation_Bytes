"""Adaptive YARA rule reputation system.

Automatically suppresses (adds to the noisy set) YARA rules that match
known-clean files, and unsuppresses (removes from the noisy set) rules
that later match confirmed malware.  This "goes back and forth" so a
rule that is noisy today can be re-enabled tomorrow if real malware
starts triggering it, and vice-versa.

State is persisted in ``yara_rule_reputation.json`` next to the scanner
so suppression decisions survive restarts and are shared between the
local agent, the folder watcher, the conditional startup scanner, and
the cloud server.

Public API:
    get_suppressed_rules() -> set[str]
        Rules currently suppressed (union of static NOISY_RULE_NAMES
        and the dynamic set).

    is_suppressed(rule_name) -> bool
        Fast check used by scan_file_with_yara().

    record_clean_hit(rule_name)
        Called when a rule matches a known-clean file.  Increments
        clean_hits; auto-suppresses after CLEAN_HIT_SUPPRESS_THRESHOLD.

    record_malware_hit(rule_name)
        Called when a rule matches a file confirmed as malware by an
        independent signal (hash signature, VirusTotal, ML model).
        Increments malware_hits; auto-unsuppresses immediately so the
        rule can fire again.

    run_auto_evaluation(scan_fn, clean_files=None)
        Scan a set of known-clean files with the loaded YARA rules and
        call record_clean_hit() for every match.  This is the main
        "automatic add to noisy" entry point.

    confirm_malware_hit(rule_names)
        Called after a file is confirmed malware; calls
        record_malware_hit() for each rule that matched it.

    get_reputation_report() -> dict
        Returns the full reputation state for the dashboard / UI.
"""

import os
import sys
import json
import time
import threading
import logging

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Suppress a rule after this many clean-file hits with zero malware hits.
CLEAN_HIT_SUPPRESS_THRESHOLD = int(os.environ.get('YARA_REPUTATION_SUPPRESS_THRESHOLD', '3'))

# Unsuppress a rule immediately when a confirmed malware hit arrives,
# *unless* the rule has this many clean hits relative to malware hits.
# Default: if clean_hits >= 2 * malware_hits, keep suppressed even on a
# single malware hit (could be a fluke).  A second malware hit will
# always unsuppress (malware_hits >= 2 check) regardless of ratio.
MALWARE_HIT_UNSUPPRESS_RATIO = float(os.environ.get('YARA_REPUTATION_UNSUPPRESS_RATIO', '2.0'))

# How often (seconds) the auto-evaluation should run.  0 = run only on
# startup / when explicitly called.
AUTO_EVAL_INTERVAL = int(os.environ.get('YARA_REPUTATION_EVAL_INTERVAL', '3600'))

# State file location
if getattr(sys, 'frozen', False):
    _BASE_DIR = os.path.dirname(sys.executable)
else:
    _BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATE_FILE = os.path.join(_BASE_DIR, 'yara_rule_reputation.json')

# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------

_lock = threading.RLock()
_state = {
    # rule_name -> {clean_hits, malware_hits, status, last_updated, suppressed_at}
    'rules': {},
    'last_evaluation': None,
    'version': 1,
}
_auto_eval_thread = None
_auto_eval_stop = threading.Event()


def _load():
    """Load persisted state from disk."""
    global _state
    try:
        if os.path.exists(STATE_FILE):
            with open(STATE_FILE, 'r', encoding='utf-8') as f:
                loaded = json.load(f)
            if isinstance(loaded, dict) and 'rules' in loaded:
                with _lock:
                    _state = loaded
                logging.info(f"Loaded rule reputation state: {len(_state.get('rules', {}))} rules tracked")
    except Exception as e:
        logging.warning(f"Could not load rule reputation state: {e}")


def _save():
    """Persist state to disk."""
    try:
        with _lock:
            snapshot = json.loads(json.dumps(_state))  # deep copy
        with open(STATE_FILE, 'w', encoding='utf-8') as f:
            json.dump(snapshot, f, indent=2)
    except Exception as e:
        logging.warning(f"Could not save rule reputation state: {e}")


def _ensure_rule(rule_name):
    """Get or create the reputation entry for a rule."""
    if rule_name not in _state['rules']:
        _state['rules'][rule_name] = {
            'clean_hits': 0,
            'malware_hits': 0,
            'status': 'active',  # 'active' or 'suppressed'
            'last_updated': time.time(),
            'suppressed_at': None,
        }
    return _state['rules'][rule_name]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def get_suppressed_rules():
    """Return the set of dynamically-suppressed rule names."""
    with _lock:
        return {
            name for name, info in _state.get('rules', {}).items()
            if info.get('status') == 'suppressed'
        }


def is_suppressed(rule_name):
    """Fast check: is this rule currently suppressed?"""
    with _lock:
        info = _state.get('rules', {}).get(rule_name)
        return info is not None and info.get('status') == 'suppressed'


def record_clean_hit(rule_name):
    """Record that *rule_name* matched a known-clean file.

    Auto-suppresses after CLEAN_HIT_SUPPRESS_THRESHOLD clean hits if the
    rule has zero malware hits.
    """
    with _lock:
        info = _ensure_rule(rule_name)
        info['clean_hits'] = info.get('clean_hits', 0) + 1
        info['last_updated'] = time.time()
        if (info['status'] == 'active'
                and info['clean_hits'] >= CLEAN_HIT_SUPPRESS_THRESHOLD
                and info.get('malware_hits', 0) == 0):
            info['status'] = 'suppressed'
            info['suppressed_at'] = time.time()
            logging.info(
                f"[rule_reputation] Auto-suppressed noisy rule "
                f"'{rule_name}' after {info['clean_hits']} clean hits"
            )
    _save()


def record_malware_hit(rule_name):
    """Record that *rule_name* matched a file confirmed as malware.

    Auto-unsuppresses the rule immediately unless the clean-to-malware
    ratio is overwhelmingly high (suggesting the malware hit was a fluke).
    A second confirmed malware hit will always unsuppress.
    """
    with _lock:
        info = _ensure_rule(rule_name)
        info['malware_hits'] = info.get('malware_hits', 0) + 1
        info['last_updated'] = time.time()
        if info['status'] == 'suppressed':
            clean = info.get('clean_hits', 0)
            malware = info.get('malware_hits', 0)
            # Unsuppress unless clean hits vastly outnumber malware hits
            if malware >= 2 or clean < MALWARE_HIT_UNSUPPRESS_RATIO * malware:
                info['status'] = 'active'
                info['suppressed_at'] = None
                logging.info(
                    f"[rule_reputation] Auto-unsuppressed rule "
                    f"'{rule_name}' after {malware} malware hit(s) "
                    f"(clean: {clean})"
                )
            else:
                logging.info(
                    f"[rule_reputation] Rule '{rule_name}' got a malware hit "
                    f"but remains suppressed (clean={clean}, malware={malware})"
                )
    _save()


def confirm_malware_hit(rule_names):
    """Call record_malware_hit() for each rule that matched a confirmed
    malware file.  *rule_names* is an iterable of rule name strings."""
    for name in rule_names:
        try:
            record_malware_hit(name)
        except Exception as e:
            logging.warning(f"[rule_reputation] confirm_malware_hit('{name}'): {e}")


def get_reputation_report():
    """Return the full reputation state for the dashboard / UI."""
    with _lock:
        rules = {}
        for name, info in _state.get('rules', {}).items():
            rules[name] = dict(info)
        return {
            'rules': rules,
            'last_evaluation': _state.get('last_evaluation'),
            'suppress_threshold': CLEAN_HIT_SUPPRESS_THRESHOLD,
            'unsuppress_ratio': MALWARE_HIT_UNSUPPRESS_RATIO,
            'total_suppressed': sum(
                1 for r in rules.values() if r.get('status') == 'suppressed'
            ),
        }


def manually_suppress(rule_name):
    """Manually suppress a rule (e.g. from the dashboard)."""
    with _lock:
        info = _ensure_rule(rule_name)
        info['status'] = 'suppressed'
        info['suppressed_at'] = time.time()
        info['last_updated'] = time.time()
    _save()


def manually_unsuppress(rule_name):
    """Manually unsuppress a rule (e.g. from the dashboard)."""
    with _lock:
        info = _ensure_rule(rule_name)
        info['status'] = 'active'
        info['suppressed_at'] = None
        info['last_updated'] = time.time()
    _save()


# ---------------------------------------------------------------------------
# Auto-evaluation
# ---------------------------------------------------------------------------

def _default_clean_files():
    """Return a list of files that are known to be clean and can be used
    to test rules for false positives.  Uses project source files and
    common system files that should never match malware rules."""
    clean = []
    # Project source files (the scanner's own code is a great clean set)
    candidates = [
        os.path.join(_BASE_DIR, 'app.py'),
        os.path.join(_BASE_DIR, 'README.md'),
        os.path.join(_BASE_DIR, 'requirements.txt'),
        os.path.join(_BASE_DIR, '.gitignore'),
        os.path.join(_BASE_DIR, 'quarantine_utils.py'),
        os.path.join(_BASE_DIR, 'build_config.py'),
        os.path.join(_BASE_DIR, 'standalone_agent.py'),
        os.path.join(_BASE_DIR, 'folder_watcher.py'),
        os.path.join(_BASE_DIR, 'conditional_startup.py'),
        os.path.join(_BASE_DIR, 'security', 'yara_scanner.py'),
        os.path.join(_BASE_DIR, 'security', 'detector.py'),
        os.path.join(_BASE_DIR, 'security', 'rule_reputation.py'),
        os.path.join(_BASE_DIR, 'cloud', 'cloud_server.py'),
        os.path.join(_BASE_DIR, 'utils', 'paths.py'),
    ]
    for c in candidates:
        if os.path.isfile(c) and os.path.getsize(c) < 5 * 1024 * 1024:
            clean.append(c)

    # Common system files that should never match
    for extra in [
        os.path.expanduser('~/.gitconfig'),
        os.path.expanduser('~/.bashrc'),
        os.path.join(os.environ.get('SYSTEMROOT', r'C:\Windows'), 'System32', 'notepad.exe'),
        os.path.join(os.environ.get('SYSTEMROOT', r'C:\Windows'), 'System32', 'calc.exe'),
    ]:
        if os.path.isfile(extra) and os.path.getsize(extra) < 5 * 1024 * 1024:
            clean.append(extra)

    return clean


def run_auto_evaluation(scan_fn=None, clean_files=None, timeout=10):
    """Scan known-clean files and record clean hits for every matching rule.

    Args:
        scan_fn: callable(filepath) -> list of yara.Match objects.
                 If None, uses security.yara_scanner.scan_file_with_yara.
        clean_files: list of clean file paths to scan.  If None, uses
                     _default_clean_files().
        timeout: YARA scan timeout per file.

    Returns:
        dict with summary stats: {files_scanned, rules_flagged, newly_suppressed}
    """
    if scan_fn is None:
        from security.yara_scanner import scan_file_with_yara as scan_fn
    if clean_files is None:
        clean_files = _default_clean_files()

    stats = {
        'files_scanned': 0,
        'rules_flagged': {},
        'newly_suppressed': [],
    }

    for cf in clean_files:
        if not os.path.isfile(cf):
            continue
        try:
            matches = scan_fn(cf, timeout=timeout)
        except Exception as e:
            logging.debug(f"[rule_reputation] Error scanning clean file {cf}: {e}")
            continue
        stats['files_scanned'] += 1
        if not matches:
            continue
        for m in matches:
            rname = getattr(m, 'rule', '?')
            stats['rules_flagged'][rname] = stats['rules_flagged'].get(rname, 0) + 1
            # Check status before recording so we can detect newly-suppressed
            with _lock:
                was_active = (_state.get('rules', {}).get(rname, {}).get('status', 'active') == 'active')
            record_clean_hit(rname)
            with _lock:
                is_now_suppressed = (_state.get('rules', {}).get(rname, {}).get('status') == 'suppressed')
            if was_active and is_now_suppressed:
                stats['newly_suppressed'].append(rname)

    with _lock:
        _state['last_evaluation'] = time.strftime('%Y-%m-%d %H:%M:%S')
    _save()

    logging.info(
        f"[rule_reputation] Auto-evaluation complete: "
        f"{stats['files_scanned']} clean files scanned, "
        f"{len(stats['rules_flagged'])} rules flagged, "
        f"{len(stats['newly_suppressed'])} newly suppressed"
    )
    return stats


def _auto_eval_loop():
    """Background loop that runs run_auto_evaluation() periodically."""
    while not _auto_eval_stop.is_set():
        try:
            run_auto_evaluation()
        except Exception as e:
            logging.warning(f"[rule_reputation] Auto-evaluation failed: {e}")
        # Wait for the interval, but check stop event every second
        waited = 0
        while waited < AUTO_EVAL_INTERVAL and not _auto_eval_stop.is_set():
            time.sleep(1)
            waited += 1


def start_auto_evaluation():
    """Start the background auto-evaluation thread (idempotent)."""
    global _auto_eval_thread
    if _auto_eval_thread is not None and _auto_eval_thread.is_alive():
        return
    _auto_eval_stop.clear()
    _auto_eval_thread = threading.Thread(
        target=_auto_eval_loop, name='yara-rule-reputation', daemon=True
    )
    _auto_eval_thread.start()
    logging.info("[rule_reputation] Background auto-evaluation started")


def stop_auto_evaluation():
    """Stop the background auto-evaluation thread."""
    _auto_eval_stop.set()
    global _auto_eval_thread
    if _auto_eval_thread is not None:
        _auto_eval_thread.join(timeout=5)
        _auto_eval_thread = None


# ---------------------------------------------------------------------------
# Startup
# ---------------------------------------------------------------------------

# Load state on import
_load()

# Run one evaluation immediately on import (non-blocking in a daemon thread
# so it doesn't slow down startup).  This ensures noisy rules are suppressed
# before the first scan if the state file already has data from a previous run.
# The first full evaluation runs in the background.
if AUTO_EVAL_INTERVAL > 0:
    start_auto_evaluation()
