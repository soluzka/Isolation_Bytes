"""Unlimited standalone-agent entrypoint.

The scanner itself remains in standalone_agent.py. This entrypoint removes the
artificial per-cycle file/time ceilings before starting the real agent, so both
source runs and packaged builds can scan until the discovered scan work is
finished instead of stopping at an arbitrary count or duration.
"""

import standalone_agent as _agent
from security.warning_enforcer import start_warning_enforcement

# The scanner loop already supports an unbounded value: its comparisons are
# against these module globals. Infinity keeps the existing control flow safe
# without introducing a new file-count or elapsed-time limit.
_agent.MAX_FILES_PER_SCAN = float('inf')
_agent.MAX_SCAN_CYCLE_SECONDS = float('inf')

# Explicitly start detector-driven firewall enforcement. Do not rely on
# Python's optional sitecustomize startup hook; PyInstaller does not guarantee
# that hook is imported in the frozen application.
start_warning_enforcement()


if __name__ == '__main__':
    _agent.main()
