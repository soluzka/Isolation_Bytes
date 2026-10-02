"""Unlimited standalone-agent entrypoint.

The scanner itself remains in standalone_agent.py. This entrypoint removes the
artificial per-cycle file/time ceilings before starting the real agent, so both
source runs and packaged builds can scan until the discovered scan work is
finished instead of stopping at an arbitrary count or duration.
"""

import standalone_agent as _agent

# The scanner loop already supports an unbounded value: its comparisons are
# against these module globals. Infinity keeps the existing control flow safe
# without introducing a new file-count or elapsed-time limit.
_agent.MAX_FILES_PER_SCAN = float('inf')
_agent.MAX_SCAN_CYCLE_SECONDS = float('inf')


if __name__ == '__main__':
    _agent.main()
