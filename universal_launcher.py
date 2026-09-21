#!/usr/bin/env python3
"""Universal launcher for Isolation Bytes agent."""
import sys, os
agent = os.path.join(os.environ.get('LOCALAPPDATA', os.path.expanduser('~')), 'IsolationBytes', 'IsolationBytesAgent.exe')
if not os.path.exists(agent):
    agent = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'IsolationBytesAgent.exe')
os.execv(agent, [agent] + sys.argv[1:])