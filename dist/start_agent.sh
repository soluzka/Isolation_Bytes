#!/usr/bin/env bash
set -euo pipefail
BASE_URL="${ISOLATION_BYTES_SERVER:-https://isolation-bytes.com}"
PAIR_CODE="${ISOLATION_BYTES_PAIR_CODE:-}"
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
AUTO_START=1
BACKGROUND=0
AGENT_ARGS=(--server "$BASE_URL" --auto-start)
while [ "$#" -gt 0 ]; do
    case "$1" in
        --pair-code) [ "$#" -ge 2 ] || exit 2; PAIR_CODE="$2"; shift 2 ;;
        --server) [ "$#" -ge 2 ] || exit 2; BASE_URL="$2"; AGENT_ARGS=(--server "$BASE_URL" --auto-start); shift 2 ;;
        --no-auto-start) AUTO_START=0; AGENT_ARGS=("${AGENT_ARGS[@]/--auto-start}"); shift ;;
        --background) BACKGROUND=1; shift ;;
        *) AGENT_ARGS+=("$1"); shift ;;
    esac
done
AGENT_EXE="${ISOLATION_BYTES_AGENT_EXE:-}"
if [ -z "$AGENT_EXE" ]; then
    for candidate in "$HOME/IsolationBytesAgent" "$HOME/IsolationBytesAgent.exe" "$SCRIPT_DIR/IsolationBytesAgent" "$SCRIPT_DIR/IsolationBytesAgent.exe"; do
        if [ -x "$candidate" ] || [ -f "$candidate" ]; then
            AGENT_EXE="$candidate"
            break
        fi
    done
fi
UNAME_S="$(uname -s 2>/dev/null || true)"
if [ -z "$AGENT_EXE" ] && { case "$UNAME_S" in MINGW*|MSYS*|CYGWIN*) true ;; *) [ -n "${WINDIR:-}" ] ;; esac; }; then
    AGENT_EXE="${LOCALAPPDATA:-$HOME/AppData/Local}/IsolationBytes/IsolationBytesAgent.exe"
    mkdir -p "$(dirname "$AGENT_EXE")"
    if [ ! -f "$AGENT_EXE" ]; then
        echo "IsolationBytesAgent.exe not found. Downloading it..."
        if command -v curl >/dev/null 2>&1; then
            curl --fail --location --silent --show-error "$BASE_URL/download/IsolationBytesAgent.exe" -o "$AGENT_EXE"
        elif command -v wget >/dev/null 2>&1; then
            wget --quiet --output-document="$AGENT_EXE" "$BASE_URL/download/IsolationBytesAgent.exe"
        else
            rm -f "$AGENT_EXE"
        fi
    fi
    [ -f "$AGENT_EXE" ] || AGENT_EXE=""
fi
if [ -n "$AGENT_EXE" ]; then
    [ -n "$PAIR_CODE" ] && AGENT_ARGS+=(--pair-code "$PAIR_CODE")
    if [ "$BACKGROUND" -eq 1 ]; then nohup "$AGENT_EXE" "${AGENT_ARGS[@]}" >/dev/null 2>&1 & exit 0; fi
    exec "$AGENT_EXE" "${AGENT_ARGS[@]}"
fi
if [ -z "${ISOLATION_BYTES_API_KEY:-}" ] && [ ! -f "${HOME}/.config/isolationbytes/cloud_api_key.txt" ] && [ -z "$PAIR_CODE" ]; then
    echo "Isolation Bytes agent is not paired on this device." >&2
    echo "Pass --pair-code CODE or set ISOLATION_BYTES_API_KEY." >&2
    exit 1
fi
PYTHON_BIN="${PYTHON:-python3}"
AGENT_SCRIPT="${ISOLATION_BYTES_AGENT_SCRIPT:-$SCRIPT_DIR/standalone_agent.py}"
if [ ! -f "$AGENT_SCRIPT" ]; then
    AGENT_SCRIPT="$HOME/standalone_agent.py"
    if command -v curl >/dev/null 2>&1; then curl --fail --location --silent --show-error "$BASE_URL/download/standalone_agent.py" -o "$AGENT_SCRIPT"; else wget --quiet --output-document="$AGENT_SCRIPT" "$BASE_URL/download/standalone_agent.py"; fi
fi
[ -f "$AGENT_SCRIPT" ] || { echo "standalone_agent.py not found" >&2; exit 1; }
[ -n "$PAIR_CODE" ] && AGENT_ARGS+=(--pair-code "$PAIR_CODE")
if [ "$BACKGROUND" -eq 1 ]; then nohup "$PYTHON_BIN" "$AGENT_SCRIPT" "${AGENT_ARGS[@]}" >/dev/null 2>&1 & exit 0; fi
exec "$PYTHON_BIN" "$AGENT_SCRIPT" "${AGENT_ARGS[@]}"
