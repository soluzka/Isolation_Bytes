#!/bin/bash
# Isolation Bytes — macOS Installer
set -e
BASE_URL="${ISOLATION_BYTES_SERVER:-https://isolation-bytes.com}"
echo "Downloading Isolation Bytes Agent for macOS..."
curl -L "$BASE_URL/download/IsolationBytesAgent.exe" -o "$HOME/IsolationBytesAgent"
chmod +x "$HOME/IsolationBytesAgent"
echo "Installing agent..."
"$HOME/IsolationBytesAgent" --server "$BASE_URL" --auto-start &
echo "Installation complete!"
