#!/bin/bash
# Isolation Bytes — Android APK Installer (via adb)
set -e
BASE_URL="${ISOLATION_BYTES_SERVER:-https://isolation-bytes.com}"
echo "Downloading Isolation Bytes APK..."
curl -L "$BASE_URL/download/IsolationBytes-v1.8.950.0.apk" -o /tmp/IsolationBytes-v1.8.950.0.apk
if command -v adb &>/dev/null; then
    echo "Installing via adb..."
    adb install -r /tmp/IsolationBytes-v1.8.950.0.apk
else
    echo "adb not found. APK saved to /tmp/IsolationBytes-v1.8.950.0.apk"
    echo "Transfer to your Android device and install manually."
fi
