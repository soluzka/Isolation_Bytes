#!/bin/bash
# Repair an existing Isolation Bytes VPS without deleting application data.
# Run as root from any directory: bash repair_vps_state.sh

set -u

APP=/opt/antivirus-server
RUNTIME=/root/IsolationBytes
QDIR="$RUNTIME/Quarantine"

if [ ! -d "$APP" ]; then
  echo "ERROR: $APP does not exist."
  exit 1
fi

mkdir -p "$QDIR" "$APP/data"
chmod 700 "$RUNTIME" "$QDIR"

# Create only missing JSON state. Existing data is preserved.
create_json() {
  local path="$1"
  local value="$2"
  if [ ! -f "$path" ]; then
    printf '%s\n' "$value" > "$path"
    echo "created: $path"
  else
    echo "kept:    $path"
  fi
}

create_json "$QDIR/quarantine_log.json" '[]'
create_json "$APP/agents.json" '{}'
create_json "$APP/agent_commands.json" '{}'
create_json "$APP/blocked_ips.json" '{}'
create_json "$APP/blocked_files.json" '{}'
create_json "$APP/scan_results.json" '{}'
create_json "$APP/scan_history.json" '[]'
create_json "$APP/phishing_alerts.json" '[]'
create_json "$APP/iocs.json" '[]'
create_json "$APP/trusted_hashes.json" '{}'
create_json "$APP/yara_rule_reputation.json" '{}'
create_json "$APP/voice_scan_status.json" '{}'
create_json "$APP/scheduled_scan_state.json" '{"enabled": false}'
create_json "$APP/conditional_startup_state.json" '{"running": false, "scanned_files": 0, "quarantined_files": 0, "errors": 0, "process_events": 0, "ml_detections": 0, "ransomware_indicators": 0, "persistence_indicators": 0, "yara_suspicious": 0}'
create_json "$APP/scanner_results.json" '{"scanner_counters": {"scanned_files": 0, "quarantined_files": 0, "errors": 0, "process_events": 0, "ml_detections": 0, "ransomware_indicators": 0, "persistence_indicators": 0, "yara_suspicious": 0}, "scanner_results": {"errors": [], "process_events": [], "ml_detections": [], "ransomware_indicators": [], "persistence_indicators": {}, "yara_suspicious": [], "quarantined_files": []}}'
create_json "$APP/data/scan_cache.json" '{}'

# Ensure the deployed runtime points at the application-owned state directory.
if [ -f "$APP/.env" ]; then
  sed -i '/^ANTIVIRUS_RUNTIME_DIR=/d' "$APP/.env"
  printf 'ANTIVIRUS_RUNTIME_DIR=%s\n' "$RUNTIME" >> "$APP/.env"
fi

# Validate every state file before restarting the service.
"$APP/venv/bin/python" - <<'PY'
import json
from pathlib import Path
files = [
    Path("/root/IsolationBytes/Quarantine/quarantine_log.json"),
    Path("/opt/antivirus-server/agents.json"),
    Path("/opt/antivirus-server/agent_commands.json"),
    Path("/opt/antivirus-server/blocked_ips.json"),
    Path("/opt/antivirus-server/blocked_files.json"),
    Path("/opt/antivirus-server/scan_results.json"),
    Path("/opt/antivirus-server/scan_history.json"),
    Path("/opt/antivirus-server/phishing_alerts.json"),
    Path("/opt/antivirus-server/iocs.json"),
    Path("/opt/antivirus-server/trusted_hashes.json"),
    Path("/opt/antivirus-server/yara_rule_reputation.json"),
    Path("/opt/antivirus-server/voice_scan_status.json"),
    Path("/opt/antivirus-server/scheduled_scan_state.json"),
    Path("/opt/antivirus-server/conditional_startup_state.json"),
    Path("/opt/antivirus-server/data/scan_cache.json"),
]
for p in files:
    with p.open("r", encoding="utf-8") as f:
        json.load(f)
print(f"Validated {len(files)} JSON state files")
PY

cd "$APP"
git fetch --prune origin
git checkout security-v2
git reset --hard origin/security-v2
"$APP/venv/bin/python" -m py_compile quick_start.py conditional_startup.py runtime_paths.py cloud/cloud_server.py cloud/cloud_server_original.py cloud/_agent_results_unlimited.py security/web_auth.py phishing_alerts.py
"$APP/venv/bin/python" -c "import cloud.cloud_server; print('cloud WSGI import: OK')"
"$APP/venv/bin/python" -c "import quick_start; print('quick_start import: OK')"
systemctl restart antivirus-cloud
systemctl restart nginx
sleep 3

if ! systemctl is-active --quiet antivirus-cloud; then
  echo "ERROR: antivirus-cloud is not active"
  journalctl -u antivirus-cloud -n 120 --no-pager
  exit 1
fi

if ! systemctl is-active --quiet nginx; then
  echo "ERROR: nginx is not active"
  systemctl --no-pager --full status nginx
  exit 1
fi

echo "Origin checks:"
curl -fsS --max-time 10 -o /dev/null -w '  / -> HTTP %{http_code}\n' http://127.0.0.1:5002/ || true
curl -fsS --max-time 10 -o /dev/null -w '  /api/config -> HTTP %{http_code}\n' http://127.0.0.1:5002/api/config || true

echo "Deployment state repair complete."
