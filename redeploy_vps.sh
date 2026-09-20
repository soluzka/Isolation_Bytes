#!/bin/bash
# Isolation Bytes — Full VPS redeploy script
# Run as root on a fresh Ubuntu 22.04 droplet
# Usage: bash redeploy_vps.sh

set -e

echo "=== Isolation Bytes VPS Redeploy ==="

# 1. System update and dependencies
echo "[1/8] Installing system dependencies..."
apt update -qq
apt install -y build-essential gcc g++ make python3 python3-venv python3-dev python3-pip nginx git pkg-config libffi-dev libssl-dev 2>&1 | tail -3

# 2. Add swap space (4GB to prevent OOM crashes)
echo "[2/8] Adding 4GB swap..."
if ! swapon --show | grep -q swapfile2; then
    fallocate -l 4G /swapfile2
    chmod 600 /swapfile2
    mkswap /swapfile2
    swapon /swapfile2
    echo '/swapfile2 none swap sw 0 0' >> /etc/fstab
fi
# Also ensure original swap exists
if ! swapon --show | grep -q swapfile; then
    fallocate -l 2G /swapfile
    chmod 600 /swapfile
    mkswap /swapfile
    swapon /swapfile
fi
echo "  Swap: $(swapon --show | wc -l) swap devices active"

# 3. Clone the repo
echo "[3/8] Cloning repository..."
if [ -d /opt/antivirus-server ]; then
    cd /opt/antivirus-server
    git fetch --prune origin
    git checkout security-v2
    git reset --hard origin/security-v2
    git clean -fd
else
    cd /opt
    git clone https://github.com/soluzka/Isolation_Bytes.git antivirus-server
    cd antivirus-server
    git checkout security-v2
fi

# 4. Python virtual environment
echo "[4/8] Setting up Python venv..."
python3 -m venv venv
# Disable heavy packages that cause memory issues
sed -i 's/^torch==/#torch==/' requirements.txt 2>/dev/null || true
sed -i 's/^transformers==/#transformers==/' requirements.txt 2>/dev/null || true
sed -i 's/^tokenizers==/#tokenizers==/' requirements.txt 2>/dev/null || true
sed -i 's/^thinc==/#thinc==/' requirements.txt 2>/dev/null || true
sed -i 's/^spacy==/#spacy==/' requirements.txt 2>/dev/null || true
sed -i 's/^llama-cpp-python==/#llama-cpp-python==/' requirements.txt 2>/dev/null || true
sed -i 's/^pyinstaller==/#pyinstaller==/' requirements.txt 2>/dev/null || true
/opt/antivirus-server/venv/bin/pip install --no-cache-dir -r requirements.txt gunicorn 2>&1 | tail -5

# Verify the exact source that will be started before touching the service.
echo "  Deployed commit: $(git rev-parse --short HEAD)"
/opt/antivirus-server/venv/bin/python -m py_compile quick_start.py cloud/cloud_server.py cloud/cloud_server_original.py cloud/_agent_results_unlimited.py
/opt/antivirus-server/venv/bin/python -c "import quick_start; print('  quick_start import: OK')"
/opt/antivirus-server/venv/bin/python -c "import cloud.cloud_server; print('  cloud.cloud_server import: OK')"
/opt/antivirus-server/venv/bin/python -c "import cloud.cloud_server as m; assert getattr(m, 'app', None) is not None; print('  production WSGI app: OK')"

# Conditional Startup counters are generation-scoped. Remove only the shared
# runtime state from the previous deployment; this does not touch quarantine
# data or scan history.
rm -f /root/IsolationBytes/conditional_startup_state.json
rm -f /opt/antivirus-server/conditional_startup_state.json

# 5. Create .env and optionally collect Cloudflare API token
echo "[5/8] Creating .env..."
if [ ! -f /opt/antivirus-server/.env ]; then
    CLOUD_API_KEY=$(python3 -c 'import secrets; print(secrets.token_hex(32))')
    cat > /opt/antivirus-server/.env << EOF
PUBLIC_URL=https://isolation-bytes.com
LICENSE_SERVER=https://isolation-bytes.com
PAYMENT_URL=https://buy.stripe.com/7sY6oBaNqfsk7VrbgM0sU04
CERT_DOMAIN=isolation-bytes.com
# Set this if you run cloud/get_cert.py on the server to renew certificates:
# CLOUDFLARE_API_TOKEN=
BEHIND_PROXY=1
PROXY_PORT=8000
FLASK_PORT=8443
CLOUD_API_KEY=$CLOUD_API_KEY
EOF
fi

# Normalize .env line endings in case it was edited on Windows
if [ -f /opt/antivirus-server/.env ]; then
    sed -i 's/\r$//' /opt/antivirus-server/.env
fi

# Use one application-owned quarantine root on the VPS.  Keep the log
# available even before the first quarantine event so the dashboard never
# fails because the JSON file is missing.
RUNTIME_DIR=/root/IsolationBytes
QUARANTINE_DIR="$RUNTIME_DIR/Quarantine"
mkdir -p "$QUARANTINE_DIR"
chmod 700 "$RUNTIME_DIR" "$QUARANTINE_DIR"
if [ ! -f "$QUARANTINE_DIR/quarantine_log.json" ]; then
    printf '[]\n' > "$QUARANTINE_DIR/quarantine_log.json"
    chmod 600 "$QUARANTINE_DIR/quarantine_log.json"
fi
if ! grep -qE '^ANTIVIRUS_RUNTIME_DIR=' /opt/antivirus-server/.env; then
    printf '\nANTIVIRUS_RUNTIME_DIR=%s\n' "$RUNTIME_DIR" >> /opt/antivirus-server/.env
fi

# Restore all application-owned JSON state files used by the cloud/dashboard.
# Create missing files and repair malformed/truncated JSON. Valid state is kept;
# invalid state is preserved as a timestamped backup before replacement.
ensure_json_state() {
    local path="$1"
    local default_json="$2"
    if [ ! -f "$path" ]; then
        printf '%s\n' "$default_json" > "$path"
        echo "  created: $path"
        return 0
    fi
    if ! /opt/antivirus-server/venv/bin/python - "$path" <<'PY'
import json, sys
with open(sys.argv[1], 'r', encoding='utf-8') as f:
    json.load(f)
PY
    then
        backup="${path}.corrupt-$(date +%Y%m%d-%H%M%S)"
        mv "$path" "$backup"
        printf '%s\n' "$default_json" > "$path"
        echo "  repaired: $path (backup: $backup)"
    fi
}

ensure_json_state "$QUARANTINE_DIR/quarantine_log.json" '[]'
ensure_json_state "/opt/antivirus-server/agents.json" '{}'
ensure_json_state "/opt/antivirus-server/agent_commands.json" '{}'
ensure_json_state "/opt/antivirus-server/blocked_ips.json" '{}'
ensure_json_state "/opt/antivirus-server/blocked_files.json" '{}'
ensure_json_state "/opt/antivirus-server/scan_results.json" '{}'
ensure_json_state "/opt/antivirus-server/scan_history.json" '[]'
ensure_json_state "/opt/antivirus-server/phishing_alerts.json" '[]'
ensure_json_state "/opt/antivirus-server/iocs.json" '[]'
ensure_json_state "/opt/antivirus-server/trusted_hashes.json" '{}'
ensure_json_state "/opt/antivirus-server/yara_rule_reputation.json" '{}'
ensure_json_state "/opt/antivirus-server/voice_scan_status.json" '{}'
ensure_json_state "/opt/antivirus-server/scheduled_scan_state.json" '{"enabled": false}'
ensure_json_state "/opt/antivirus-server/conditional_startup_state.json" '{"running": false, "scanned_files": 0, "quarantined_files": 0, "errors": 0}'
# Scan cache is intentionally empty on a fresh/repaired deployment.
mkdir -p /opt/antivirus-server/data
if [ ! -f /opt/antivirus-server/data/scan_cache.json ]; then printf '{}\\n' > /opt/antivirus-server/data/scan_cache.json; fi

# Quarantine metadata is separate from payloads and is always valid JSON.
if [ ! -f "$QUARANTINE_DIR/quarantine_log.json" ]; then
    printf '[]\\n' > "$QUARANTINE_DIR/quarantine_log.json"
    chmod 600 "$QUARANTINE_DIR/quarantine_log.json"
fi

# If running interactively, ask for the Cloudflare API token so we can obtain
# a Let's Encrypt origin certificate. The token is not echoed.
if [ -t 0 ]; then
    EXISTING_TOKEN=$(grep -E '^CLOUDFLARE_API_TOKEN=' /opt/antivirus-server/.env 2>/dev/null | cut -d= -f2- | tr -d '"'"'" | tr -d "'" | tr -d '\r')
    if [ -z "$EXISTING_TOKEN" ]; then
        read -sp "Cloudflare API token (Zone:Read + DNS:Edit for isolation-bytes.com), or press Enter to skip HTTPS: " CF_INPUT
        echo
        if [ -n "$CF_INPUT" ]; then
            # Upsert CLOUDFLARE_API_TOKEN in .env
            if grep -qE '^#?\s*CLOUDFLARE_API_TOKEN=' /opt/antivirus-server/.env; then
                sed -i "s|^#\?\s*CLOUDFLARE_API_TOKEN=.*|CLOUDFLARE_API_TOKEN=$CF_INPUT|" /opt/antivirus-server/.env
            else
                echo "CLOUDFLARE_API_TOKEN=$CF_INPUT" >> /opt/antivirus-server/.env
            fi
            echo "  Cloudflare API token saved to /opt/antivirus-server/.env"
        fi
    fi
fi

# 6. Nginx config (HTTPS if a certificate exists or can be obtained)
echo "[6/8] Configuring Nginx..."
mkdir -p /opt/antivirus-server/certs
CERT_DIR=/opt/antivirus-server/certs
FULLCHAIN=$CERT_DIR/fullchain.pem
PRIVKEY=$CERT_DIR/privkey.pem
CF_TOKEN=$(grep -E '^CLOUDFLARE_API_TOKEN=' /opt/antivirus-server/.env 2>/dev/null | cut -d= -f2- | tr -d '"'"'" | tr -d "'" | tr -d '\r')
CERT_DOMAIN=$(grep -E '^CERT_DOMAIN=' /opt/antivirus-server/.env 2>/dev/null | cut -d= -f2- | tr -d '"'"'" | tr -d "'" | tr -d '\r')
CERT_DOMAIN=${CERT_DOMAIN:-isolation-bytes.com}

MODE=http
if [ -f "$FULLCHAIN" ] && [ -f "$PRIVKEY" ]; then
    echo "  Using existing certificate in $CERT_DIR"
    MODE=https
elif [ -n "$CF_TOKEN" ]; then
    echo "  Obtaining Let's Encrypt certificate via Cloudflare DNS for $CERT_DOMAIN..."
    export CLOUDFLARE_API_TOKEN="$CF_TOKEN"
    export CERT_DOMAIN="$CERT_DOMAIN"
    export CERT_DIR="$CERT_DIR"
    cd /opt/antivirus-server
    /opt/antivirus-server/venv/bin/python cloud/get_cert.py
    if [ -f "$FULLCHAIN" ] && [ -f "$PRIVKEY" ]; then
        MODE=https
    else
        echo "  WARNING: certificate acquisition failed; falling back to HTTP"
    fi
else
    echo "  No CLOUDFLARE_API_TOKEN set; using HTTP only."
    echo "  Set Cloudflare SSL/TLS to Flexible or provide a CLOUDFLARE_API_TOKEN for HTTPS."
fi

if [ "$MODE" = "https" ]; then
    cat > /etc/nginx/sites-enabled/antivirus-cloud << EOF
server {
    listen 80;
    server_name $CERT_DOMAIN;
    return 301 https://\$host\$request_uri;
}
server {
    listen 443 ssl;
    server_name $CERT_DOMAIN;
    ssl_certificate $FULLCHAIN;
    ssl_certificate_key $PRIVKEY;
    location / {
        proxy_pass http://127.0.0.1:5002;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
EOF
else
    cat > /etc/nginx/sites-enabled/antivirus-cloud << 'EOF'
server {
    listen 80;
    server_name isolation-bytes.com;
    location / {
        proxy_pass http://127.0.0.1:5002;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
EOF
fi

rm -f /etc/nginx/sites-enabled/default
nginx -t 2>&1
systemctl restart nginx

# 7. Systemd service (1 worker to save memory)
echo "[7/8] Creating systemd service (1 worker to prevent OOM)..."
cat > /etc/systemd/system/antivirus-cloud.service << 'EOF'
[Unit]
Description=Antivirus Cloud Server (Flask + gunicorn WSGI)
After=network.target

[Service]
User=root
WorkingDirectory=/opt/antivirus-server
ExecStart=/opt/antivirus-server/venv/bin/gunicorn -w 1 --timeout 120 --graceful-timeout 30 --keep-alive 5 -b 127.0.0.1:5002 cloud.cloud_server:app
Restart=always
RestartSec=5
Environment=PYTHONPATH=/opt/antivirus-server
EnvironmentFile=-/opt/antivirus-server/.env

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable antivirus-cloud

# 8. Start everything
echo "[8/8] Starting services..."
systemctl restart antivirus-cloud
sleep 2
if ! systemctl is-active --quiet antivirus-cloud; then
    echo "ERROR: antivirus-cloud failed to start"
    systemctl --no-pager --full status antivirus-cloud || true
    journalctl -u antivirus-cloud -n 120 --no-pager || true
    exit 1
fi
if ! systemctl is-active --quiet nginx; then
    echo "ERROR: nginx failed to start"
    systemctl --no-pager --full status nginx || true
    exit 1
fi
systemctl is-enabled antivirus-cloud

# Verify the origin directly before declaring the deployment healthy.
echo ""
echo "=== Verification ==="
for attempt in $(seq 1 20); do
    if curl -fsS --max-time 5 -o /dev/null http://127.0.0.1:5002/; then
        echo "Origin: HTTP 200"
        if curl -fsS --max-time 5 -o /dev/null http://127.0.0.1:5002/api/config; then
        # /run_startup must be handled by the cloud app without importing the Windows-only quick_start module.
        STARTUP_STATUS=$(curl -sS --max-time 5 -o /tmp/isolation-bytes-run-startup.json -w '%{http_code}' -X POST http://127.0.0.1:5002/run_startup || true)
        if [ "$STARTUP_STATUS" = "202" ] || [ "$STARTUP_STATUS" = "200" ]; then
            echo "Startup endpoint: HTTP $STARTUP_STATUS"
        else
            echo "ERROR: /run_startup returned HTTP $STARTUP_STATUS"
            cat /tmp/isolation-bytes-run-startup.json 2>/dev/null || true
            journalctl -u antivirus-cloud -n 80 --no-pager || true
            exit 1
        fi

            echo "API: HTTP 200"
        else
            echo "WARNING: root is healthy but /api/config failed"
        fi
        test -f "$QUARANTINE_DIR/quarantine_log.json"
        echo "Quarantine log: present at $QUARANTINE_DIR/quarantine_log.json"
        break
    fi
    if [ "$attempt" -eq 20 ]; then
        echo "ERROR: origin 127.0.0.1:5002 did not become healthy"
        systemctl --no-pager --full status antivirus-cloud || true
        journalctl -u antivirus-cloud -n 80 --no-pager || true
        exit 1
    fi
    sleep 2
done
echo ""
free -h
echo ""
echo "=== Done! ==="
echo "Server should be live at https://isolation-bytes.com"
