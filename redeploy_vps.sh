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
    git fetch origin
    git checkout security-v2
    git reset --hard origin/security-v2
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
ExecStart=/opt/antivirus-server/venv/bin/gunicorn -w 1 -b 127.0.0.1:5002 cloud.cloud_server:app
Restart=always
RestartSec=5
Environment=PYTHONPATH=/opt/antivirus-server

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable antivirus-cloud

# 8. Start everything
echo "[8/8] Starting services..."
systemctl restart antivirus-cloud
sleep 3
systemctl is-active antivirus-cloud
systemctl is-active nginx

# Verify
echo ""
echo "=== Verification ==="
curl -s -o /dev/null -w "HTTP %{http_code}" http://127.0.0.1:5002/ 2>/dev/null || echo "Flask not responding yet"
echo ""
free -h
echo ""
echo "=== Done! ==="
echo "Server should be live at https://isolation-bytes.com"
