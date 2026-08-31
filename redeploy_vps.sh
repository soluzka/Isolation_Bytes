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

# 5. Nginx config
echo "[5/8] Configuring Nginx..."
cp nginx-cloud.conf /etc/nginx/sites-enabled/antivirus-cloud 2>/dev/null || true
rm -f /etc/nginx/sites-enabled/default
nginx -t 2>&1
systemctl restart nginx

# 6. Systemd service (1 worker to save memory)
echo "[6/8] Creating systemd service (1 worker to prevent OOM)..."
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

# 7. Create .env with payment URL
echo "[7/8] Creating .env..."
if [ ! -f /opt/antivirus-server/.env ]; then
    cat > /opt/antivirus-server/.env << 'EOF'
PUBLIC_URL=https://isolation-bytes.com
LICENSE_SERVER=https://isolation-bytes.com
PAYMENT_URL=https://buy.stripe.com/7sY6oBaNqfsk7VrbgM0sU04
BEHIND_PROXY=1
PROXY_PORT=8000
FLASK_PORT=8443
CLOUD_API_KEY=d63dfd43ad0543871148b37f3dbf5533731fbe3aa87fb546a8e139dbee30b198
EOF
fi

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
