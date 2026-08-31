#!/usr/bin/env bash
# Deploy / update the Antivirus Cloud Server on a GoDaddy VPS (Ubuntu/Debian).
#
# Run as root (or with sudo):
#   sudo bash deploy/deploy.sh
#
# What this does:
#   1. Installs system + Python deps (python3, pip, venv, nginx, waitress).
#   2. Creates a virtualenv and installs requirements.txt into it.
#   3. Installs the systemd unit so the app auto-starts and survives reboots.
#   4. Installs the nginx reverse-proxy config.
#   5. Reloads everything and runs a smoke test against /get_folder_watcher_paths.
#
# Re-running this script is safe -- it's idempotent and just re-pulls/restarts.

set -euo pipefail

# ---- CONFIG: edit these to match your VPS -----------------------------------
REPO_DIR="/opt/antivirus-yara-rules-c"        # where the repo lives on the VPS
APP_USER="www-data"                           # user the service runs as
APP_PORT="5002"                               # internal port waitress listens on
DOMAIN="soluzka.com"                          # public domain
PUBLIC_PORT="8443"                            # public HTTPS port (matches existing https://soluzka.com:8443/ URLs)
SSL_CERT="/etc/ssl/certs/soluzka.com.crt"     # path to your SSL cert
SSL_KEY="/etc/ssl/private/soluzka.com.key"    # path to your SSL key
# -----------------------------------------------------------------------------

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
log()  { echo -e "${GREEN}[deploy]${NC} $*"; }
warn() { echo -e "${YELLOW}[warn]${NC}  $*"; }
err()  { echo -e "${RED}[err]${NC}   $*" >&2; }

[[ $EUID -eq 0 ]] || { err "Run with sudo: sudo bash deploy/deploy.sh"; exit 1; }

# 1. System deps
log "Installing system packages (python3, pip, venv, nginx)..."
apt-get update -y
apt-get install -y python3 python3-pip python3-venv nginx
python3 -m pip install --upgrade pip

# 2. Repo + virtualenv
log "Ensuring repo dir exists at $REPO_DIR..."
if [[ ! -d "$REPO_DIR/.git" ]]; then
    err "Repo not found at $REPO_DIR. Clone it first:"
    err "  git clone <your-repo-url> $REPO_DIR"
    exit 1
fi

log "Pulling latest code..."
sudo -u "$APP_USER" git -C "$REPO_DIR" pull --ff-only || warn "git pull failed (maybe run it manually)"

VENV="$REPO_DIR/venv"
log "Creating virtualenv at $VENV (if missing)..."
[[ -d "$VENV" ]] || python3 -m venv "$VENV"

log "Upgrading pip in venv and installing requirements.txt..."
"$VENV/bin/python" -m pip install --upgrade pip
"$VENV/bin/python" -m pip install -r "$REPO_DIR/requirements.txt"

# Make sure waitress is present (it's in requirements.txt, but be explicit).
"$VENV/bin/python" -c "import waitress" 2>/dev/null || "$VENV/bin/python" -m pip install waitress

# 3. systemd unit
log "Installing systemd unit..."
UNIT_SRC="$REPO_DIR/deploy/antivirus-cloud.service"
UNIT_DST="/etc/systemd/system/antivirus-cloud.service"
# Patch the unit file with the real paths/user for this VPS before installing.
sed -e "s|^User=.*|User=$APP_USER|" \
    -e "s|^Group=.*|Group=$APP_USER|" \
    -e "s|^WorkingDirectory=.*|WorkingDirectory=$REPO_DIR|" \
    -e "s|^ExecStart=.*|ExecStart=$VENV/bin/python -m waitress --listen=127.0.0.1:$APP_PORT wsgi:application|" \
    -e "s|^ReadWritePaths=.*|ReadWritePaths=$REPO_DIR/instance $REPO_DIR/logs|" \
    "$UNIT_SRC" > "$UNIT_DST"
systemctl daemon-reload
systemctl enable antivirus-cloud

# 4. nginx config
log "Installing nginx config..."
NGINX_SRC="$REPO_DIR/deploy/nginx-antivirus-cloud.conf"
NGINX_DST="/etc/nginx/sites-available/antivirus-cloud"
sed -e "s|YOUR_DOMAIN|$DOMAIN|g" \
    -e "s|YOUR_PUBLIC_PORT|$PUBLIC_PORT|g" \
    -e "s|/etc/ssl/certs/yourdomain.crt|$SSL_CERT|g" \
    -e "s|/etc/ssl/private/yourdomain.key|$SSL_KEY|g" \
    "$NGINX_SRC" > "$NGINX_DST"
mkdir -p /etc/nginx/sites-enabled
ln -sf "$NGINX_DST" /etc/nginx/sites-enabled/antivirus-cloud
# Remove the default site if it conflicts for port 80/443.
rm -f /etc/nginx/sites-enabled/default

if ! nginx -t; then
    err "nginx config test failed -- fix the errors above, then re-run."
    exit 1
fi

# 5. (Re)start services
log "Restarting antivirus-cloud and nginx..."
systemctl restart antivirus-cloud
systemctl reload nginx

# 6. Smoke test -- this is the endpoint that was 404-ing.
log "Smoke testing http://127.0.0.1:$APP_PORT/get_folder_watcher_paths ..."
sleep 2
if curl -sf "http://127.0.0.1:$APP_PORT/get_folder_watcher_paths" >/dev/null; then
    log "OK: /get_folder_watcher_paths returned 200 on the backend."
else
    err "Backend smoke test failed. Check: journalctl -u antivirus-cloud -n 50"
    exit 1
fi

log "All done. Live site: https://$DOMAIN:$PUBLIC_PORT"
log "Tail logs with:  journalctl -u antivirus-cloud -f"
log "Status:          systemctl status antivirus-cloud"
