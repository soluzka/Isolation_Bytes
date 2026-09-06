# Deploying the Antivirus Cloud Server to a GoDaddy VPS

This folder contains everything needed to run the Flask cloud server in
production behind nginx on a GoDaddy VPS (Ubuntu/Debian). It fixes the
`/get_folder_watcher_paths` 404s you were seeing on the live site.

## Files

| File | Purpose |
|------|---------|
| `../wsgi.py` | WSGI entry point (`wsgi:application`) that waitress/gunicorn load. |
| `antivirus-cloud.service` | systemd unit -- runs the app, restarts on crash, starts on boot. |
| `nginx-antivirus-cloud.conf` | nginx reverse proxy -- forwards all paths (including the API endpoints) to the Flask app. |
| `deploy.sh` | One-shot install/update script. Idempotent; safe to re-run after `git pull`. |

## Why the 404 was happening

The route `/get_folder_watcher_paths` exists in `cloud/cloud_server.py` and
returns 200 when tested locally. On the live site it 404'd because the running
Flask process on the VPS was either:

1. **running stale code** (started before the route was added -- Flask only
   loads routes at process start, not on file changes), or
2. **not actually receiving the request** because nginx's `location /` was
   serving static files from a directory instead of `proxy_pass`-ing to the
   Flask app.

Both are fixed by this deployment: `deploy.sh` re-pulls the code, restarts the
systemd service (so the new routes load), and installs an nginx config whose
`location /` proxies everything to waitress on `127.0.0.1:5002`.

## One-shot deploy

```bash
# On the VPS, as root:
sudo bash deploy/deploy.sh
```

The CONFIG block at the top of `deploy.sh` is pre-filled for soluzka.com:

```bash
REPO_DIR="/opt/antivirus-yara-rules-c"
APP_USER="www-data"
APP_PORT="5002"                               # internal (waitress -> nginx)
DOMAIN="soluzka.com"                          # public domain
PUBLIC_PORT="8443"                            # public HTTPS port (matches existing https://soluzka.com:8443/ URLs)
SSL_CERT="/etc/ssl/certs/soluzka.com.crt"     # <-- set to your real cert path
SSL_KEY="/etc/ssl/private/soluzka.com.key"    # <-- set to your real key path
```

Only the SSL_CERT and SSL_KEY paths likely need adjusting to point at the
actual certificate files on the VPS (GoDaddy-provided or Let's Encrypt).

The script:
1. Installs `python3`, `pip`, `venv`, `nginx`.
2. Creates a virtualenv at `$REPO_DIR/venv` and installs `requirements.txt`.
3. Patches the systemd unit with your real paths/user and enables it.
4. Patches the nginx config with your domain + cert paths and enables it.
5. Restarts `antivirus-cloud` and reloads nginx.
6. Smoke-tests `http://127.0.0.1:5002/get_folder_watcher_paths` (expects 200).

## Manual deploy (if you don't want to use the script)

```bash
# 1. Get the latest code on the VPS.
cd /opt/antivirus-yara-rules-c
git pull origin main

# 2. Verify the route is actually in the file you just pulled.
grep -n "get_folder_watcher_paths" cloud/cloud_server.py
# Expect: 543:  @cloud_bp.route('/get_folder_watcher_paths', methods=['GET'])

# 3. Install deps (use a venv if you prefer).
python3 -m pip install -r requirements.txt

# 4. Run with waitress (production WSGI). Bind to localhost; nginx fronts it.
python3 -m waitress --listen=127.0.0.1:5002 wsgi:application
```

Then install the nginx config and systemd unit as described in the comments at
the top of `nginx-antivirus-cloud.conf` and `antivirus-cloud.service`.

## Verify the fix

```bash
# On the VPS -- backend directly:
curl -i http://127.0.0.1:5002/get_folder_watcher_paths
# Expect: HTTP/1.1 200 OK   + JSON body

# Through nginx / the public domain:
curl -i https://soluzka.com:8443/get_folder_watcher_paths
# Expect: HTTP/2 200         + JSON body
```

Open `https://soluzka.com:8443/yara_scanner` (or wherever the dashboard lives)
in a browser and watch the console -- the two `get_folder_watcher_paths` 404
errors will be gone.

## Updating after future code changes

```bash
cd /opt/antivirus-yara-rules-c
git pull origin main
sudo systemctl restart antivirus-cloud
```

Flask only reads routes at process start, so **you must restart the service**
after pulling new code. `deploy.sh` does this for you automatically.

## Common issues

- **404 still happening after deploy** -- `systemctl status antivirus-cloud`
  (is it actually running?) and `journalctl -u antivirus-cloud -n 50` (did it
  crash on startup?). Then `nginx -t` (is the proxy config valid?) and check
  that `location /` is `proxy_pass http://127.0.0.1:5002;`, not serving from a
  root directory.
- **502 Bad Gateway** -- waitress isn't running or is on a different port.
  Check the `--listen` value in the systemd unit matches `proxy_pass` in nginx.
- **SSL errors** -- the cert/key paths in the nginx config are wrong, or the
  cert doesn't cover the domain you're hitting.
- **Permission denied writing to instance/ or logs/** -- the `ReadWritePaths=`
  line in the systemd unit needs to point at dirs the `APP_USER` can write to.

## Logs

```bash
# App logs (Flask + waitress):
journalctl -u antivirus-cloud -f

# nginx access/error logs:
tail -f /var/log/nginx/access.log /var/log/nginx/error.log
```
