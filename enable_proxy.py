"""Enable or disable reverse proxy mode for the cloud server.

Usage:
    python enable_proxy.py caddy    # Set up for Caddy (recommended — auto SSL)
    python enable_proxy.py nginx    # Set up for nginx
    python enable_proxy.py off      # Disable proxy mode (direct on 8443)

When proxy mode is enabled:
    - Server runs on 127.0.0.1:8000 without SSL
    - The reverse proxy (Caddy/nginx) handles SSL on port 443
    - Users connect to https://soluzka.com/ (no port number needed)

When proxy mode is disabled:
    - Server runs on 0.0.0.0:8443 with SSL directly
    - Users connect to https://soluzka.com:8443/
"""
import os
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
ENV_FILE = BASE_DIR / '.env'


def read_env():
    lines = []
    if ENV_FILE.exists():
        lines = ENV_FILE.read_text(encoding='utf-8').splitlines()
    return lines


def write_env(lines):
    content = '\n'.join(lines) + '\n'
    # OneDrive files can be reparse points that block direct writes.
    # Write to a temp file first, then replace.
    tmp = ENV_FILE.with_suffix('.env.tmp')
    tmp.write_text(content, encoding='utf-8')
    # Clear attributes (Hidden, ReparsePoint) on the original if present
    try:
        import ctypes
        FILE_ATTRIBUTE_HIDDEN = 0x2
        FILE_ATTRIBUTE_REPARSE_POINT = 0x400
        attrs = ctypes.windll.kernel32.GetFileAttributesW(str(ENV_FILE))
        if attrs != 0xFFFFFFFF:
            ctypes.windll.kernel32.SetFileAttributesW(str(ENV_FILE), 0)
    except Exception:
        pass
    ENV_FILE.replace(tmp)
    # Restore Hidden attribute
    try:
        import ctypes
        ctypes.windll.kernel32.SetFileAttributesW(str(ENV_FILE), 0x2)
    except Exception:
        pass


def set_env_var(lines, key, value):
    found = False
    new_lines = []
    for line in lines:
        if line.strip().startswith(f'{key}='):
            new_lines.append(f'{key}={value}')
            found = True
        else:
            new_lines.append(line)
    if not found:
        new_lines.append(f'{key}={value}')
    return new_lines


def enable_proxy(proxy_type):
    lines = read_env()
    lines = set_env_var(lines, 'BEHIND_PROXY', '1')
    lines = set_env_var(lines, 'PROXY_PORT', '8000')
    write_env(lines)

    print(f"Reverse proxy mode ENABLED ({proxy_type}).")
    print(f"Server will run on 127.0.0.1:8000 without SSL.")
    print()
    if proxy_type == 'caddy':
        print("Caddy setup:")
        print("  1. Download Caddy from https://caddyserver.com/download")
        print(f"  2. Use the Caddyfile at: cloud/Caddyfile")
        print("  3. Run: caddy run")
        print("  4. Caddy auto-manages Let's Encrypt certs")
        print("  5. Server will be at https://soluzka.com/ (no port needed)")
    elif proxy_type == 'nginx':
        print("nginx setup:")
        print(f"  1. Copy cloud/nginx.conf to your nginx sites-enabled directory")
        print("  2. Get SSL certs: sudo certbot --nginx -d soluzka.com")
        print("  3. Reload: sudo nginx -s reload")
        print("  4. Server will be at https://soluzka.com/ (no port needed)")
    print()
    print("Restart the server after this change.")


def disable_proxy():
    lines = read_env()
    lines = set_env_var(lines, 'BEHIND_PROXY', '0')
    write_env(lines)
    print("Reverse proxy mode DISABLED.")
    print("Server will run directly on 0.0.0.0:8443 with SSL.")
    print("Users connect to https://soluzka.com:8443/")
    print()
    print("Restart the server after this change.")


def main():
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python enable_proxy.py caddy   # Enable with Caddy (recommended)")
        print("  python enable_proxy.py nginx   # Enable with nginx")
        print("  python enable_proxy.py off     # Disable (direct mode)")
        sys.exit(1)

    arg = sys.argv[1].lower()
    if arg == 'caddy':
        enable_proxy('caddy')
    elif arg == 'nginx':
        enable_proxy('nginx')
    elif arg == 'off':
        disable_proxy()
    else:
        print(f"Unknown option: {arg}")
        print("Use: caddy, nginx, or off")
        sys.exit(1)


if __name__ == '__main__':
    main()
