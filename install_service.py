"""Install the antivirus cloud server as a Windows service.

Run this as Administrator:
    python install_service.py

This will:
1. Install pywin32 if needed
2. Register the service
3. Set it to auto-start on boot
4. Start it immediately
"""
import os
import sys
import subprocess
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
os.chdir(str(BASE_DIR))


def run(cmd, check=True):
    print(f"> {cmd}")
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if result.stdout:
        print(result.stdout.strip())
    if result.stderr:
        print(result.stderr.strip())
    if check and result.returncode != 0:
        print(f"Command failed with exit code {result.returncode}")
    return result.returncode == 0


def main():
    print("=== Antivirus Cloud Server Service Installer ===\n")

    # Check if running as admin
    try:
        import ctypes
        if not ctypes.windll.shell32.IsUserAnAdmin():
            print("ERROR: This script must be run as Administrator.")
            print("Right-click Command Prompt -> Run as Administrator, then run:")
            print(f"  cd \"{BASE_DIR}\"")
            print("  python install_service.py")
            sys.exit(1)
    except Exception:
        pass

    # Install pywin32 if needed
    try:
        import win32serviceutil
        print("[OK] pywin32 is installed")
    except ImportError:
        print("Installing pywin32...")
        if not run(f'"{sys.executable}" -m pip install pywin32'):
            print("Failed to install pywin32. Please install it manually:")
            print(f'  "{sys.executable}" -m pip install pywin32')
            sys.exit(1)
        # Run pywin32 post-install
        scripts_dir = os.path.join(os.path.dirname(sys.executable), 'Scripts')
        postinstall = os.path.join(scripts_dir, 'pywin32_postinstall.py')
        if os.path.exists(postinstall):
            run(f'"{sys.executable}" "{postinstall}" -install')

    # Stop existing service if running
    print("\nStopping existing service if running...")
    run('sc stop AntivirusCloudServer', check=False)

    # Remove existing service if installed
    print("\nRemoving existing service if installed...")
    run(f'"{sys.executable}" cloud_service.py remove', check=False)

    # Install the service
    print("\nInstalling service...")
    if not run(f'"{sys.executable}" cloud_service.py install'):
        print("Failed to install service")
        sys.exit(1)

    # Set to auto-start
    print("\nSetting service to auto-start on boot...")
    run('sc config AntivirusCloudServer start= auto')

    # Start the service
    print("\nStarting service...")
    run('sc start AntivirusCloudServer')

    print("\n=== Installation Complete ===")
    print("\nThe Antivirus Cloud Server is now running as a Windows service.")
    print("It will:")
    print("  - Auto-start when the computer boots")
    print("  - Stay running even when no one is logged in")
    print("  - Automatically restart if it crashes")
    print("  - Run the server, local agent, AI assistant, Caddy, and Cloudflare tunnel")
    print("\nComponents started by the service:")
    print("  1. Flask antivirus server (port 8000 in proxy mode, or 8443 direct)")
    print("  2. Caddy reverse proxy (port 443, if installed at C:\\caddy\\)")
    print("  3. Cloudflare tunnel (provides public access without port forwarding)")
    print("\nManage it via:")
    print("  - services.msc (Windows Services Manager)")
    print(f"  - Stop:   python cloud_service.py stop")
    print(f"  - Start:  python cloud_service.py start")
    print(f"  - Remove: python cloud_service.py remove")
    print(f"\nLocal dashboard: https://127.0.0.1:8000/ (proxy mode) or https://127.0.0.1:8443/ (direct)")
    print(f"Public via Caddy: https://isolation-bytes.com/ (requires port 443 forwarding)")
    print(f"Public via Cloudflare tunnel: check service.log for the trycloudflare URL")


if __name__ == '__main__':
    main()
