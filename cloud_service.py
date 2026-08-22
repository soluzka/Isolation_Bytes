"""Windows Service wrapper for the cloud antivirus server.

This allows the server to run 24/7 as a Windows service that:
- Auto-starts on boot
- Survives logoffs
- Restarts on crash
- Works even when no one is logged in

Install:
    python cloud_service.py install

Uninstall:
    python cloud_service.py remove

Start:
    python cloud_service.py start

Stop:
    python cloud_service.py stop

Or use the Windows Services Manager (services.msc) to manage it.
"""
import os
import sys
import logging
from pathlib import Path

# Set up paths
BASE_DIR = Path(__file__).resolve().parent
os.chdir(str(BASE_DIR))

# Add to path
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))
if str(BASE_DIR / 'cloud') not in sys.path:
    sys.path.insert(0, str(BASE_DIR / 'cloud'))

try:
    import win32serviceutil
    import win32service
    import win32event
    import servicemanager
    HAS_WIN32 = True
except ImportError:
    HAS_WIN32 = False
    print("pywin32 is required. Install it with: pip install pywin32")


class CloudServerService(win32serviceutil.ServiceFramework if HAS_WIN32 else object):
    """Windows service that runs the cloud antivirus server 24/7."""

    _svc_name_ = "AntivirusCloudServer"
    _svc_display_name_ = "Antivirus Cloud Server"
    _svc_description_ = "Runs the antivirus cloud dashboard, local agent, and AI assistant 24/7. Auto-starts on boot and survives logoffs."

    def __init__(self, args):
        if not HAS_WIN32:
            raise RuntimeError("pywin32 is not installed")
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
        self._server_process = None
        self._caddy_process = None
        self._cloudflared_process = None
        self._stop_requested = False
        logging.basicConfig(
            filename=str(BASE_DIR / 'cloud' / 'service.log'),
            level=logging.INFO,
            format='%(asctime)s [%(levelname)s] %(message)s'
        )
        self.log = logging.getLogger('CloudServerService')

    def SvcStop(self):
        """Called when the service is stopped."""
        self.log.info("Service stop requested")
        self._stop_requested = True
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        # Kill the cloudflared tunnel
        if self._cloudflared_process:
            try:
                self._cloudflared_process.terminate()
            except Exception:
                pass
        # Kill Caddy
        if self._caddy_process:
            try:
                self._caddy_process.terminate()
            except Exception:
                pass
        # Kill the server process
        if self._server_process:
            try:
                self._server_process.terminate()
            except Exception:
                pass
        win32event.SetEvent(self.hWaitStop)

    def SvcDoRun(self):
        """Called when the service starts."""
        self.log.info("Antivirus Cloud Server service starting")
        servicemanager.LogMsg(
            servicemanager.EVENTLOG_INFORMATION_TYPE,
            servicemanager.PYS_SERVICE_STARTED,
            (self._svc_name_, '')
        )
        self._run_server()

    def _wait_for_port(self, port, timeout=120):
        """Wait for a port to be listening. Returns True if ready, False on timeout."""
        import socket
        import time
        deadline = time.time() + timeout
        while time.time() < deadline and not self._stop_requested:
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=2):
                    return True
            except (OSError, socket.error):
                time.sleep(2)
        return False

    def _run_server(self):
        """Run the cloud server, Caddy, and Cloudflare tunnel as subprocesses."""
        import subprocess
        import threading
        import time
        import shutil
        from dotenv import dotenv_values

        child_env = os.environ.copy()
        for env_path in (BASE_DIR / '.env', BASE_DIR / 'cloud' / '.env', BASE_DIR / '.env.server'):
            if env_path.exists():
                for key, value in dotenv_values(env_path).items():
                    if value is not None:
                        child_env[key] = value

        # Use a stable local directory outside OneDrive to avoid sync/permission issues
        # when running as SYSTEM. Copy the EXE there on each start.
        local_dir = r'C:\AntivirusServer'
        os.makedirs(local_dir, exist_ok=True)

        # Source EXE locations (check both)
        source_exe = str(BASE_DIR / 'dist' / 'cloud_server.exe')
        server_script = str(BASE_DIR / 'cloud' / 'cloud_server.py')
        python_exe = sys.executable

        # Copy the EXE to the stable local directory
        local_exe = os.path.join(local_dir, 'cloud_server.exe')
        if os.path.exists(source_exe):
            try:
                shutil.copy2(source_exe, local_exe)
                self.log.info(f"Copied cloud_server.exe to {local_exe}")
            except Exception as e:
                self.log.warning(f"Failed to copy EXE to local dir: {e}, using source path")
                local_exe = source_exe

        server_exe_to_use = local_exe if os.path.exists(local_exe) else source_exe

        if os.path.exists(server_exe_to_use):
            # Use the built EXE — it has everything bundled
            self._server_process = subprocess.Popen(
                [server_exe_to_use],
                cwd=local_dir if os.path.exists(local_exe) else str(BASE_DIR),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                creationflags=subprocess.CREATE_NO_WINDOW,
                env=child_env,
            )
            self.log.info(f"Server EXE started with PID {self._server_process.pid}")
        else:
            # Fallback: run with Python
            self._server_process = subprocess.Popen(
                [python_exe, server_script],
                cwd=str(BASE_DIR),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                creationflags=subprocess.CREATE_NO_WINDOW,
                env=child_env,
            )
            self.log.info(f"Server (Python) started with PID {self._server_process.pid}")

        # Wait for the server to be ready (up to 120 seconds for large EXE extraction)
        self.log.info("Waiting for server to be ready (up to 120s)...")
        if self._wait_for_port(8000, timeout=120):
            self.log.info("Server is ready on port 8000")
        else:
            self.log.warning("Server did not become ready in 120 seconds")

        # Start Caddy reverse proxy (if installed and Caddyfile exists)
        caddy_exe = r'C:\caddy\caddy.exe'
        caddyfile = r'C:\caddy\Caddyfile'
        if os.path.exists(caddy_exe) and os.path.exists(caddyfile):
            try:
                self._caddy_process = subprocess.Popen(
                    [caddy_exe, 'run', '--config', caddyfile],
                    cwd=r'C:\caddy',
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    creationflags=subprocess.CREATE_NO_WINDOW,
                )
                self.log.info(f"Caddy started with PID {self._caddy_process.pid}")
            except Exception as e:
                self.log.warning(f"Failed to start Caddy: {e}")
        else:
            self.log.info("Caddy not found at C:\\caddy\\caddy.exe — skipping")

        # Start Cloudflare tunnel (if installed) — provides access without port forwarding
        cloudflared_exe = r'C:\caddy\cloudflared.exe'
        cloudflared_config = r'C:\Users\bpier\.cloudflared\config.yml'
        if os.path.exists(cloudflared_exe):
            try:
                self._cloudflared_process = subprocess.Popen(
                    [cloudflared_exe, 'tunnel', '--config', cloudflared_config, 'run', 'isolation-bytes'],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    creationflags=subprocess.CREATE_NO_WINDOW,
                )
                self.log.info(f"Cloudflare tunnel started with PID {self._cloudflared_process.pid}")
            except Exception as e:
                self.log.warning(f"Failed to start Cloudflare tunnel: {e}")
        else:
            self.log.info("cloudflared not found at C:\\caddy\\cloudflared.exe — skipping")

        # Monitor all processes — restart if they crash
        while not self._stop_requested:
            # Check server
            ret = self._server_process.poll()
            if ret is not None:
                self.log.warning(f"Server process exited with code {ret}. Restarting in 10 seconds...")
                time.sleep(10)
                if not self._stop_requested:
                    self.log.info("Restarting server...")
                    # Re-copy the EXE in case it was updated
                    if os.path.exists(source_exe):
                        try:
                            shutil.copy2(source_exe, local_exe)
                        except Exception:
                            pass
                    if os.path.exists(server_exe_to_use):
                        self._server_process = subprocess.Popen(
                            [server_exe_to_use],
                            cwd=local_dir if os.path.exists(local_exe) else str(BASE_DIR),
                            stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT,
                            creationflags=subprocess.CREATE_NO_WINDOW,
                            env=child_env,
                        )
                    else:
                        self._server_process = subprocess.Popen(
                            [python_exe, server_script],
                            cwd=str(BASE_DIR),
                            stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT,
                            creationflags=subprocess.CREATE_NO_WINDOW,
                            env=child_env,
                        )
                    self.log.info(f"Server restarted with PID {self._server_process.pid}")
                    # Wait for port to be ready after restart
                    self._wait_for_port(8000, timeout=120)

            # Check Caddy
            if self._caddy_process and self._caddy_process.poll() is not None:
                if os.path.exists(caddy_exe) and os.path.exists(caddyfile) and not self._stop_requested:
                    self.log.warning("Caddy exited. Restarting in 5 seconds...")
                    time.sleep(5)
                    if not self._stop_requested:
                        self._caddy_process = subprocess.Popen(
                            [caddy_exe, 'run', '--config', caddyfile],
                            cwd=r'C:\caddy',
                            stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT,
                            creationflags=subprocess.CREATE_NO_WINDOW,
                        )
                        self.log.info(f"Caddy restarted with PID {self._caddy_process.pid}")

            # Check cloudflared
            if self._cloudflared_process and self._cloudflared_process.poll() is not None:
                if os.path.exists(cloudflared_exe) and not self._stop_requested:
                    self.log.warning("Cloudflare tunnel exited. Restarting in 10 seconds...")
                    time.sleep(10)
                    if not self._stop_requested:
                        self._cloudflared_process = subprocess.Popen(
                            [cloudflared_exe, 'tunnel', '--config', cloudflared_config, 'run', 'isolation-bytes'],
                            stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT,
                            creationflags=subprocess.CREATE_NO_WINDOW,
                        )
                        self.log.info(f"Cloudflare tunnel restarted with PID {self._cloudflared_process.pid}")

            # Wait a bit before checking again
            win32event.WaitForSingleObject(self.hWaitStop, 5000)

        self.log.info("Service stopped")


if __name__ == '__main__':
    if not HAS_WIN32:
        print("pywin32 is required. Install it with: pip install pywin32")
        sys.exit(1)

    if len(sys.argv) == 1:
        # Running as a service
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(CloudServerService)
        servicemanager.StartServiceCtrlDispatcher()
    else:
        # Command line usage
        win32serviceutil.HandleCommandLine(CloudServerService)
