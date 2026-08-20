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

    def _run_server(self):
        """Run the cloud server in a subprocess."""
        import subprocess
        import threading

        server_script = str(BASE_DIR / 'cloud' / 'cloud_server.py')
        python_exe = sys.executable

        # Start the server in a subprocess so it runs independently
        self._server_process = subprocess.Popen(
            [python_exe, server_script],
            cwd=str(BASE_DIR),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )

        self.log.info(f"Server started with PID {self._server_process.pid}")

        # Monitor the process — restart if it crashes
        while not self._stop_requested:
            ret = self._server_process.poll()
            if ret is not None:
                self.log.warning(f"Server process exited with code {ret}. Restarting in 5 seconds...")
                import time
                time.sleep(5)
                if not self._stop_requested:
                    self.log.info("Restarting server...")
                    self._server_process = subprocess.Popen(
                        [python_exe, server_script],
                        cwd=str(BASE_DIR),
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        creationflags=subprocess.CREATE_NO_WINDOW,
                    )
                    self.log.info(f"Server restarted with PID {self._server_process.pid}")
            else:
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
