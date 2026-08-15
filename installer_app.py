"""One-click installer for the Antivirus Server MSIX package."""
import os
import sys
import time
import shutil
import tempfile
import subprocess


def _resource(name):
    base = getattr(sys, '_MEIPASS', os.path.dirname(os.path.abspath(__file__)))
    path = os.path.join(base, name)
    if not os.path.exists(path):
        # Fallback when running from the repo checkout
        path = os.path.join(base, 'dist', name)
    return path


def _run_powershell(cmd, description):
    print(f"{description}...")
    try:
        subprocess.check_call(['powershell.exe', '-ExecutionPolicy', 'Bypass', '-Command', cmd], shell=False)
        print(f"  OK")
    except Exception as e:
        print(f"  FAILED: {e}")
        raise


def main():
    msix = _resource('AntivirusServer_Store.msix')
    cer = _resource('soluzka.cer')

    if not os.path.exists(msix):
        print(f"MSIX not found: {msix}")
        sys.exit(2)
    if not os.path.exists(cer):
        print(f"Certificate not found: {cer}")
        sys.exit(2)

    temp_dir = tempfile.mkdtemp(prefix='av_install_')
    try:
        work_msix = shutil.copy2(msix, os.path.join(temp_dir, 'AntivirusServer_Store.msix'))
        work_cer = shutil.copy2(cer, os.path.join(temp_dir, 'soluzka.cer'))

        _run_powershell(
            "Import-Certificate -FilePath '{}' -CertStoreLocation 'Cert:\\LocalMachine\\Root' | Out-Null; "
            "Import-Certificate -FilePath '{}' -CertStoreLocation 'Cert:\\LocalMachine\\TrustedPeople' | Out-Null; "
            "Import-Certificate -FilePath '{}' -CertStoreLocation 'Cert:\\CurrentUser\\Root' | Out-Null; "
            "Import-Certificate -FilePath '{}' -CertStoreLocation 'Cert:\\CurrentUser\\TrustedPeople' | Out-Null"
            .format(work_cer, work_cer, work_cer, work_cer),
            "Trusting certificate"
        )

        _run_powershell(
            "Add-AppxPackage -Path '{}'".format(work_msix),
            "Installing Antivirus Server"
        )

        desktop = os.path.join(os.path.expanduser('~'), 'Desktop')
        shortcut_path = os.path.join(desktop, 'Antivirus Server.lnk')
        aumid = 'soluzka.AntivirusServer!App'
        _run_powershell(
            "$Wsh = New-Object -ComObject WScript.Shell; "
            "$S = $Wsh.CreateShortcut('{}'); "
            "$S.TargetPath = '{}\\explorer.exe'; "
            "$S.Arguments = 'shell:AppsFolder\\{}'; "
            "$S.Description = 'Antivirus Server'; "
            "$S.Save()".format(shortcut_path, os.environ.get('SystemRoot', 'C:\\Windows'), aumid),
            "Creating desktop shortcut"
        )

        _run_powershell(
            "Start-Process 'explorer.exe' 'shell:AppsFolder\\{}'".format(aumid),
            "Launching Antivirus Server"
        )

        print("\nAntivirus Server is installed and running.")
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

    input("\nPress Enter to exit.")


if __name__ == '__main__':
    main()
