"""One-click installer for the Antivirus Server MSIX package."""
import os
import sys
import time
import struct
import shutil
import tempfile
import subprocess
import base64


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
        encoded = base64.b64encode(cmd.encode('utf-16le')).decode('ascii')
        subprocess.check_call(['powershell.exe', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', encoded], shell=False)
        print(f"  OK")
    except Exception as e:
        print(f"  FAILED: {e}")
        raise


def _clear_shortcut_runas(path):
    """Clear the RunAs flag so an MSIX shortcut uses normal activation."""
    try:
        with open(path, 'r+b') as f:
            header = struct.unpack('<I', f.read(4))[0]
            if header != 0x4C:
                return
            f.seek(0x14)
            flags = struct.unpack('<I', f.read(4))[0]
            flags &= ~0x2000
            f.seek(0x14)
            f.write(struct.pack('<I', flags))
    except Exception:
        pass


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
            "Get-AppxPackage -Name 'soluzka.AntivirusServer' | Remove-AppxPackage -ErrorAction SilentlyContinue; "
            "Add-AppxPackage -Path '{}' -ForceApplicationShutdown -ForceUpdateFromAnyVersion".format(work_msix),
            "Installing Antivirus Server"
        )

        desktop = os.path.join(os.path.expanduser('~'), 'Desktop')
        shortcut_path = os.path.join(desktop, 'Antivirus Server.lnk')
        _run_powershell(
            "$pkg = Get-AppxPackage -Name 'soluzka.AntivirusServer'; "
            "if (-not $pkg) {{ throw 'Package not found after install' }}; "
            "$exe = Join-Path $pkg.InstallLocation 'antivirus_server.exe'; "
            "$aumid = $pkg.PackageFamilyName + '!App'; "
            "$Wsh = New-Object -ComObject WScript.Shell; "
            "$S = $Wsh.CreateShortcut('{}'); "
            "$S.TargetPath = 'explorer.exe'; "
            "$S.Arguments = \"shell:AppsFolder\\$aumid\"; "
            "$S.IconLocation = \"$exe,0\"; "
            "$S.Description = 'Antivirus Server'; "
            "$S.Save()".format(shortcut_path),
            "Creating desktop shortcut"
        )
        _clear_shortcut_runas(shortcut_path)

        # Create the conditional startup and YARA scanner shortcuts.
        for name, arg, desc in [
            ('Start Conditional Antivirus.lnk', '', 'Start Conditional Antivirus'),
            ('Start YARA Scanner.lnk', '--open-yara', 'Start YARA Scanner'),
        ]:
            sc_path = os.path.join(desktop, name)
            _run_powershell(
                "$pkg = Get-AppxPackage -Name 'soluzka.AntivirusServer'; "
                "if (-not $pkg) {{ throw 'Package not found after install' }}; "
                "$exe = Join-Path $pkg.InstallLocation 'antivirus_server.exe'; "
                "$Wsh = New-Object -ComObject WScript.Shell; "
                "$S = $Wsh.CreateShortcut('{}'); "
                "$S.TargetPath = $exe; "
                "$S.Arguments = '{}'; "
                "$S.WorkingDirectory = $pkg.InstallLocation; "
                "$S.IconLocation = \"$exe,0\"; "
                "$S.Description = '{}'; "
                "$S.Save()".format(sc_path, arg, desc),
                "Creating {} shortcut".format(desc)
            )
            _clear_shortcut_runas(sc_path)

        _run_powershell(
            "$pkg = Get-AppxPackage -Name 'soluzka.AntivirusServer'; "
            "if (-not $pkg) {{ throw 'Package not found after install' }}; "
            "$aumid = $pkg.PackageFamilyName + '!App'; "
            "Start-Process -FilePath 'explorer.exe' -ArgumentList \"shell:AppsFolder\\$aumid\"",
            "Launching Antivirus Server"
        )

        print("\nAntivirus Server is installed and running.")
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


if __name__ == '__main__':
    main()
