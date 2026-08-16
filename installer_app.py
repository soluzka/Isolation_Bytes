"""One-click installer for the Antivirus Server MSIX package."""
import os
import sys
import time
import struct
import shutil
import tempfile
import subprocess
import base64


_INSTALLER_ELEVATION_FLAG = '--installer-elevation-attempted'


def _ensure_administrator():
    """Ensure the one-file installer has permission for machine-wide setup."""
    if sys.platform != 'win32' or _INSTALLER_ELEVATION_FLAG in sys.argv:
        return True
    try:
        import ctypes
        if ctypes.windll.shell32.IsUserAnAdmin():
            return True
        params = [*sys.argv[1:], _INSTALLER_ELEVATION_FLAG]
        command_line = ' '.join(f'"{arg}"' if ' ' in arg else arg for arg in params)
        result = ctypes.windll.shell32.ShellExecuteW(
            None, 'runas', sys.executable, command_line, None, 1
        )
        if result <= 32:
            print('Administrator privileges were not granted.', file=sys.stderr)
            return False
        return None
    except Exception as error:
        print(f'Could not request Administrator privileges: {error}', file=sys.stderr)
        return False


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
        if description.startswith('Creating '):
            print('  Continuing installation; shortcut creation is non-critical.')
            return False
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


def _install_standalone_bundle(source):
    """Install the unpacked app and elevated helper beside the MSIX."""
    program_files = os.environ.get('ProgramFiles', r'C:\\Program Files')
    target = os.path.join(program_files, 'Antivirus Server')
    if not os.path.isdir(source):
        raise FileNotFoundError(f'Standalone bundle not found: {source}')
    os.makedirs(target, exist_ok=True)
    shutil.copytree(source, target, dirs_exist_ok=True)
    return os.path.join(target, 'AntivirusServer_AdminHelper.exe')


def _create_admin_shortcuts(helper_path, desktop):
    """Create shortcuts that target the unpacked elevated helper."""
    helper = helper_path.replace("'", "''")
    desktop_path = desktop.replace("'", "''")
    command = f"""
$wsh = New-Object -ComObject WScript.Shell
$desktop = '{desktop_path}'
$items = @(
    @{{ Name = 'Antivirus Server (Administrator).lnk'; Args = '' }},
    @{{ Name = 'Start Conditional Antivirus (Administrator).lnk'; Args = '' }},
    @{{ Name = 'Start YARA Scanner (Administrator).lnk'; Args = '--open-yara' }}
)
foreach ($item in $items) {{
    $s = $wsh.CreateShortcut((Join-Path $desktop $item.Name))
    $s.TargetPath = '{helper}'
    $s.Arguments = $item.Args
    $s.WorkingDirectory = Split-Path -Parent '{helper}'
    $s.IconLocation = '{helper},0'
    $s.Description = 'Antivirus Server (Administrator)'
    $s.Save()
}}
"""
    _run_powershell(command, 'Creating Administrator shortcuts')


def main():
    elevated = _ensure_administrator()
    if elevated is None:
        return
    if not elevated:
        sys.exit(1)

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

        desktop_candidates = [
            os.path.join(os.environ.get('OneDrive', ''), 'Desktop'),
            os.path.join(os.path.expanduser('~'), 'Desktop'),
        ]
        desktop = next((path for path in desktop_candidates if os.path.isdir(path)), desktop_candidates[-1])
        os.makedirs(desktop, exist_ok=True)
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

        # Create MSIX shortcuts through the registered AUMID. Direct shortcuts
        # into WindowsApps can produce an access-denied launch error.
        for name, desc in [
            ('Start Conditional Antivirus (MSIX).lnk', 'Start Conditional Antivirus (MSIX)'),
            ('Start YARA Scanner (MSIX).lnk', 'Start YARA Scanner (MSIX)'),
        ]:
            sc_path = os.path.join(desktop, name)
            _run_powershell(
                "$pkg = Get-AppxPackage -Name 'soluzka.AntivirusServer'; "
                "if (-not $pkg) {{ throw 'Package not found after install' }}; "
                "$aumid = $pkg.PackageFamilyName + '!App'; "
                "$exe = Join-Path $pkg.InstallLocation 'antivirus_server.exe'; "
                "$Wsh = New-Object -ComObject WScript.Shell; "
                "$S = $Wsh.CreateShortcut('{}'); "
                "$S.TargetPath = 'explorer.exe'; "
                "$S.Arguments = \"shell:AppsFolder\\$aumid\"; "
                "$S.IconLocation = \"$exe,0\"; "
                "$S.Description = '{}'; "
                "$S.Save()".format(sc_path, desc),
                "Creating {} shortcut".format(desc)
            )
            _clear_shortcut_runas(sc_path)

        # Install the unpacked administrator bundle alongside the MSIX.
        try:
            standalone_root = os.path.join(os.environ.get('ProgramFiles', r'C:\\Program Files'), 'Antivirus Server')
            helper_path = _install_standalone_bundle(_resource('antivirus_server'))
            _create_admin_shortcuts(helper_path, desktop)
            identity_msix = _resource('AntivirusServer_Identity.msix')
            if os.path.exists(identity_msix):
                _run_powershell(
                    "Get-AppxPackage -Name 'soluzka.AntivirusServer.External' | Remove-AppxPackage -ErrorAction SilentlyContinue; "
                    "Add-AppxPackage -Path '{}' -ExternalLocation '{}' -ErrorAction Stop".format(identity_msix, standalone_root),
                    "Registering external-location identity"
                )
        except Exception as error:
            print(f"  WARNING: Administrator helper/identity setup failed: {error}")

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
