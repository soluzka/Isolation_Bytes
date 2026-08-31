"""One-click installer for the Antivirus Server MSIX package."""
import os
import sys
import time
import struct
import shutil
import tempfile
import subprocess
import zipfile
import base64


_INSTALLER_ELEVATION_FLAG = '--installer-elevation-attempted'


def _ensure_administrator():
    """Ensure the installer has permission for machine-wide setup."""
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
    roots = [base, os.path.dirname(base), os.path.dirname(os.path.dirname(base))]
    for root in roots:
        path = os.path.join(root, name)
        if os.path.exists(path):
            return path
    # Fallback when running from the repo checkout
    return os.path.join(base, 'dist', name)


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


def _install_dotnet_sdk():
    """Install the .NET 8 SDK globally so the build environment is available."""
    dotnet_dir = r'C:\Program Files\dotnet'
    dotnet_exe = os.path.join(dotnet_dir, 'dotnet.exe')
    if os.path.exists(dotnet_exe):
        try:
            result = subprocess.run([dotnet_exe, '--list-sdks'], capture_output=True, text=True, timeout=30,
                                    creationflags=0x08000000)
            if result.stdout.strip():
                print('.NET SDK already installed globally.')
                return
        except Exception:
            pass
    print('Installing .NET 8 SDK...')
    script = os.path.join(tempfile.gettempdir(), 'dotnet-install.ps1')
    command = (
        "$script = Join-Path $env:TEMP 'dotnet-install.ps1'; "
        "Invoke-WebRequest -Uri 'https://dot.net/v1/dotnet-install.ps1' -OutFile $script; "
        "& $script -Version 8.0.406 -InstallDir 'C:\\Program Files\\dotnet' -NoPath; "
        "$machinePath = [Environment]::GetEnvironmentVariable('Path', 'Machine'); "
        "if ($machinePath -notlike '*C:\\Program Files\\dotnet*') {{ "
        "    [Environment]::SetEnvironmentVariable('Path', \"$machinePath;C:\\Program Files\\dotnet\", 'Machine') "
        "}}"
    ).format()
    try:
        _run_powershell(command, 'Installing .NET 8 SDK')
    except Exception as e:
        print(f'  WARNING: .NET SDK install failed: {e}. Continuing antivirus install.')


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


def _install_standalone_bundle(source, extraction_root):
    """Install the unpacked app and elevated helper beside the MSIX."""
    if os.path.isfile(source) and source.lower().endswith('.zip'):
        extracted = os.path.join(extraction_root, 'standalone')
        os.makedirs(extracted, exist_ok=True)
        with zipfile.ZipFile(source) as archive:
            archive.extractall(extracted)
        source = extracted
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

    msix = _resource('IsolationBytes.msix')
    cer = _resource('IsolationBytes.cer')

    if not os.path.exists(msix):
        print(f"MSIX not found: {msix}")
        sys.exit(2)
    if not os.path.exists(cer):
        print(f"Certificate not found: {cer}")
        sys.exit(2)

    temp_dir = tempfile.mkdtemp(prefix='av_install_')
    try:
        work_msix = shutil.copy2(msix, os.path.join(temp_dir, 'IsolationBytes.msix'))
        work_cer = shutil.copy2(cer, os.path.join(temp_dir, 'IsolationBytes.cer'))

        _run_powershell(
            "Import-Certificate -FilePath '{}' -CertStoreLocation 'Cert:\\LocalMachine\\Root' | Out-Null; "
            "Import-Certificate -FilePath '{}' -CertStoreLocation 'Cert:\\LocalMachine\\TrustedPeople' | Out-Null; "
            "Import-Certificate -FilePath '{}' -CertStoreLocation 'Cert:\\CurrentUser\\Root' | Out-Null; "
            "Import-Certificate -FilePath '{}' -CertStoreLocation 'Cert:\\CurrentUser\\TrustedPeople' | Out-Null"
            .format(work_cer, work_cer, work_cer, work_cer),
            "Trusting certificate"
        )

        _run_powershell(
            "Get-AppxPackage -Name 'soluzka.IsolationBytes' | Remove-AppxPackage -ErrorAction SilentlyContinue; "
            "Add-AppxPackage -Path '{}' -ForceApplicationShutdown -ForceUpdateFromAnyVersion".format(work_msix),
            "Installing Isolation Bytes"
        )

        desktop_candidates = [
            os.path.join(os.environ.get('OneDrive', ''), 'Desktop'),
            os.path.join(os.path.expanduser('~'), 'Desktop'),
        ]
        desktop = next((path for path in desktop_candidates if os.path.isdir(path)), desktop_candidates[-1])
        os.makedirs(desktop, exist_ok=True)
        shortcut_path = os.path.join(desktop, 'Isolation Bytes.lnk')
        _run_powershell(
            "$pkg = Get-AppxPackage -Name 'soluzka.IsolationBytes'; "
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

        install_root = os.path.join(os.environ.get('ProgramFiles', r'C:\\Program Files'), 'Antivirus Server')
        os.makedirs(install_root, exist_ok=True)

        # Launch the decorated .NET 8 SDK installer. The full SDK zip is
        # bundled in the SFX and copied to the install root before launching.
        sdk_exe = _resource('Install .NET 8 SDK.exe')
        sdk_zip = _resource('dotnet-sdk-8.0.424-win-x64.zip')
        if os.path.exists(sdk_exe):
            for launcher_name in ('Install .NET 8 SDK.bat', 'Start Antivirus Server.bat', 'Start Antivirus Server.exe', 'AntivirusServerLogin.exe', 'IsolationBytesLogin.exe'):
                launcher = _resource(launcher_name)
                if os.path.exists(launcher):
                    shutil.copy2(launcher, os.path.join(install_root, launcher_name))
            sdk_target = os.path.join(install_root, 'Install .NET 8 SDK.exe')
            sdk_zip_target = os.path.join(install_root, 'dotnet-sdk-8.0.424-win-x64.zip')
            shutil.copy2(sdk_exe, sdk_target)
            if os.path.exists(sdk_zip):
                shutil.copy2(sdk_zip, sdk_zip_target)
            print('Launching decorated .NET 8 SDK installer...')
            try:
                args = [sdk_target]
                if os.path.exists(sdk_zip_target):
                    args.append(sdk_zip_target)
                proc = subprocess.Popen(args, creationflags=subprocess.CREATE_NEW_CONSOLE)  # nosec B603
                proc.wait()
                print('  .NET SDK installer finished.')
            except Exception as e:
                print(f'  WARNING: could not launch .NET SDK installer: {e}')
            sdk_shortcut = os.path.join(desktop, 'Install .NET 8 SDK.lnk')
            shortcut_args = sdk_zip_target if os.path.exists(sdk_zip_target) else ''
            _run_powershell(
                "$Wsh = New-Object -ComObject WScript.Shell; "
                "$S = $Wsh.CreateShortcut('{}'); "
                "$S.TargetPath = '{}'; "
                "$S.Arguments = '{}'; "
                "$S.Description = 'Install .NET 8 SDK'; "
                "$S.Save()".format(
                    sdk_shortcut.replace("'", "''"),
                    sdk_target.replace("'", "''"),
                    shortcut_args.replace("'", "''"),
                ),
                "Creating Install .NET 8 SDK shortcut"
            )

        # Create shortcuts that always go through the protected login launcher.
        start_exe = os.path.join(install_root, 'Start Antivirus Server.exe')
        for lnk_name, target, desc in [
            ('Start Antivirus Server.lnk', start_exe, 'Start Antivirus Server (opens secure login)'),
            ('Isolation Bytes Login.lnk', os.path.join(install_root, 'AntivirusServerLogin.exe'), 'Isolation Bytes Login'),
        ]:
            sc_path = os.path.join(desktop, lnk_name)
            _run_powershell(
                "$Wsh = New-Object -ComObject WScript.Shell; "
                "$S = $Wsh.CreateShortcut('{}'); "
                "$S.TargetPath = '{}'; "
                "$S.Description = '{}'; "
                "$S.Save()".format(
                    sc_path.replace("'", "''"),
                    target.replace("'", "''"),
                    desc.replace("'", "''"),
                ),
                "Creating {} shortcut".format(desc)
            )
            _clear_shortcut_runas(sc_path)

        # Install the unpacked administrator bundle alongside the MSIX.
        try:
            standalone_root = os.path.join(os.environ.get('ProgramFiles', r'C:\\Program Files'), 'Antivirus Server')
            standalone_bundle = _resource('antivirus_server.zip')
            if not os.path.exists(standalone_bundle):
                standalone_bundle = _resource('antivirus_server')
            helper_path = _install_standalone_bundle(standalone_bundle, temp_dir)
            _create_admin_shortcuts(helper_path, desktop)
            for service_file in ('manage_admin_service.ps1', 'windows_admin_service.py'):
                source = _resource(service_file)
                if os.path.isfile(source):
                    shutil.copy2(source, os.path.join(standalone_root, service_file))
            identity_msix = _resource('IsolationBytes_Identity.msix')
            if os.path.exists(identity_msix):
                _run_powershell(
                    "Get-AppxPackage -Name 'soluzka.IsolationBytes.External' | Remove-AppxPackage -ErrorAction SilentlyContinue; "
                    "Add-AppxPackage -Path '{}' -ExternalLocation '{}' -ErrorAction Stop".format(identity_msix, standalone_root),
                    "Registering external-location identity"
                )
        except Exception as error:
            print(f"  WARNING: Administrator helper/identity setup failed: {error}")

        login_target = os.path.join(install_root, 'AntivirusServerLogin.exe')
        if not os.path.exists(login_target):
            login_target = os.path.join(install_root, 'IsolationBytesLogin.exe')
        if os.path.exists(login_target):
            _run_powershell(
                "$Wsh = New-Object -ComObject WScript.Shell; "
                "$S = $Wsh.CreateShortcut('{}'); "
                "$S.TargetPath = '{}'; "
                "$S.Description = 'Isolation Bytes Login'; "
                "$S.Save()".format(
                    os.path.join(desktop, 'Isolation Bytes Login.lnk').replace("'", "''"),
                    login_target.replace("'", "''"),
                ),
                "Creating login shortcut"
            )
            print('Launching Isolation Bytes Login...')
            try:
                subprocess.Popen([login_target], creationflags=subprocess.CREATE_NEW_CONSOLE)  # nosec B603
            except Exception as e:
                print(f'  WARNING: could not launch login: {e}')

        print("\nAntivirus Server is installed. Please activate with the login window.")
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


if __name__ == '__main__':
    main()
