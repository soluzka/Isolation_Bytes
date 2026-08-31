"""Build a WinRAR self-extracting installer for the Antivirus Server package."""
import os
import sys
import glob
import shutil
import subprocess
import tempfile
from pathlib import Path
import PyInstaller.__main__

base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
dist_dir = os.environ.get('ANTIVIRUS_BUILD_DIST', os.path.join(base_dir, 'dist'))
app = os.path.join(base_dir, 'installer_app.py')
msix = os.path.join(dist_dir, 'IsolationBytes.msix')
cer = os.path.join(dist_dir, 'IsolationBytes.cer')
standalone = os.path.join(dist_dir, 'antivirus_server')
identity_msix = os.path.join(dist_dir, 'IsolationBytes_Identity.msix')
include_local_model = '--include-local-model' in sys.argv

if not os.path.exists(msix):
    print('IsolationBytes.msix not found at', msix)
    print('Run "python build_config.py" first to build the MSIX.')
    sys.exit(2)

if not os.path.exists(cer):
    print('IsolationBytes.cer not found at', cer)
    print('Run "python build_config.py" first.')
    sys.exit(2)

if not os.path.isdir(standalone):
    print('Standalone application bundle not found at', standalone)
    print('Run "python build_config.py" first.')
    sys.exit(2)

work_root = Path(tempfile.mkdtemp(prefix='antivirus_installer_work_'))
stage_root = Path(tempfile.mkdtemp(prefix='antivirus_installer_sfx_'))
installer_payload = os.path.join(dist_dir, 'Install_AntivirusServer')
if os.path.isdir(installer_payload):
    shutil.rmtree(installer_payload)
    print('Removed stale installer payload before rebuilding.')

if include_local_model:
    print('Including local GGUF assistant model in the MSIX installer.')
else:
    print('Building the MSIX-only installer without the local assistant model.')

# PyInstaller reuses a same-named spec file if it exists; remove stale specs
# so the current data list is used for this installer build.
stale_spec = os.path.join(base_dir, 'Install_AntivirusServer.spec')
if os.path.exists(stale_spec):
    os.remove(stale_spec)

args = [
    '--name=Install_AntivirusServer',
    '--onedir',
    '--clean',
    '--uac-admin',
    '--noconfirm',
    '--log-level=INFO',
    '--distpath', dist_dir,
    '--workpath', str(work_root),
    app,
]

upx = shutil.which('upx')
if not upx:
    user_upx = os.path.join(os.environ.get('LOCALAPPDATA', ''), 'UPX', 'upx.exe')
    candidates = [user_upx, *glob.glob(r'C:\Users\*\AppData\Local\UPX\upx.exe')]
    upx = next((path for path in candidates if os.path.isfile(path)), None)
if upx:
    args.extend(['--upx-dir', os.path.dirname(upx)])
    print('UPX compression enabled:', upx)
else:
    print('UPX not found; executable compression is disabled.')

print('Building onedir installer with:', args)
try:
    PyInstaller.__main__.run(args)
finally:
    shutil.rmtree(work_root, ignore_errors=True)

# Build the .NET 8 SDK launcher EXE so the SFX can launch it post-install.
sdk_app = os.path.join(base_dir, 'tools', 'install_dotnet_sdk.py')
sdk_work = Path(tempfile.mkdtemp(prefix='antivirus_dotnet_sdk_work_'))
sdk_args = [
    '--name=Install .NET 8 SDK',
    '--onefile',
    '--noconsole',
    '--clean',
    '--uac-admin',
    '--noconfirm',
    '--log-level=INFO',
    '--distpath', dist_dir,
    '--workpath', str(sdk_work),
    sdk_app,
]
if upx:
    sdk_args.extend(['--upx-dir', os.path.dirname(upx)])
try:
    PyInstaller.__main__.run(sdk_args)
finally:
    shutil.rmtree(sdk_work, ignore_errors=True)

sdk_exe = os.path.join(dist_dir, 'Install .NET 8 SDK.exe')
if os.path.exists(sdk_exe):
    shutil.copy2(sdk_exe, stage_root / 'Install .NET 8 SDK.exe')

# Build decorated GUI launchers for the remaining components.
for launcher_name, launcher_app in (
    ('Start Antivirus Server', 'tools/start_antivirus_server.py'),
    ('Run SFX Installer', 'tools/run_sfx_installer.py'),
):
    launcher_src = os.path.join(base_dir, *launcher_app.split('/'))
    if os.path.exists(launcher_src):
        launcher_work = Path(tempfile.mkdtemp(prefix='antivirus_launcher_work_'))
        launcher_args = [
            f'--name={launcher_name}',
            '--onefile',
            '--noconsole',
            '--clean',
            '--uac-admin',
            '--noconfirm',
            '--log-level=INFO',
            '--distpath', dist_dir,
            '--workpath', str(launcher_work),
            launcher_src,
        ]
        if upx:
            launcher_args.extend(['--upx-dir', os.path.dirname(upx)])
        try:
            PyInstaller.__main__.run(launcher_args)
        finally:
            shutil.rmtree(launcher_work, ignore_errors=True)

# Build the C# login/activation launcher. This is a single EXE with no temp files and no Python source.
login_proj = os.path.join(base_dir, 'native', 'AntivirusServerLogin', 'AntivirusServerLogin.csproj')
if os.path.exists(login_proj):
    print('Embedding website login HTML and .env into the C# launcher with heavy obfuscation...')
    subprocess.run([sys.executable, os.path.join(base_dir, 'tools', 'embed_resources.py')], check=True)

    print('Building C# Antivirus Server Login launcher...')
    login_publish = Path(tempfile.mkdtemp(prefix='antivirus_login_publish_'))
    try:
        dotnet = shutil.which('dotnet')
        if not dotnet:
            dotnet = r'C:\Program Files\dotnet\dotnet.exe'
            if not os.path.exists(dotnet):
                dotnet = os.path.join(os.environ.get('LOCALAPPDATA', os.path.expanduser('~')), r'Microsoft\dotnet\dotnet.exe')
        if not os.path.exists(dotnet):
            raise FileNotFoundError('dotnet SDK not found; cannot build login launcher')
        subprocess.check_call([
            dotnet, 'publish', login_proj,
            '-c', 'Release',
            '-r', 'win-x64',
            '--self-contained', 'false',
            '-o', str(login_publish),
        ])
        built_login = login_publish / 'AntivirusServerLogin.exe'
        if built_login.exists():
            final_login = os.path.join(dist_dir, 'IsolationBytesLogin.exe')
            shutil.copy2(str(built_login), final_login)
        else:
            print('WARNING: C# login build did not produce AntivirusServerLogin.exe')
    finally:
        shutil.rmtree(login_publish, ignore_errors=True)

for launcher_file in ('Install .NET 8 SDK.bat', 'Start Antivirus Server.bat'):
    src = os.path.join(base_dir, launcher_file)
    if os.path.exists(src):
        shutil.copy2(src, stage_root / launcher_file)

for launcher_name in ('Start Antivirus Server', 'AntivirusServerLogin', 'IsolationBytesLogin'):
    exe = os.path.join(dist_dir, f'{launcher_name}.exe')
    if os.path.exists(exe):
        shutil.copy2(exe, stage_root / f'{launcher_name}.exe')

# Bundle a full .NET 8 SDK so the target PC does not need to download it.
sdk_zip = stage_root / 'dotnet-sdk-8.0.424-win-x64.zip'
if not sdk_zip.exists():
    print('Downloading .NET 8 SDK zip for offline bundle...')
    try:
        import urllib.request
        urllib.request.urlretrieve(
            'https://dotnetcli.azureedge.net/dotnet/Sdk/8.0.424/dotnet-sdk-8.0.424-win-x64.zip',
            str(sdk_zip),
        )
    except Exception as e:
        print('WARNING: could not download .NET 8 SDK zip for bundling:', e)

sfx_launcher = stage_root / 'Install_AntivirusServer'
shutil.copytree(installer_payload, sfx_launcher)
if include_local_model:
    shutil.copytree(standalone, stage_root / 'antivirus_server')
else:
    shutil.copytree(
        standalone,
        stage_root / 'antivirus_server',
        ignore=shutil.ignore_patterns('*.gguf'),
    )
shutil.copy2(msix, stage_root / 'IsolationBytes.msix')
shutil.copy2(cer, stage_root / 'IsolationBytes.cer')
if os.path.exists(identity_msix):
    shutil.copy2(identity_msix, stage_root / 'IsolationBytes_Identity.msix')

winrar = r'C:\Program Files\WinRAR\WinRAR.exe'
if not os.path.exists(winrar):
    raise FileNotFoundError(f'WinRAR was not found at {winrar}')

sfx_output = os.path.join(dist_dir, 'Install_AntivirusServer_SFX.exe')
sfx_fd, sfx_path = tempfile.mkstemp(prefix='antivirus_server_sfx_', suffix='.txt')
os.close(sfx_fd)
sfx_config = Path(sfx_path)
sfx_config.write_text(
    'TempMode=1\n'
    'Silent=1\n'
    'Overwrite=1\n'
    'Setup=Install_AntivirusServer\\Install_AntivirusServer.exe\n',
    encoding='utf-8',
)
if os.path.exists(sfx_output):
    os.remove(sfx_output)
    print('Removed previous SFX before rebuilding.')

payloads = [
    'Install_AntivirusServer',
    'IsolationBytes.msix',
    'IsolationBytes.cer',
    'antivirus_server',
    'Install .NET 8 SDK.exe',
    'Start Antivirus Server.exe',
    'AntivirusServerLogin.exe',
    'IsolationBytesLogin.exe',
    'Install .NET 8 SDK.bat',
    'Start Antivirus Server.bat',
    'dotnet-sdk-8.0.424-win-x64.zip',
]
for service_file in ('manage_admin_service.ps1', 'windows_admin_service.py'):
    if os.path.exists(os.path.join(base_dir, service_file)):
        shutil.copy2(os.path.join(base_dir, service_file), stage_root / service_file)
        payloads.append(service_file)
if os.path.exists(identity_msix):
    payloads.append('IsolationBytes_Identity.msix')

try:
    print('Creating WinRAR self-extracting installer:', sfx_output)
    subprocess.check_call([
        winrar,
        'a',
        '-sfx',
        '-m5',
        '-y',
        f'-z{sfx_config}',
        sfx_output,
        *payloads,
    ], cwd=stage_root)
finally:
    sfx_config.unlink(missing_ok=True)
    shutil.rmtree(stage_root, ignore_errors=True)

installer_payload = os.path.join(dist_dir, 'Install_AntivirusServer')
if os.path.isdir(installer_payload):
    shutil.rmtree(installer_payload)
    print('Removed unpacked installer payload after creating the SFX.')
print('Done. Single-file installer: ' + sfx_output)
