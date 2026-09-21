"""Build script for Isolation Bytes MSIX.

Builds:
  1. antivirus_server.exe (PyInstaller onedir from antivirus_server.spec)
     — the local dashboard/launcher that serves the web UI.
  2. IsolationBytes.exe (WPF WebView2 app via dotnet publish)
     — the MSIX shell that loads isolation-bytes.com in a desktop window.
  3. IsolationBytes.msix — packs both into a signed MSIX installer.

Usage:
    python build_config.py              # build everything (does not install)
    python build_config.py --skip-exe   # skip PyInstaller, MSIX only
"""

import os
import sys
import subprocess
import shutil
import re
import argparse
import zipfile
import contextlib

from utils.subprocess_safe import safe_run

# ---------------------------------------------------------------------------
# Paths and version
# ---------------------------------------------------------------------------

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DIST_DIR = os.path.join(BASE_DIR, 'dist')
BUILD_DIR = os.path.join(BASE_DIR, 'build')
NATIVE_DIR = os.path.join(BASE_DIR, 'native', 'IsolationBytesMSIX')
CSPROJ = os.path.join(NATIVE_DIR, 'IsolationBytes.csproj')
MANIFEST = os.path.join(NATIVE_DIR, 'Package.appxmanifest')
PFX = os.path.join(NATIVE_DIR, 'IsolationBytes.pfx')
PFX_PASSWORD = os.environ.get('ISOLATION_BYTES_PFX_PASSWORD', 'IsolationBytes2026')

# Windows SDK tools
SDK_BIN = r'C:\Program Files (x86)\Windows Kits\10\bin\10.0.22621.0\x64'
MAKEAPPX = os.path.join(SDK_BIN, 'makeappx.exe')
SIGNTOOL = os.path.join(SDK_BIN, 'signtool.exe')

VERSION_FILE = os.path.join(BASE_DIR, 'version.txt')
with open(VERSION_FILE, encoding='utf-8') as f:
    VERSION_TXT = f.read().strip()
parts = [int(p) for p in VERSION_TXT.split('.')]
if len(parts) == 3:
    parts.append(0)
APP_VERSION = '.'.join(str(p) for p in parts)

# Secure API key injection for build-time secrets (source stays clean)
CLOUD_API_KEY = os.environ.get('CLOUD_API_KEY', '')
PROGRAM_CS = os.path.join(BASE_DIR, 'native', 'AntivirusServerLogin', 'Program.cs')
MAINWINDOW_CS = os.path.join(NATIVE_DIR, 'MainWindow.xaml.cs')
SW_JS = os.path.join(BASE_DIR, 'static', 'sw.js')
BG_JS = os.path.join(BASE_DIR, 'browser_extension', 'background.js')


@contextlib.contextmanager
def _with_secret_injection(file_path, placeholder='__CLOUD_API_KEY__', secret=None):
    """Temporarily replace a placeholder in a file with a build secret."""
    if not secret or not os.path.isfile(file_path):
        yield
        return
    with open(file_path, 'r', encoding='utf-8') as f:
        original = f.read()
    if placeholder not in original:
        yield
        return
    try:
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(original.replace(placeholder, secret))
        yield
    finally:
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(original)


parser = argparse.ArgumentParser(description='Build Isolation Bytes MSIX')
parser.add_argument('--skip-exe', action='store_true',
                    help='Skip PyInstaller build, MSIX only')
args = parser.parse_args()


def run(cmd, **kw):
    """Run a build command and preserve actionable child diagnostics."""
    cmd = [str(x) for x in cmd]
    print(f'>>> {" ".join(cmd)}')
    kw.setdefault('check', True)
    return safe_run(cmd, **kw)


def _run_buildconfig():
    """Run buildconfig.py without hiding the real child-process failure."""
    buildconfig = os.path.join(BASE_DIR, 'buildconfig.py')
    if not os.path.isfile(buildconfig):
        print('NOTE: buildconfig.py not found — skipping cloud server + login exe build.')
        return True

    print(f'\n{"="*60}\nBuilding cloud_server.exe + IsolationBytesAgent.exe + IsolationBytesLogin.exe\n{"="*60}')
    command = [sys.executable, buildconfig]

    # Keep the child output visible.  The previous implementation used
    # check=True, which converted the useful inner failure into only:
    # "CalledProcessError ... buildconfig.py ... exit status 1".
    result = safe_run(
        command,
        cwd=BASE_DIR,
        stdout=None,
        stderr=None,
        check=False,
    )

    if result.returncode == 0:
        login_exe = os.path.join(DIST_DIR, 'IsolationBytesLogin.exe')
        if os.path.isfile(login_exe):
            login_size = os.path.getsize(login_exe) / 1048576
            print(f'IsolationBytesLogin.exe built ({login_size:.1f} MB)')
        return True

    print(f'\nERROR: buildconfig.py failed with exit code {result.returncode}.')
    print('The failure occurred inside buildconfig.py, not in the MSIX wrapper.')

    # The child builder writes separate logs for the PyInstaller targets.
    # Show their locations so the first actionable error is immediately
    # available instead of requiring the user to reproduce the build.
    for log_name in ('cloud_server-build.log', 'agent-build.log'):
        log_path = os.path.join(BASE_DIR, log_name)
        if os.path.isfile(log_path):
            print(f'  Build log: {log_path}')

    raise SystemExit(result.returncode)


def _ensure_spec_excludes(spec_path, modules):
    """Normalize PyInstaller Analysis options without spec-incompatible CLI flags."""
    import ast

    with open(spec_path, 'r', encoding='utf-8') as f:
        content = f.read()
    if not re.search(r'\bAnalysis\s*\(', content):
        raise RuntimeError(f'Could not find Analysis() in PyInstaller spec: {spec_path}')
    wanted = list(dict.fromkeys(str(m) for m in modules))
    lines = content.splitlines()
    normalized = []
    hook_found = False
    excludes_found = False
    skip_excludes_continuation = False

    for line in lines:
        stripped = line.strip()
        if skip_excludes_continuation:
            if ']' in line:
                skip_excludes_continuation = False
            continue
        if stripped.startswith('hookspath='):
            hook_found = True
        if stripped.startswith('excludes='):
            excludes_found = True
            prefix, _, remainder = line.partition('[')
            existing = []
            if ']' in remainder:
                remainder = remainder.split(']', 1)[0]
                try:
                    existing = ast.literal_eval('[' + remainder + ']')
                except Exception:
                    existing = []
            merged = list(dict.fromkeys([str(x) for x in existing] + wanted))
            indent = line[:len(line) - len(line.lstrip())]
            normalized.append(f"{indent}excludes={merged!r},")
            if ']' not in line:
                skip_excludes_continuation = True
            continue
        normalized.append(line)

    if not hook_found:
        for i, line in enumerate(normalized):
            if line.strip().startswith('pathex='):
                normalized.insert(i + 1, "    hookspath=[],")
                break

    if not excludes_found:
        for i, line in enumerate(normalized):
            if line.strip() == 'noarchive=False,':
                normalized.insert(i, f"    excludes={wanted!r},")
                break

    with open(spec_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(normalized) + '\n')


# ---------------------------------------------------------------------------
# 1. Build cloud_server.exe + IsolationBytesLogin.exe (via buildconfig.py)
# ---------------------------------------------------------------------------

if not args.skip_exe:
    buildconfig = os.path.join(BASE_DIR, 'buildconfig.py')
    if os.path.isfile(buildconfig):
        with _with_secret_injection(PROGRAM_CS, secret=CLOUD_API_KEY):
            _run_buildconfig()
    else:
        print('NOTE: buildconfig.py not found — skipping cloud server + login exe build.')

# ---------------------------------------------------------------------------
# 2. Build antivirus_server.exe from .spec (PyInstaller onedir)
# ---------------------------------------------------------------------------

if not args.skip_exe:
    # Clean previous output
    for stale in ['antivirus_server']:
        p = os.path.join(DIST_DIR, stale)
        if os.path.isdir(p):
            shutil.rmtree(p, ignore_errors=True)
    if os.path.isdir(BUILD_DIR):
        shutil.rmtree(BUILD_DIR, ignore_errors=True)

    spec = os.path.join(BASE_DIR, 'antivirus_server.spec')

    print(f'\n{"="*60}\nBuilding antivirus_server.exe (PyInstaller)\n{"="*60}')
    _generate_antivirus_server_spec(spec)
    run([sys.executable, '-m', 'PyInstaller', spec,
         '--noconfirm',
         '--distpath', DIST_DIR,
         '--workpath', BUILD_DIR])
    print('antivirus_server.exe build complete.')

    onedir = os.path.join(DIST_DIR, 'antivirus_server')
    if not os.path.isdir(onedir):
        print(f'ERROR: onedir not found at {onedir}')
        sys.exit(1)
    print(f'Onedir: {onedir}')

    # ── Build the universal launcher as a single standalone EXE ──
    launcher_spec = os.path.join(BASE_DIR, 'universal_launcher.spec')
    launcher_source = os.path.join(BASE_DIR, 'universal_launcher.py')
    launcher_dist_source = os.path.join(DIST_DIR, 'universal_launcher.py')

    if os.path.isfile(launcher_spec) and (os.path.isfile(launcher_source) or os.path.isfile(launcher_dist_source)):
        print(f'\n{"="*60}\nBuilding universal launcher EXE\n{"="*60}')
        if not os.path.isfile(launcher_dist_source) and os.path.isfile(launcher_source):
            shutil.copy2(launcher_source, launcher_dist_source)
        _ensure_spec_excludes(launcher_spec, ('pydantic', 'pydantic_core'))
        try:
            run([sys.executable, '-m', 'PyInstaller', launcher_spec,
                 '--noconfirm',
                 '--distpath', DIST_DIR,
                 '--workpath', BUILD_DIR])
        except subprocess.CalledProcessError as exc:
            print(f'WARNING: optional universal launcher build failed (exit {exc.returncode}).')
            print('         Continuing with the Windows WPF/MSIX launcher.')
        launcher_exe = os.path.join(DIST_DIR, 'IsolationBytesLauncher.exe')
        if os.path.isfile(launcher_exe):
            print(f'Universal launcher: {launcher_exe}')
    else:
        print('NOTE: Optional universal launcher source/spec not available — skipping Python launcher EXE.')

    # ── Validate the standalone agent as a true ONEFILE ──
    print(f'\n{"="*60}\nValidating standalone agent ONEFILE\n{"="*60}')
    agent_exe = os.path.join(DIST_DIR, 'IsolationBytesAgent.exe')
    stale_agent_dir = os.path.join(DIST_DIR, 'IsolationBytesAgent')
    if os.path.isdir(stale_agent_dir):
        shutil.rmtree(stale_agent_dir, ignore_errors=True)
        if os.path.isdir(stale_agent_dir):
            print(f'ERROR: stale agent directory could not be removed: {stale_agent_dir}')
            sys.exit(1)
    if not os.path.isfile(agent_exe):
        print(f'ERROR: IsolationBytesAgent.exe not found at {agent_exe}')
        print('The agent must be produced by buildconfig.py as a PyInstaller ONEFILE.')
        sys.exit(1)
    agent_size = os.path.getsize(agent_exe) / 1048576
    print(f'IsolationBytesAgent.exe: {agent_size:.1f} MB (ONEFILE)')

# ---------------------------------------------------------------------------
# 2. Update version
# ---------------------------------------------------------------------------

update_version(APP_VERSION)

# ---------------------------------------------------------------------------
# 3. dotnet publish — compile the IsolationBytes WPF WebView2 app
# ---------------------------------------------------------------------------

dotnet = find_dotnet()

# Clean previous .NET outputs
for d in ['msix', 'bin', 'obj']:
    p = os.path.join(NATIVE_DIR, d)
    if os.path.isdir(p):
        shutil.rmtree(p, ignore_errors=True)

print(f'\n{"="*60}\nCompiling IsolationBytes WPF launcher\n{"="*60}')
with _with_secret_injection(MAINWINDOW_CS, secret=CLOUD_API_KEY):
    run([dotnet, 'publish', CSPROJ,
         '-c', 'Release',
         '-r', 'win-x64',
         '-p:Platform=x64',
         '--self-contained', 'false'])

publish_dir = os.path.join(NATIVE_DIR, 'bin', 'x64', 'Release',
                           'net8.0-windows', 'win-x64', 'publish')
if not os.path.isdir(publish_dir):
    print(f'ERROR: publish output not found at {publish_dir}')
    sys.exit(1)

# ---------------------------------------------------------------------------
# 4. Stage the MSIX contents (WPF app + antivirus_server onedir)
# ---------------------------------------------------------------------------

print(f'\n{"="*60}\nStaging MSIX contents\n{"="*60}')
stage_dir = os.path.join(NATIVE_DIR, 'staging')
if os.path.isdir(stage_dir):
    shutil.rmtree(stage_dir, ignore_errors=True)
os.makedirs(stage_dir)

for item in os.listdir(publish_dir):
    src = os.path.join(publish_dir, item)
    dst = os.path.join(stage_dir, item)
    if os.path.isdir(src):
        shutil.copytree(src, dst, dirs_exist_ok=True)
    else:
        shutil.copy2(src, dst)

shutil.copy2(MANIFEST, os.path.join(stage_dir, 'AppxManifest.xml'))

server_dst = os.path.join(stage_dir, 'antivirus_server')
shutil.copytree(onedir, server_dst, dirs_exist_ok=True)
print(f'Embedded antivirus_server onedir ({len(os.listdir(server_dst))} items) into MSIX staging')

agent_exe = os.path.join(DIST_DIR, 'IsolationBytesAgent.exe')
if os.path.isfile(agent_exe):
    agent_dst = os.path.join(stage_dir, 'IsolationBytesAgent.exe')
    shutil.copy2(agent_exe, agent_dst)
    print(f'Embedded IsolationBytesAgent.exe ({os.path.getsize(agent_dst) / 1048576:.1f} MB) into MSIX staging')
else:
    print('WARNING: IsolationBytesAgent.exe not found — MSIX will not include the agent')

total_items = sum(len(files) for _, _, files in os.walk(stage_dir))
print(f'Staged {total_items} total files in {stage_dir}')

print(f'\n{"="*60}\nPacking IsolationBytes MSIX v{APP_VERSION}\n{"="*60}')

os.makedirs(DIST_DIR, exist_ok=True)
msix_path = os.path.join(DIST_DIR, 'IsolationBytes.msix')

temp_msix = os.path.join(os.environ.get('TEMP', os.path.expanduser('~')),
                         'IsolationBytes.msix')
if os.path.isfile(temp_msix):
    os.remove(temp_msix)

run([MAKEAPPX, 'pack', '/d', stage_dir, '/p', temp_msix, '/nv', '/o'])

if os.path.isfile(msix_path):
    try:
        os.remove(msix_path)
    except OSError as e:
        print(f'WARNING: could not remove existing {msix_path}: {e}')

shutil.copy2(temp_msix, msix_path)
os.remove(temp_msix)
print(f'MSIX packed: {msix_path}')

print(f'\n{"="*60}\nSigning MSIX\n{"="*60}')
run([SIGNTOOL, 'sign', '/f', PFX, '/p', PFX_PASSWORD,
     '/fd', 'sha256', msix_path])
print('MSIX signed.')

cer_path = os.path.join(DIST_DIR, 'IsolationBytes.cer')
ps_cmd = (
    f"$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2("
    f"'{PFX}', '{PFX_PASSWORD}'); "
    f"[System.IO.File]::WriteAllBytes('{cer_path}', "
    f"$cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert))"
)
run(['powershell.exe', '-NoProfile', '-Command', ps_cmd], check=False)
if os.path.isfile(cer_path):
    print(f'Certificate exported: {cer_path}')

print(f'\n{"="*60}\nTrusting certificate\n{"="*60}')
trust_cmd = (
    f"Import-Certificate -FilePath '{cer_path}' "
    f"-CertStoreLocation Cert:\\LocalMachine\\TrustedPeople"
)
run(['powershell.exe', '-NoProfile', '-Command', trust_cmd], check=False)
print(f'Certificate trusted in LocalMachine\\TrustedPeople')

print(f'\n{"="*60}\nCopying installer scripts\n{"="*60}')
for script in ['install-windows.ps1', 'install-windows.bat',
               'install-macos.sh', 'install-linux.sh',
               'install-ios.mobileconfig', 'universal_launcher.py',
               'standalone_agent.py', 'start_agent.bat',
               'install-universal.bat', 'install-universal.sh',
               'install-android.sh', 'install-chromeos.sh']:
    src = os.path.join(DIST_DIR, script)
    if not os.path.isfile(src):
        src = os.path.join(BASE_DIR, script)
    if os.path.isfile(src):
        dst = os.path.join(DIST_DIR, script)
        if os.path.abspath(src) != os.path.abspath(dst):
            shutil.copy2(src, dst)
            print(f'Copied {script} to dist/')
        else:
            print(f'{script} already in dist/')

print(f'\n{"="*60}\nGenerating IsolationBytes.appinstaller v{APP_VERSION}\n{"="*60}')
appinstaller_path = os.path.join(DIST_DIR, 'IsolationBytes.appinstaller')
appinstaller_xml = f'''<?xml version="1.0" encoding="utf-8"?>
<AppInstaller
    xmlns="http://schemas.microsoft.com/appx/appinstaller/2018"
    Version="{APP_VERSION}"
    Uri="https://isolation-bytes.com/download/IsolationBytes.appinstaller" >
    <MainPackage
        Name="soluzka.IsolationBytes"
        Publisher="CN=soluzka, O=soluzka, C=US"
        Version="{APP_VERSION}"
        ProcessorArchitecture="x64"
        Uri="https://isolation-bytes.com/download/IsolationBytes.msix" />
    <UpdateSettings>
        <OnLaunch HoursBetweenUpdateChecks="6" ShowPrompt="true" UpdateBlocksActivation="true" />
        <AutomaticBackgroundTask />
    </UpdateSettings>
    <OptionalPackages>
    </OptionalPackages>
    <RelatedPackages>
    </RelatedPackages>
    <Dependencies>
    </Dependencies>
</AppInstaller>
'''
with open(appinstaller_path, 'w', encoding='utf-8') as f:
    f.write(appinstaller_xml)
print(f'AppInstaller generated: {appinstaller_path}')

pwa_zip = os.path.join(DIST_DIR, f'IsolationBytesPWA-v{APP_VERSION}.zip')
ext_zip = os.path.join(DIST_DIR, f'IsolationBytesChrome-v{APP_VERSION}.zip')

print(f'\n{"="*60}\nPackaging PWA and Chrome extension\n{"="*60}')

if os.path.isdir(os.path.join(BASE_DIR, 'static')):
    with _with_secret_injection(SW_JS, secret=CLOUD_API_KEY):
        with zipfile.ZipFile(pwa_zip, 'w', zipfile.ZIP_DEFLATED) as zf:
            for root, _, files in os.walk(os.path.join(BASE_DIR, 'static')):
                for file in files:
                    src = os.path.join(root, file)
                    arc = os.path.join('static', os.path.relpath(src, os.path.join(BASE_DIR, 'static')))
                    zf.write(src, arc)
    print(f'PWA packaged: {pwa_zip}')
else:
    print('WARNING: static/ not found — PWA zip skipped')

ext_dir = os.path.join(BASE_DIR, 'browser_extension')
if os.path.isdir(ext_dir):
    with _with_secret_injection(BG_JS, secret=CLOUD_API_KEY):
        with zipfile.ZipFile(ext_zip, 'w', zipfile.ZIP_DEFLATED) as zf:
            for root, _, files in os.walk(ext_dir):
                for file in files:
                    src = os.path.join(root, file)
                    arc = os.path.relpath(src, ext_dir)
                    zf.write(src, arc)
    print(f'Chrome extension packaged: {ext_zip}')
else:
    print('WARNING: browser_extension/ not found — Chrome zip skipped')

print(f'\n{"="*60}\nBuilding Android APK\n{"="*60}')

apk_dst = os.path.join(DIST_DIR, f'IsolationBytes-v{APP_VERSION}.apk')
gradlew = os.path.join(BASE_DIR, 'android', 'gradlew.bat')
if os.path.isfile(gradlew):
    run([gradlew, 'assembleRelease'], cwd=os.path.join(BASE_DIR, 'android'), check=False)
    apk_out = os.path.join(BASE_DIR, 'android', 'app', 'build', 'outputs', 'apk', 'release')
    if os.path.isdir(apk_out):
        apks = [os.path.join(apk_out, f) for f in os.listdir(apk_out) if f.endswith('.apk')]
        if apks:
            src_apk = max(apks, key=os.path.getmtime)
            shutil.copy2(src_apk, apk_dst)
            print(f'APK built and copied: {apk_dst}')
        else:
            print(f'WARNING: no APK found in {apk_out}')
    else:
        print(f'WARNING: APK output directory not found: {apk_out}')
else:
    print(f'WARNING: gradlew.bat not found — Android APK build skipped')

print(f'\n{"="*60}\nBuilding SFX installer\n{"="*60}')

sfx_builder = os.path.join(BASE_DIR, 'tools', 'build_installer_exe.py')
if os.path.isfile(sfx_builder):
    sfx_result = safe_run(
        [sys.executable, sfx_builder],
        cwd=BASE_DIR,
    )
    if sfx_result.returncode != 0:
        print('WARNING: SFX installer build failed or skipped (see errors above).')
    else:
        sfx_path = os.path.join(DIST_DIR, 'Install_AntivirusServer_SFX.exe')
        if os.path.isfile(sfx_path):
            sfx_size = os.path.getsize(sfx_path) / (1024 * 1024)
            print(f'SFX installer: {sfx_path} ({sfx_size:.1f} MB)')
else:
    print(f'WARNING: {sfx_builder} not found — SFX build skipped.')

msix_size_mb = os.path.getsize(msix_path) / (1024 * 1024)
print(f'\n{"="*60}')
print(f'Build complete!')
print(f'  Version: {APP_VERSION}')
print(f'  MSIX:    {msix_path} ({msix_size_mb:.1f} MB)')
print(f'  Cert:    {cer_path}')
print(f'  AppInstaller: {appinstaller_path}')
login_exe = os.path.join(DIST_DIR, 'IsolationBytesLogin.exe')
if os.path.isfile(login_exe):
    login_size = os.path.getsize(login_exe) / (1024 * 1024)
    print(f'  Login:   {login_exe} ({login_size:.1f} MB)')
cloud_exe = os.path.join(DIST_DIR, 'cloud_server.exe')
if os.path.isfile(cloud_exe):
    cloud_size = os.path.getsize(cloud_exe) / (1024 * 1024)
    print(f'  Cloud:   {cloud_exe} ({cloud_size:.1f} MB)')
agent_exe = os.path.join(DIST_DIR, 'IsolationBytesAgent.exe')
if os.path.isfile(agent_exe):
    agent_size = os.path.getsize(agent_exe) / (1024 * 1024)
    print(f'  Agent:   {agent_exe} ({agent_size:.1f} MB) [ONEFILE]')
launcher_exe = os.path.join(DIST_DIR, 'IsolationBytesLauncher.exe')
if os.path.isfile(launcher_exe):
    launcher_size = os.path.getsize(launcher_exe) / (1024 * 1024)
    print(f'  Launcher: {launcher_exe} ({launcher_size:.1f} MB)')
if os.path.isfile(pwa_zip):
    pwa_size = os.path.getsize(pwa_zip) / (1024 * 1024)
    print(f'  PWA:     {pwa_zip} ({pwa_size:.1f} MB)')
if os.path.isfile(ext_zip):
    ext_size = os.path.getsize(ext_zip) / (1024 * 1024)
    print(f'  Chrome:  {ext_zip} ({ext_size:.1f} MB)')
if os.path.isfile(apk_dst):
    apk_size = os.path.getsize(apk_dst) / (1024 * 1024)
    print(f'  APK:     {apk_dst} ({apk_size:.1f} MB)')
sfx_path = os.path.join(DIST_DIR, 'Install_AntivirusServer_SFX.exe')
if os.path.isfile(sfx_path):
    sfx_size = os.path.getsize(sfx_path) / (1024 * 1024)
    print(f'  SFX:     {sfx_path} ({sfx_size:.1f} MB)')
print(f'  Output:  {DIST_DIR}')
print(f'{"="*60}')
