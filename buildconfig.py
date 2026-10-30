"""buildconfig.py — single source of truth for building all EXEs.

Builds both EXEs with the same configuration:
  - cloud_server.exe         (PyInstaller — Flask + Caddy + Cloudflare)
  - IsolationBytesLogin.exe  (dotnet — launcher with embedded cloud_server.exe)

The launcher embeds cloud_server.exe inside itself, so the final
IsolationBytesLogin.exe is fully self-contained — no external files needed.

Usage:
    python buildconfig.py              # build everything (cloud first, then launcher)
    python buildconfig.py --cloud      # only cloud_server.exe
    python buildconfig.py --launcher   # only IsolationBytesLogin.exe
    python buildconfig.py --clean      # clean dist/ then build everything

Everything is defined here: URLs, ports, paths, embedded files.
No separate spec file or build script needed.
"""
import os
import sys
import shutil
import subprocess
import time
from pathlib import Path

from utils.subprocess_safe import safe_popen, safe_run

# ============================================================
# SHARED CONFIGURATION — used by both EXEs
# ============================================================
PROJECT_ROOT = Path(__file__).resolve().parent
DIST_DIR = PROJECT_ROOT / 'dist'

# URLs (no port — Caddy/Cloudflare handle HTTPS on 443)
PUBLIC_URL = "https://isolation-bytes.com"
LICENSE_SERVER = "https://isolation-bytes.com"
PAYMENT_URL = os.environ.get("PAYMENT_URL", "")  # Set in .env — any store's checkout URL

# Ports
PROXY_PORT = 8000      # Flask internal (proxy mode)
HTTPS_PORT = 443       # Caddy external
DIRECT_PORT = 8443     # Flask direct (non-proxy fallback)

# External tools
CADDY_EXE = r"C:\caddy\caddy.exe"
CADDYFILE = r"C:\caddy\Caddyfile"
CLOUDFLARED_EXE = r"C:\caddy\cloudflared.exe"
DOTNET_EXE = Path(os.environ.get("LOCALAPPDATA", str(Path.home() / "AppData" / "Local"))) / "Microsoft" / "dotnet" / "dotnet.exe"

# ============================================================
# FILES TO BUNDLE IN cloud_server.exe
# ============================================================
BUNDLED_DIRS = [
    "templates", "static", "website", "security",
    "blocklists", "utils", "yara_rules",
]
BUNDLED_FILES = [
    "cloud/cert.pem",
    "cloud/localhost.crt",
    "malware_signatures.json",
    "malware_signatures.txt",
]

# ============================================================
# ML MODELS — bundle all model files except assistant.gguf (1.6 GB, disabled in cloud mode)
# ============================================================
def _get_model_files():
    """Return list of (filepath, 'models') tuples for all model files except assistant.gguf."""
    models_dir = PROJECT_ROOT / "models"
    model_files = []
    if models_dir.is_dir():
        for f in os.listdir(models_dir):
            fp = models_dir / f
            if fp.is_file() and f != "assistant.gguf":
                model_files.append((str(fp), "models"))
    return model_files

# ============================================================
# HIDDEN IMPORTS for PyInstaller
# ============================================================
HIDDEN_IMPORTS = [
    "flask", "flask.sessions", "flask_cors", "flask_limiter", "flask_wtf",
    "werkzeug", "werkzeug.middleware", "werkzeug.middleware.proxy_fix",
    "requests", "psutil", "ssl", "dnslib", "dns.resolver",
    "dotenv", "cryptography", "cryptography.fernet", "bcrypt", "pyotp",
    "security.yara_scanner", "security.c2_detector", "security.secure_memory",
    "security.local_assistant", "security.assistant_trainer",
    "security.assistant_database", "security.local_agent",
    "security.network_devices",
    "quarantine_utils", "file_crypto", "utils.paths",
    "waitress", "json", "hashlib", "secrets", "webbrowser",
    "license_manager",
    "standalone_agent", "socket", "platform", "threading", "datetime",
    "argparse", "concurrent.futures", "re", "plistlib", "urllib3",
    # ML/scanning libraries — needed for BODMAS, EMBER, sklearn models, YARA
    "sklearn", "sklearn.ensemble", "sklearn.linear_model", "sklearn.svm",
    "sklearn.tree", "sklearn.neural_network", "sklearn.preprocessing",
    "sklearn.decomposition", "sklearn.pipeline", "sklearn.metrics",
    "sklearn.model_selection",
    "numpy", "scipy", "scipy.sparse", "onnxruntime", "yara",
    "joblib", "pickle", "pandas", "pefile", "tlsh", "lief",
]

EXCLUDED_IMPORTS = [
    "tensorflow", "torch", "torch.*", "torchvision", "torchaudio",
    "transformers", "transformers.*", "accelerate", "accelerate.*",
    "sentence_transformers", "sentence_transformers.*", "safetensors", "safetensors.*",
    # This project uses cryptography, not the legacy Crypto/Cryptodome namespaces.
    # Excluding them prevents a stray/broken Crypto installation from triggering
    # pyinstaller-hooks-contrib hook-Crypto.py during Analysis.
    "Crypto", "Crypto.*", "Cryptodome", "Cryptodome.*",
    "matplotlib", "IPython", "ipykernel", "notebook", "pytest",
]

# ============================================================
# BUILD: cloud_server.exe (PyInstaller)
# ============================================================
def build_cloud_server():
    print("\n[1/2] Building cloud_server.exe (PyInstaller)...")
    print(f"  PUBLIC_URL:    {PUBLIC_URL}")
    print(f"  PROXY_PORT:    {PROXY_PORT}")
    print(f"  HTTPS_PORT:    {HTTPS_PORT}")
    print(f"  Caddy:         {CADDY_EXE}")
    print(f"  Cloudflared:   {CLOUDFLARED_EXE}")

    # Write the .env with current config
    _ensure_env_config()

    # Clean build dir
    build_dir = PROJECT_ROOT / "build"
    if build_dir.exists():
        shutil.rmtree(build_dir, ignore_errors=True)

    # Build datas list (only existing files)
    datas = []
    for d in BUNDLED_DIRS:
        src = PROJECT_ROOT / d
        if src.exists():
            datas.append((str(src), d))
    for f in BUNDLED_FILES:
        src = PROJECT_ROOT / f
        if src.exists():
            dst = os.path.dirname(f) or "."
            datas.append((str(src), dst))

    # Add ML model files (except assistant.gguf which is 1.6 GB and disabled in cloud mode)
    model_files = _get_model_files()
    datas.extend(model_files)
    print(f"  Bundling {len(model_files)} model files from models/")

    # Generate spec content
    spec_content = _generate_cloud_spec(datas)
    spec_path = PROJECT_ROOT / "cloud_server.spec"
    spec_path.write_text(spec_content, encoding="utf-8")
    print(f"  Generated spec: {spec_path}")

    # Run PyInstaller
    result = safe_run(
        [sys.executable, "-m", "PyInstaller", str(spec_path),
         "--noconfirm", "--distpath", str(DIST_DIR)],
        cwd=str(PROJECT_ROOT),
    )
    if result.returncode != 0:
        print("FAILED: cloud_server.exe build")
        return False

    exe = DIST_DIR / "cloud_server.exe"
    if not exe.exists():
        print("ERROR: cloud_server.exe not found")
        return False
    print(f"  OK: {exe.name} ({exe.stat().st_size / 1048576:.1f} MB)")
    return True


def _generate_cloud_spec(datas):
    datas_str = ",\n    ".join(f"({repr(s)}, {repr(d)})" for s, d in datas)
    hidden_str = ", ".join(repr(h) for h in HIDDEN_IMPORTS)
    excludes_str = ", ".join(repr(e) for e in EXCLUDED_IMPORTS)
    project = str(PROJECT_ROOT).replace("\\", "\\\\")
    return f"""# -*- mode: python ; coding: utf-8 -*-
# AUTO-GENERATED by buildconfig.py — do not edit manually.
import os

datas = [
    {datas_str}
]
binaries = []
hiddenimports = [{hidden_str}]
excludes = [{excludes_str}]

a = Analysis(
    [r'{project}\\cloud\\cloud_server.py'],
    pathex=[r'{project}'],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[r'{project}\\pyinstaller_hooks'],
    hooksconfig={{}},
    runtime_hooks=[],
    excludes=excludes,
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz, a.scripts, a.binaries, a.datas, [],
    name='cloud_server',
    debug=False, bootloader_ignore_signals=False, strip=False,
    upx=True, upx_exclude=[], runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False, argv_emulation=False,
    target_arch=None, codesign_identity=None, entitlements_file=None,
    icon=[r'{project}\\static\\favicon.ico'],
)
"""


# ============================================================
# EMBED RESOURCES — regenerate encrypted C# source files
# ============================================================
def embed_resources():
    print("\n  Embedding resources into launcher...")
    embed_script = PROJECT_ROOT / "tools" / "embed_resources.py"
    if not embed_script.exists():
        print("  WARNING: tools/embed_resources.py not found — skipping")
        return True
    result = safe_run([sys.executable, str(embed_script)], cwd=str(PROJECT_ROOT),
)
    if result.returncode != 0:
        print("  FAILED: embed_resources.py")
        return False
    print("  OK: Resources embedded (LoginHtml.g.cs, CloudServer.g.cs)")
    return True


# ============================================================
# GENERATE .csproj — with embedded cloud_server.exe
# ============================================================
def generate_csproj():
    csproj_path = PROJECT_ROOT / "native" / "AntivirusServerLogin" / "AntivirusServerLogin.csproj"

    content = """<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>WinExe</OutputType>
    <TargetFramework>net8.0-windows</TargetFramework>
    <UseWindowsForms>true</UseWindowsForms>
    <ImplicitUsings>enable</ImplicitUsings>
    <Nullable>enable</Nullable>
    <PublishSingleFile>true</PublishSingleFile>
    <SelfContained>true</SelfContained>
    <RuntimeIdentifier>win-x64</RuntimeIdentifier>
    <IncludeNativeLibrariesForSelfExtract>true</IncludeNativeLibrariesForSelfExtract>
    <PublishReadyToRun>false</PublishReadyToRun>
    <PublishTrimmed>false</PublishTrimmed>
    <TrimmerRemoveSymbols>true</TrimmerRemoveSymbols>
    <DebuggerSupport>false</DebuggerSupport>
    <DebugType>none</DebugType>
    <DebugSymbols>false</DebugSymbols>
    <AssemblyTitle>Isolation Bytes Login</AssemblyTitle>
    <AssemblyProduct>Isolation Bytes</AssemblyProduct>
    <AssemblyCompany>soluzka</AssemblyCompany>
    <Version>1.8.950.0</Version>
    <ApplicationManifest>app.manifest</ApplicationManifest>
    <AssemblyName>IsolationBytesLogin</AssemblyName>
  </PropertyGroup>

  <!-- No embedded cloud_server.exe, cloudflared, or Python installer.
       The login exe is a thin client that validates via the server API. -->

  <Target Name="CopyFriendlyLauncherName" AfterTargets="Publish">
    <Copy SourceFiles="$(PublishDir)IsolationBytesLogin.exe" DestinationFiles="$(PublishDir)AntivirusServerLogin.exe" />
  </Target>
</Project>
"""
    csproj_path.write_text(content, encoding="utf-8")
    print(f"  Generated csproj: {csproj_path.name}")
    return True


# ============================================================
# BUILD: AntivirusServerLogin.exe (dotnet)
# ============================================================
def build_launcher():
    print("\n[2/2] Building IsolationBytesLogin.exe (dotnet)...")
    print(f"  PUBLIC_URL:    {PUBLIC_URL}")
    print(f"  Mode:          Thin client (no embedded server)")

    # No longer need embed_resources — login page is fetched from the server
    # No longer need cloud_server.exe — server runs on the VPS

    # Generate .csproj (no embedded cloud_server.exe anymore)
    if not generate_csproj():
        return False

    csproj_path = PROJECT_ROOT / "native" / "AntivirusServerLogin" / "AntivirusServerLogin.csproj"
    publish_dir = PROJECT_ROOT / "native" / "AntivirusServerLogin" / "bin" / "Release" / "net8.0-windows" / "win-x64" / "publish"

    # Clean previous publish
    if publish_dir.exists():
        shutil.rmtree(publish_dir, ignore_errors=True)

    # Find dotnet
    dotnet = str(DOTNET_EXE) if DOTNET_EXE.exists() else "dotnet"

    result = safe_run(
        [dotnet, "publish", str(csproj_path),
         "-c", "Release", "-r", "win-x64",
         "--self-contained", "true",
         "-p:PublishSingleFile=true",
         "-p:IncludeNativeLibrariesForSelfExtract=true"],
        cwd=str(PROJECT_ROOT),
    )
    if result.returncode != 0:
        print("FAILED: IsolationBytesLogin.exe build")
        return False

    src_exe = publish_dir / "IsolationBytesLogin.exe"
    if not src_exe.exists():
        # Fall back to old name if AssemblyName wasn't applied
        src_exe = publish_dir / "AntivirusServerLogin.exe"
    if not src_exe.exists():
        print(f"ERROR: IsolationBytesLogin.exe not found in {publish_dir}")
        return False

    # Copy to dist — IsolationBytesLogin.exe is the primary name
    shutil.copy2(src_exe, DIST_DIR / "IsolationBytesLogin.exe")
    shutil.copy2(src_exe, DIST_DIR / "AntivirusServerLogin.exe")  # backward compat

    # Copy IsolationBytesAgent.exe next to the login EXE so it can start
    # the local agent automatically on launch (no Python needed).
    agent_exe = DIST_DIR / "IsolationBytesAgent.exe"
    if agent_exe.exists():
        shutil.copy2(agent_exe, publish_dir / "IsolationBytesAgent.exe")
        print(f"  OK: IsolationBytesAgent.exe bundled alongside login EXE")
    else:
        print(f"  NOTE: IsolationBytesAgent.exe not found in dist/ yet —")
        print(f"        the login EXE will download it from the server on first launch")

    size = (DIST_DIR / "IsolationBytesLogin.exe").stat().st_size / 1048576
    print(f"  OK: IsolationBytesLogin.exe ({size:.1f} MB)")
    print(f"  OK: AntivirusServerLogin.exe ({size:.1f} MB) [backward compat]")
    return True


# ============================================================
# Ensure .env has the right config
# ============================================================
def _ensure_env_config():
    env_path = PROJECT_ROOT / ".env"
    if not env_path.exists():
        return
    content = env_path.read_text(encoding="utf-8", errors="ignore")
    updates = {
        "PUBLIC_URL": PUBLIC_URL,
        "LICENSE_SERVER": LICENSE_SERVER,
        "PAYMENT_URL": PAYMENT_URL,
        "BEHIND_PROXY": "1",
        "PROXY_PORT": str(PROXY_PORT),
        "FLASK_PORT": str(DIRECT_PORT),
    }
    lines = content.splitlines()
    found = set()
    new_lines = []
    for line in lines:
        stripped = line.strip()
        if "=" in stripped and not stripped.startswith("#"):
            key = stripped.split("=", 1)[0].strip()
            if key in updates:
                new_lines.append(f"{key}={updates[key]}")
                found.add(key)
                continue
        new_lines.append(line)
    for key, val in updates.items():
        if key not in found:
            new_lines.append(f"{key}={val}")
    env_path.write_text("\n".join(new_lines) + "\n", encoding="utf-8")
    print(f"  Updated .env with current config")


# ============================================================
# Clean
# ============================================================
def clean():
    print("Cleaning dist/ and build/...")
    for d in [DIST_DIR, PROJECT_ROOT / "build"]:
        if d.exists():
            shutil.rmtree(d, ignore_errors=True)
    DIST_DIR.mkdir(parents=True, exist_ok=True)
    print("  OK")


# ============================================================
# START THE WEBSITE SERVER + REGISTER EVERY STARTUP MECHANISM
# ============================================================
SERVER_URLS = ('http://127.0.0.1:8000/', 'https://127.0.0.1:8443/')
STARTUP_TASK_NAME = 'IsolationBytesCloudServerStartup'
STARTUP_RUN_VALUE = 'IsolationBytesCloudServer'


def _server_commands():
    """Return every way to start the website server, best first."""
    commands = []
    exe = DIST_DIR / 'cloud_server.exe'
    if exe.is_file():
        commands.append([str(exe)])
    script = PROJECT_ROOT / 'cloud' / 'cloud_server.py'
    if script.is_file():
        # Run as a module so the package-relative imports resolve; running the
        # file path directly puts cloud/ on sys.path and breaks "import cloud".
        commands.append([sys.executable, '-m', 'cloud.cloud_server'])
    return commands


def _server_command():
    """Return the preferred command that starts the website server."""
    commands = _server_commands()
    return commands[0] if commands else None


def _server_is_up():
    """True when either the proxy port or direct port already answers."""
    import socket
    for port in (8000, 8443):
        try:
            with socket.create_connection(('127.0.0.1', port), timeout=1):
                return True
        except OSError:
            continue
    return False


def start_cloud_server(wait_seconds=45):
    """Launch the built website server in the background.

    If the built executable exits immediately (for example it predates the
    entrypoint fix), try the source server so the website still comes up.
    """
    commands = _server_commands()
    if not commands:
        print('  WARNING: No cloud server executable or script found — not started.')
        return False
    if _server_is_up():
        print('  Website server is already running on port 8000/8443.')
        return True

    for cmd in commands:
        print(f"  Starting website server: {subprocess.list2cmdline(cmd)}")
        kwargs = {
            'cwd': str(PROJECT_ROOT),
            'stdout': subprocess.DEVNULL,
            'stderr': subprocess.DEVNULL,
        }
        if os.name == 'nt':
            # Detached so the server survives the build shell closing.
            kwargs['creationflags'] = 0x00000008 | 0x08000000
        try:
            proc = safe_popen(cmd, **kwargs)
        except Exception as exc:
            print(f'  WARNING: Could not start website server: {exc}')
            continue

        deadline = time.time() + max(1, int(wait_seconds))
        while time.time() < deadline:
            if _server_is_up():
                print(f'  Website server ready (PID {proc.pid}).')
                print('  Open: http://127.0.0.1:8000/  (or https://127.0.0.1:8443/)')
                return True
            if proc.poll() is not None:
                print(f'  WARNING: Website server exited during startup (code {proc.returncode}).')
                break
            time.sleep(1)
        if _server_is_up():
            return True
        print(f'  WARNING: Website server started (PID {proc.pid}) but did not answer; trying the next launcher.')
    return False


def _startup_folder():
    return os.path.join(
        os.environ.get('APPDATA', ''),
        r'Microsoft\Windows\Start Menu\Programs\Startup',
    )


def install_server_startup():
    """Register the website server in every Windows startup mechanism.

    Covers Task Scheduler, HKCU Run, the Startup folder, and HKLM Run (when
    the build is elevated). Each mechanism is independent, so a failure in
    one still leaves the server auto-starting from the others.
    """
    cmd = _server_command()
    if not cmd:
        print('  WARNING: No server command to register at startup.')
        return
    if os.name != 'nt':
        print('  Startup registration is Windows-only; skipped.')
        return

    command_line = subprocess.list2cmdline(cmd)
    results = []

    def run_quiet(args):
        try:
            return safe_run(args, capture_output=True, text=True, timeout=30)
        except Exception as exc:
            print(f'    {exc}')
            return None

    # 1) Scheduled Task at logon, highest privileges first, then plain logon.
    run_quiet(['schtasks', '/delete', '/tn', STARTUP_TASK_NAME, '/f'])
    task_args = ['schtasks', '/create', '/tn', STARTUP_TASK_NAME,
                 '/tr', command_line, '/sc', 'ONLOGON', '/rl', 'HIGHEST', '/f']
    if len(command_line) > 260:
        wrapper_dir = os.path.join(os.environ.get('ProgramData', r'C:\ProgramData'), 'IsolationBytes')
        os.makedirs(wrapper_dir, exist_ok=True)
        wrapper = os.path.join(wrapper_dir, 'cloud_server_start.bat')
        with open(wrapper, 'w', encoding='utf-8') as fh:
            fh.write(f'@echo off\r\n{command_line}\r\n')
        task_args = ['schtasks', '/create', '/tn', STARTUP_TASK_NAME,
                     '/tr', wrapper, '/sc', 'ONLOGON', '/rl', 'HIGHEST', '/f']
    task = run_quiet(task_args)
    if task is None or task.returncode != 0:
        task = run_quiet(['schtasks', '/create', '/tn', STARTUP_TASK_NAME,
                          '/tr', task_args[task_args.index('/tr') + 1],
                          '/sc', 'ONLOGON', '/f'])
    results.append(('Task Scheduler', task is not None and task.returncode == 0))

    # 2) Per-user registry Run key.
    hkcu = run_quiet(['reg', 'add', r'HKCU\Software\Microsoft\Windows\CurrentVersion\Run',
                      '/v', STARTUP_RUN_VALUE, '/t', 'REG_SZ', '/d', command_line, '/f'])
    results.append(('HKCU Run key', hkcu is not None and hkcu.returncode == 0))

    # 3) Startup folders (hidden VBS launcher; no console window).
    escaped = command_line.replace('"', '""')
    startup_dirs = [_startup_folder()]
    all_users_startup = os.path.join(
        os.environ.get('ProgramData', r'C:\ProgramData'),
        r'Microsoft\Windows\Start Menu\Programs\StartUp',
    )
    startup_dirs.append(all_users_startup)
    folder_ok = False
    for startup_dir in startup_dirs:
        try:
            os.makedirs(startup_dir, exist_ok=True)
            vbs_path = os.path.join(startup_dir, 'IsolationBytesCloudServer.vbs')
            with open(vbs_path, 'w', encoding='utf-8') as fh:
                fh.write('Set sh = CreateObject("WScript.Shell")\r\n')
                fh.write(f'sh.Run "{escaped}", 0, False\r\n')
            folder_ok = True
        except Exception as exc:
            print(f'    Startup folder registration skipped ({startup_dir}): {exc}')
    results.append(('Startup folder', folder_ok))

    # 4) Machine-wide Run key (succeeds only when the build is elevated).
    hklm = run_quiet(['reg', 'add', r'HKLM\Software\Microsoft\Windows\CurrentVersion\Run',
                      '/v', STARTUP_RUN_VALUE, '/t', 'REG_SZ', '/d', command_line, '/f'])
    results.append(('HKLM Run key', hklm is not None and hklm.returncode == 0))

    print('  Startup registration:')
    for name, ok in results:
        print(f'    {name + ":":<20s} {"OK" if ok else "skipped/failed (non-fatal)"}')


# ============================================================
# Main
# ============================================================
def main():
    args = set(sys.argv[1:])
    do_clean = "--clean" in args

    # If specific flags given, only build those
    if "--cloud" in args or "--launcher" in args:
        build_cloud = "--cloud" in args
        build_launcher_flag = "--launcher" in args
    else:
        build_cloud = True
        build_launcher_flag = True

    print(f"\n{'='*60}")
    print(f"  BUILD CONFIGURATION")
    print(f"{'='*60}")
    print(f"  Project:       {PROJECT_ROOT}")
    print(f"  Output:        {DIST_DIR}")
    print(f"  PUBLIC_URL:    {PUBLIC_URL}")
    print(f"  Build cloud:   {build_cloud}")
    print(f"  Build launcher: {build_launcher_flag}")
    print(f"  Order:         cloud_server.exe first, then launcher embeds it")

    if do_clean:
        clean()

    DIST_DIR.mkdir(parents=True, exist_ok=True)

    ok = True
    if build_cloud:
        ok = build_cloud_server() and ok
    if build_launcher_flag:
        ok = build_launcher() and ok  # No longer requires cloud_server.exe

    # build_config.py invokes this script while building; it owns the final
    # launch so the server is not started from a stale build mid-pipeline.
    nested = os.environ.get('ISOLATION_BYTES_BUILD_NESTED') == '1'
    if ok and not nested and '--no-start' not in args:
        print(f"\n{'='*60}")
        print('  STARTING WEBSITE SERVER')
        print(f"{'='*60}")
        start_cloud_server()
    if ok and not nested and '--no-startup' not in args:
        install_server_startup()

    print(f"\n{'='*60}")
    if ok:
        print("  BUILD COMPLETE")
        print(f"{'='*60}")
        for f in sorted(DIST_DIR.glob("*.exe")):
            print(f"  {f.name:40s} {f.stat().st_size / 1048576:>8.1f} MB")
        print(f"\n  IsolationBytesLogin.exe is a thin client:")
        print(f"    - Loads login page from {PUBLIC_URL}")
        print(f"    - Validates license via POST /api/license/validate")
        print(f"    - Authenticates via POST /api/user/login")
        print(f"    - No embedded server, no embedded secrets")
        print(f"    - No local password hashing — all auth is server-side")
        print(f"    - Launches the MSIX app after successful login")
    else:
        print("  BUILD FAILED")
        print(f"{'='*60}")
        sys.exit(1)


if __name__ == "__main__":
    main()
