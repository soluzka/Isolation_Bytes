"""buildconfig.py — single source of truth for building all EXEs.

Builds both EXEs with the same configuration:
  - cloud_server.exe         (PyInstaller — Flask + Caddy + Cloudflare)
  - AntivirusServerLogin.exe (dotnet — launcher with embedded cloud_server.exe)

The launcher embeds cloud_server.exe inside itself, so the final
AntivirusServerLogin.exe is fully self-contained — no external files needed.

Usage:
    python buildconfig.py              # build everything (cloud first, then launcher)
    python buildconfig.py --cloud      # only cloud_server.exe
    python buildconfig.py --launcher   # only AntivirusServerLogin.exe
    python buildconfig.py --clean      # clean dist/ then build everything

Everything is defined here: URLs, ports, paths, embedded files.
No separate spec file or build script needed.
"""
import os
import sys
import shutil
import subprocess
from pathlib import Path

# ============================================================
# SHARED CONFIGURATION — used by both EXEs
# ============================================================
PROJECT_ROOT = Path(__file__).resolve().parent
DIST_DIR = PROJECT_ROOT / 'dist'

# URLs (no port — Caddy/Cloudflare handle HTTPS on 443)
PUBLIC_URL = "https://isolation-bytes.com"
LICENSE_SERVER = "https://isolation-bytes.com"
PAYMENT_URL = "https://soluzka.lemonsqueezy.com/checkout/buy/19c84fba-cbd9-458e-80ba-8dfd2e5c11c0"

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
    "quarantine_utils", "file_crypto", "utils.paths",
    "waitress", "json", "hashlib", "secrets", "webbrowser",
    # ML/scanning libraries — needed for BODMAS, EMBER, sklearn models, YARA
    "sklearn", "sklearn.ensemble", "sklearn.linear_model", "sklearn.svm",
    "sklearn.tree", "sklearn.neural_network", "sklearn.preprocessing",
    "sklearn.decomposition", "sklearn.pipeline", "sklearn.metrics",
    "sklearn.model_selection",
    "numpy", "scipy", "scipy.sparse", "onnxruntime", "yara",
    "joblib", "pickle", "pandas", "pefile", "tlsh", "lief",
]

EXCLUDED_IMPORTS = [
    "tensorflow", "torch", "torchvision",
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
    cmd = [sys.executable, "-m", "PyInstaller", str(spec_path),
           "--noconfirm", "--distpath", str(DIST_DIR)]
    result = subprocess.run(cmd, cwd=str(PROJECT_ROOT))
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
    hookspath=[],
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
    result = subprocess.run([sys.executable, str(embed_script)], cwd=str(PROJECT_ROOT))
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
    cloud_exe_rel = "..\\..\\dist\\cloud_server.exe"
    python_installer_rel = "..\\..\\python-3.11.9-amd64.exe"

    content = f"""<Project Sdk="Microsoft.NET.Sdk">
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
    <AssemblyTitle>Antivirus Server Login</AssemblyTitle>
    <AssemblyProduct>Antivirus Server</AssemblyProduct>
    <AssemblyCompany>soluzka</AssemblyCompany>
    <Version>1.8.678.0</Version>
    <ApplicationManifest>app.manifest</ApplicationManifest>
    <CloudflaredPath Condition="'$(CloudflaredPath)' == ''">C:\\caddy\\cloudflared.exe</CloudflaredPath>
  </PropertyGroup>

  <!-- Python installer embedded for bootstrap fallback -->
  <ItemGroup>
    <EmbeddedResource Include="{python_installer_rel}" LogicalName="python_installer.exe" />
  </ItemGroup>

  <!-- cloud_server.exe embedded so the launcher is fully self-contained -->
  <!-- No .env embedded — launcher fetches config from the server at runtime -->
  <ItemGroup>
    <Compile Remove="EnvData.g.cs" />
    <EmbeddedResource Include="{cloud_exe_rel}" LogicalName="cloud_server_exe" />
    <EmbeddedResource Include="$(CloudflaredPath)" LogicalName="cloudflared_exe" Condition="Exists('$(CloudflaredPath)')" />
    <EmbeddedResource Include="cloudflared.template.yml" LogicalName="cloudflared_config_template" />
  </ItemGroup>

  <Target Name="CopyFriendlyLauncherName" AfterTargets="Publish">
    <Copy SourceFiles="$(PublishDir)AntivirusServerLogin.exe" DestinationFiles="$(PublishDir)Antivirus Server Login.exe" />
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
    print("\n[2/2] Building AntivirusServerLogin.exe (dotnet)...")
    print(f"  PUBLIC_URL:    {PUBLIC_URL}")
    print(f"  Embedded:      cloud_server.exe, cloudflared.exe, config template, login.html, cloud_server.py")

    # Check that cloud_server.exe exists (needed for embedding)
    cloud_exe = DIST_DIR / "cloud_server.exe"
    if not cloud_exe.exists():
        print(f"  ERROR: {cloud_exe} not found — build cloud_server first")
        print(f"  Run: python buildconfig.py --cloud")
        return False

    # Re-embed resources (regenerates LoginHtml.g.cs and CloudServer.g.cs)
    if not embed_resources():
        return False

    # Generate .csproj with embedded cloud_server.exe
    if not generate_csproj():
        return False

    csproj_path = PROJECT_ROOT / "native" / "AntivirusServerLogin" / "AntivirusServerLogin.csproj"
    publish_dir = PROJECT_ROOT / "native" / "AntivirusServerLogin" / "bin" / "Release" / "net8.0-windows" / "win-x64" / "publish"

    # Clean previous publish
    if publish_dir.exists():
        shutil.rmtree(publish_dir, ignore_errors=True)

    # Find dotnet
    dotnet = str(DOTNET_EXE) if DOTNET_EXE.exists() else "dotnet"

    cmd = [dotnet, "publish", str(csproj_path),
           "-c", "Release", "-r", "win-x64",
           "--self-contained", "true",
           "-p:PublishSingleFile=true",
           "-p:IncludeNativeLibrariesForSelfExtract=true"]
    result = subprocess.run(cmd, cwd=str(PROJECT_ROOT))
    if result.returncode != 0:
        print("FAILED: AntivirusServerLogin.exe build")
        return False

    src_exe = publish_dir / "AntivirusServerLogin.exe"
    if not src_exe.exists():
        print(f"ERROR: {src_exe} not found")
        return False

    # Copy to dist with both names
    shutil.copy2(src_exe, DIST_DIR / "AntivirusServerLogin.exe")
    shutil.copy2(src_exe, DIST_DIR / "Antivirus Server Login.exe")

    size = (DIST_DIR / "AntivirusServerLogin.exe").stat().st_size / 1048576
    print(f"  OK: AntivirusServerLogin.exe ({size:.1f} MB)")
    print(f"  OK: Antivirus Server Login.exe ({size:.1f} MB)")
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
        ok = build_launcher() and ok

    print(f"\n{'='*60}")
    if ok:
        print("  BUILD COMPLETE")
        print(f"{'='*60}")
        for f in sorted(DIST_DIR.glob("*.exe")):
            print(f"  {f.name:40s} {f.stat().st_size / 1048576:>8.1f} MB")
        print(f"\n  AntivirusServerLogin.exe contains:")
        print(f"    - Embedded cloud_server.exe (extracts and runs on launch)")
        print(f"    - No embedded secrets; .env is created beside the server EXE at runtime")
        print(f"    - Embedded login.html (website)")
        print(f"    - Embedded cloud_server.py (Python fallback)")
        print(f"    - Embedded Python 3.11 installer (fallback if no Python)")
        print(f"\n  cloud_server.exe starts:")
        print(f"    - Flask on port {PROXY_PORT}")
        print(f"    - Caddy on port {HTTPS_PORT} (HTTPS)")
        print(f"    - Cloudflare tunnel (public access)")
        print(f"    - Browser -> {PUBLIC_URL}")
    else:
        print("  BUILD FAILED")
        print(f"{'='*60}")
        sys.exit(1)


if __name__ == "__main__":
    main()
