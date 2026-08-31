# Isolation Bytes Antivirus

A cross-platform antivirus and security suite with a cloud-connected dashboard, YARA malware scanning, ML-assisted threat detection, real-time monitoring, encrypted quarantine, and a Windows MSIX desktop shell.

**Website:** [https://isolation-bytes.com](https://isolation-bytes.com)

## Architecture

Isolation Bytes consists of several components:

| Component | Description |
|-----------|-------------|
| **Cloud Server** | Flask-based cloud application serving the web dashboard, login, license validation, downloads, and API endpoints at `https://isolation-bytes.com` |
| **MSIX Desktop Shell** | WPF WebView2 app (`IsolationBytes.msix`) that loads the cloud dashboard in a native Windows window with auto-update support |
| **Login Launcher** | Thin Windows client (`IsolationBytesLogin.exe`) that authenticates against the cloud API, validates licenses, and launches the MSIX app |
| **Universal Launcher** | Cross-platform installer/launcher (`IsolationBytesLauncher.exe`) that downloads, trusts, and installs the MSIX on Windows, or installs ClamAV + Python scanners on macOS/Linux/ChromeOS |
| **Local Antivirus Server** | PyInstaller-bundled local server embedded inside the MSIX for on-device scanning, folder watching, and quarantine |
| **Universal Installer Scripts** | Platform-specific shell/batch scripts for Windows, macOS, Linux, ChromeOS, iOS, and Android |

## Features

### Detection and Scanning

- YARA rule scanning for files and running processes
- Hash signatures, fuzzy hashing (TLSH/ssdeep), and heuristics
- EMBER, BODMAS, and ONNX-based ML model scoring
- Recursive folder watching and on-access scanning
- Real-time process monitoring
- Network traffic and DNS monitoring
- Ransomware and persistence checks
- Windows Defender integration on Windows
- ClamAV integration on macOS, Linux, and ChromeOS (auto-installed via package managers)
- VirusTotal enrichment (optional, API key required)
- MalwareBazaar signature updates (optional, API key required)

### Cross-Platform Support

| Platform | Installation Method | Scanner |
|----------|-------------------|---------|
| **Windows 10/11** | MSIX + AppInstaller (auto-update) | Windows Defender + YARA + ML |
| **macOS 10.13+** | Shell installer / Universal launcher | ClamAV + YARA + ML |
| **Linux** | Shell installer / Universal launcher | ClamAV + YARA + ML |
| **ChromeOS** | PWA / Linux container (Crostini) | ClamAV + YARA + ML |
| **Android** | APK / PWA | YARA + ML (portable) |
| **iOS / iPadOS** | PWA / Web Clip profile | YARA + ML (portable) |
| **Any device** | PWA from `https://isolation-bytes.com` | Cloud-assisted |

### Quarantine and Remediation

- Fernet-encrypted quarantine
- Safe quarantine behavior for protected OS paths
- Ransomware and persistence review before bulk quarantine
- Quarantine listing, restore, deletion, and delete-all controls
- File encryption and decryption through the dashboard
- Block files in place first, then review and quarantine manually
- Combined unblock + quarantine in a single command cycle (`quarantine_after` flag)

### Block / Unblock / Quarantine Compatibility by Platform

| Platform | Block in Place | Unblock | Quarantine | Remote Commands | Combined Unblock + Quarantine |
|----------|----------------|---------|------------|-----------------|-------------------------------|
| **Windows** (standalone_agent.py) | Yes — `icacls` deny | Yes — `icacls` grant | Yes — `shutil.move` | Yes — polls `/agent/commands` | Yes — `quarantine_after` flag |
| **macOS** (standalone_agent.py) | Yes — `chmod 0o000` | Yes — `chmod 0o755` | Yes — `shutil.move` | Yes — polls `/agent/commands` | Yes — `quarantine_after` flag |
| **Linux** (standalone_agent.py) | Yes — `chmod 0o000` | Yes — `chmod 0o755` | Yes — `shutil.move` | Yes — polls `/agent/commands` | Yes — `quarantine_after` flag |
| **ChromeOS** (Linux via Crostini) | Yes — same as Linux | Yes — same as Linux | Yes — same as Linux | Yes — same as Linux | Yes — same as Linux |
| **Android** (AgentService.kt) | Yes — `setReadable/Writable/Executable(false)` | Yes — `setReadable/Writable(true)` | Yes — `copyTo` + `delete` | No — does not poll `/agent/commands` | No — no remote command polling |
| **iOS / iPadOS** (PWA) | No — browser sandbox | No — browser sandbox | No — browser sandbox | No — browser sandbox | No — browser sandbox |
| **Any device** (PWA) | No — browser sandbox | No — browser sandbox | No — browser sandbox | No — browser sandbox | No — browser sandbox |

> **Note:** Android has local block/unblock/quarantine functions but does not currently poll the cloud for remote commands. Dashboard-driven unblock/quarantine actions only reach Windows, macOS, Linux, and ChromeOS agents. iOS/PWA cannot block or quarantine files due to browser sandbox restrictions.

### Dashboard and Administration

- Cloud-hosted web dashboard at `https://isolation-bytes.com`
- Cloud-based user authentication and license validation
- Windows Firewall integration
- Administrator service for protected scans, firewall actions, and quarantine actions
- Local findings assistant with report, IOC, prioritization, and service-status tools
- Startup apps management across platforms
- Network monitoring and blocking
- Process and service management

## Installation

### Windows (Recommended)

1. Download **IsolationBytesLauncher.exe** from the [install page](https://isolation-bytes.com/install)
2. Run it — it automatically:
   - Downloads the MSIX package and certificate
   - Trusts the certificate in `Root` and `TrustedPeople` stores
   - Installs the MSIX via `Add-AppxPackage`
   - Launches the app

Alternatively, use PowerShell:

```powershell
iwr https://isolation-bytes.com/download/install-windows.ps1 -UseBasicParsing | iex
```

Or use the Windows AppInstaller:

```
https://isolation-bytes.com/download/IsolationBytes.appinstaller
```

### macOS

```bash
bash install-macos.sh
```

Creates a `.app` bundle in `/Applications`. Auto-installs ClamAV via Homebrew if missing.

### Linux

```bash
bash install-linux.sh
```

Auto-detects the browser (Chromium, Firefox, Epiphany, Midori, Falkon). Installs ClamAV via the system package manager (`apt`, `dnf`, `pacman`, `apk`, `zypper`, `emerge`, `xbps-install`, FreeBSD `pkg`).

### ChromeOS

Install as a PWA from Chrome's address bar, or use the Linux container (Crostini) with the Linux installer.

### iOS / iPadOS

Open `https://isolation-bytes.com` in Safari, tap **Share > Add to Home Screen**. Or download the [Configuration Profile](https://isolation-bytes.com/download/install-ios.mobileconfig) for a fullscreen web app with its own icon.

### Android

**Option 1: APK / PWA**

Download the APK from the [install page](https://isolation-bytes.com/install) or install as a PWA from Chrome.

**Option 2: Termux (Python agent — no root required)**

1. Install [Termux from F-Droid](https://f-droid.org/packages/com.termux/) (not Play Store — it's outdated)
2. Open Termux and run:
   ```bash
   pkg install python git -y
   pip install psutil requests
   termux-setup-storage
   git clone https://github.com/soluzka/Isolation_Bytes.git
   cd Isolation_Bytes && git checkout security-v2
   python mobile_agent.py --server https://isolation-bytes.com --key YOUR_API_KEY
   ```

Without root: reports CPU, memory, disk, battery, file scanning, and network discovery. Process list is limited to Termux's sandbox.
With root: full process list, all network connections, and firewall blocking — same as the Windows agent.

### Universal (Any OS with Python 3.8+)

```bash
python universal_launcher.py
```

Auto-detects the OS, installs the appropriate components, and launches the app. Supports `--install`, `--launch`, `--uninstall`, `--status`, `--update`, `--repair`, and `--silent` modes.

## MSIX Package Identity

| Property | Value |
|----------|-------|
| Package Name | `soluzka.IsolationBytes` |
| Application ID | `IsolationBytes` |
| AUMID | `soluzka.IsolationBytes!IsolationBytes` |
| Publisher | `CN=soluzka, O=soluzka, C=US` |
| Auto-update | Every 6 hours via AppInstaller |

## Login Launcher

`IsolationBytesLogin.exe` is a thin Windows client that:

- Loads the login page from `https://isolation-bytes.com`
- Validates licenses via `POST /api/license/validate`
- Authenticates users via `POST /api/user/login`
- Launches the MSIX app after successful login
- No embedded server, no embedded secrets
- All authentication is server-side

## Building from Source

### Prerequisites

- Python 3.11+
- .NET 8 SDK
- Windows SDK (for `makeappx.exe` and `signtool.exe`)
- PyInstaller

### Full Build (Cloud Server + Login Launcher + MSIX)

```powershell
python build_config.py
```

This builds:
1. `cloud_server.exe` and `AntivirusServerLogin.exe` via `buildconfig.py`
2. `antivirus_server` onedir via PyInstaller
3. `IsolationBytesLauncher.exe` (universal launcher)
4. `IsolationBytes.msix` (signed, with WPF shell + embedded antivirus_server)
5. `IsolationBytes.cer` (public certificate for sideload trust)

### Partial Builds

```powershell
python buildconfig.py --cloud      # only cloud_server.exe
python buildconfig.py --launcher   # only AntivirusServerLogin.exe
python build_config.py --skip-exe  # MSIX only (requires existing antivirus_server onedir)
```

### Build Outputs

| Artifact | Location | Approx. Size |
|----------|----------|-------------|
| `IsolationBytes.msix` | `dist/` | ~1.9 GB |
| `IsolationBytes.cer` | `dist/` | ~1 KB |
| `IsolationBytes.appinstaller` | `dist/` | ~2 KB |
| `IsolationBytesLauncher.exe` | `dist/` | ~6 MB |
| `AntivirusServerLogin.exe` | `dist/` | ~154 MB |
| `IsolationBytesLogin.exe` | `dist/` | ~154 MB |
| `cloud_server.exe` | `dist/` | ~293 MB |
| `antivirus_server/` | `dist/` | onedir |

## Configuration

Create a `.env` file in the project root. At minimum, configure a Fernet key:

```dotenv
FERNET_KEY=<44-character base64 Fernet key>
```

Generate one with:

```powershell
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Other optional settings:

```dotenv
FLASK_SECRET_KEY=<random secret>
ADMIN_USERNAME=<admin username>
ADMIN_PASSWORD=<strong password>
MALWAREBAZAAR_API_KEY=<optional API key>
VT_API_KEY=<optional VirusTotal API key>
```

Never commit `.env`, `.pfx`, `.p12`, private keys, API keys, quarantine data, or local model files.

## Scanning Guidance

- YARA rules are loaded from `security/yara_rules/`
- ClamAV definitions are updated via `freshclam` on non-Windows systems
- Windows uses `Update-MpSignature` for Defender definitions
- Broad matches in legitimate OS files should be reviewed as heuristic indicators
- Protected scans and remediation may require the administrator service
- Use the dashboard review controls before bulk quarantine actions

## Administrator Service

The administrator service allows the dashboard to request privileged operations without running the dashboard itself as Administrator.

Supported operations:
- Protected YARA scans
- Multiple configured scan roots
- Public-IP firewall block and unblock
- Quarantine restore and deletion
- Service status and audit logging

The service uses a restricted local named pipe. It does not expose arbitrary shell commands or unrestricted file paths.

```powershell
.\manage_admin_service.ps1 Install `
  -ProtectedScanRoots 'C:\Users\Public\Downloads;D:\Samples' `
  -QuarantineRestoreRoots 'C:\ProgramData\AntivirusServer\restored'

.\manage_admin_service.ps1 Start
.\manage_admin_service.ps1 Status
.\manage_admin_service.ps1 Stop
.\manage_admin_service.ps1 Uninstall
```

## Privacy and Data Handling

The application may access:
- Files and running processes selected for scanning
- Network connection metadata
- Quarantine records
- Optional external malware reputation services (VirusTotal, MalwareBazaar)
- The optional local GGUF assistant model

For the full privacy policy, see [PRIVACY.md](PRIVACY.md).

## Security

See [SECURITY.md](SECURITY.md) for supported versions and vulnerability reporting guidance.

## License

See [LICENSE](LICENSE) for licensing information.

---

Isolation Bytes Antivirus &copy; 2026 soluzka
