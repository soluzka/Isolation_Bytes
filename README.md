# Windows Defender — Advanced Antivirus Dashboard

A local Windows security suite with YARA malware scanning, real-time process and network monitoring, ML-assisted threat detection, encrypted quarantine, and a browser-based dashboard.

> This is a local, research-oriented antivirus dashboard. It is not a replacement for commercial endpoint protection and should not be exposed to the public internet.

## Features

### Detection and scanning

- YARA rule scanning for files and running processes
- Hash signatures, fuzzy hashing, heuristics, and malware classifiers
- EMBER, BODMAS, and ONNX-based model scoring
- Real-time process monitoring
- Network traffic and DNS monitoring
- Folder watching and on-access scanning
- Ransomware and persistence checks
- Conditional startup scans with progress reporting

### Quarantine and remediation

- Fernet-encrypted quarantine
- Safe quarantine behavior for protected Windows and installed-software paths
- Review of ransomware and persistence findings before bulk quarantine
- Quarantine listing, restore, deletion, and delete-all controls
- File encryption and decryption through the dashboard

### Dashboard and administration

- Local Flask web dashboard
- HTTP authentication and optional two-factor authentication
- Windows Firewall integration
- Administrator service for protected scans, firewall actions, and quarantine actions
- Local findings assistant with report, IOC, prioritization, and service-status tools

## Requirements

- Windows 10 version 2004 or later, or Windows 11
- 64-bit Windows
- Administrator approval when installing the packaged administrator service
- 4 GB RAM minimum; more is recommended for ML scanning and the local assistant
- Python 3.11 or later for source/development use

## Installation

### Microsoft Store

For Store distribution, install the application from Microsoft Store. The Store signs the MSIX package and Windows handles package updates.

The packaged administrator service is installed with the MSIX and starts automatically when supported by the package and Windows version. Installation requires Administrator approval because the service runs under LocalSystem.

### Offline SFX installer

For offline installation, use the generated `Install_AntivirusServer_SFX.exe`. It installs the MSIX, the unpacked administrator helper bundle, and the service setup files.

The SFX installer is intended for Windows 10/11 x64 systems and requires Administrator approval.

## Administrator service

The administrator service allows the normal MSIX dashboard to request privileged operations without running the dashboard itself as Administrator.

Supported operations include:

- Protected YARA scans
- Multiple configured scan roots
- Public-IP firewall block and unblock
- Quarantine restore and deletion
- Quarantine and firewall listings
- Service status and audit logging

The service uses a restricted local named pipe. It does not expose arbitrary shell commands or unrestricted file paths.

If manual service setup is needed, run PowerShell as Administrator:

```powershell
.\manage_admin_service.ps1 Install `
  -ProtectedScanRoots 'C:\Users\Public\Downloads;D:\Samples' `
  -QuarantineRestoreRoots 'C:\ProgramData\AntivirusServer\restored'

.\manage_admin_service.ps1 Start
```

To inspect or remove the service:

```powershell
.\manage_admin_service.ps1 Status
.\manage_admin_service.ps1 Stop
.\manage_admin_service.ps1 Uninstall
```

Configured scan and restore roots must already exist. Mutating service operations require the explicit confirmation value `CONFIRM`.

## Running the dashboard

When running from source:

```powershell
python quick_start.py
```

Open the address shown by the application, normally:

```text
http://127.0.0.1:5000
```

The port may fall back to `5001` or another available port.

Do not run the application from `C:\Windows` or another protected directory. The application writes logs, runtime state, quarantine data, and scan data next to its runtime directory.

## Logging in

The dashboard uses administrator authentication. The default development credentials are:

```text
Username: admin
Password: admin123
```

Change the password before using the dashboard on a shared or exposed system.

## Optional local AI assistant

The local assistant answers questions about supplied findings and scan context. It can:

- Explain why a file was flagged
- Prioritize findings by risk
- Extract hashes, IP addresses, and domains
- Summarize incidents
- Compare persisted scan history
- Explain service status and remediation options
- Download Markdown, HTML, or JSON reports

The assistant does not execute commands, change firewall rules, delete files, or quarantine files directly.

The optional local model is stored as:

```text
models\assistant.gguf
```

The downloader uses a compact Qwen3 GGUF quantization. The model is optional; the assistant falls back to findings-only mode when it is unavailable.

## Configuration and secrets

Create a `.env` file in the project root or next to the packaged application. At minimum, configure a Fernet key:

```dotenv
FERNET_KEY=<44-character base64 Fernet key>
```

Generate one with:

```powershell
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Other optional settings include:

```dotenv
FLASK_SECRET_KEY=<random secret>
ADMIN_USERNAME=admin
ADMIN_PASSWORD=<strong password>
MALWAREBAZAAR_API_KEY=<optional API key>
VT_API_KEY=<optional API key>
```

Never commit `.env`, `.pfx`, `.p12`, private keys, API keys, quarantine data, or local model files.

## Scanning guidance

- YARA rules are loaded from `security\yara_rules\`.
- Media files may be skipped to improve performance.
- Broad matches in legitimate Windows files should be reviewed as heuristic indicators, not automatically treated as confirmed malware.
- Protected scans and remediation may require the administrator service.
- Use the dashboard review controls before bulk quarantine actions.

## Signature updates

The scanner uses local malware signature databases. If a MalwareBazaar API key is configured, signatures can be refreshed through the application’s update controls.

Optional VirusTotal enrichment can be enabled with `VT_API_KEY`. API services may have rate limits and should not be treated as the sole source of a detection decision.

## Stopping a runaway scan

If a scan becomes unresponsive, stop the application process from an elevated PowerShell window:

```powershell
Get-Process -Name antivirus_server -ErrorAction SilentlyContinue | Stop-Process -Force
```

Confirm that the process has stopped before starting another scan.

## Privacy and data handling

The application runs locally. Depending on configuration, it may access:

- Files and running processes selected for scanning
- Network connection metadata
- Quarantine records
- Optional external malware reputation services
- The optional local GGUF assistant model

Keep the dashboard bound to localhost and protect its authentication credentials.

For the full privacy policy, see [PRIVACY.md](PRIVACY.md).

## Security

See [SECURITY.md](SECURITY.md) for supported versions and vulnerability reporting guidance.

## License

See [LICENSE](LICENSE) for licensing information.
