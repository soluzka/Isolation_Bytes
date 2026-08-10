# Windows Defender — Advanced Antivirus Dashboard

**A Windows-first security suite with YARA malware scanning, real-time network & process monitoring, ML-assisted threat detection, encrypted quarantine, and a live Flask dashboard.**

> Scan files, monitor running processes, block suspicious network connections, and quarantine threats — all from one portable Windows application.

---

## Key Features

- **YARA Rule Scanning** — Signature-based detection using rule sets in `security/yara_rules/`, with on-demand and background scanning.
- **Real-Time Process Monitor** — Scans running user processes, flags malware, terminates infected processes, and blocks outbound connections.
- **Network Traffic Monitoring** — Live connection/protocol/process stats plus heuristic C2-pattern and DNS reputation detection.
- **ML & Heuristic Threat Detection** — EMBER/synthetic-ML scoring and ransomware heuristic checks for static-file and process analysis.
- **Encrypted Quarantine** — Fernet-encrypted quarantine with ACL/permissions hardening and user-confirmed safe release/delete.
- **Folder Watching** — Tracks configured directories, reports high-risk file types, and performs live on-access scanning.
- **Conditional Startup Scan** — One-click combined scan of monitored directories and running processes with live progress reporting.
- **Flask Web Dashboard** — Clean browser-based UI with live tiles for scanned files, quarantined items, process events, ML detections, ransomware indicators, and persistence indicators.
- **Windows Firewall Integration** — Auto-blocks remote IPs associated with malicious processes (requires admin).
- **File Encryption/Decryption** — In-browser file crypto for sensitive files, capped at 125MB.

---

## Steam / Store Page Short Description

Defend your Windows PC with a YARA-powered antivirus dashboard. Scan files, monitor live processes and network traffic, quarantine threats with encryption, and block malicious connections — all from a single portable app.

## Discord Server Blurb

**Windows Defender AV Dashboard** — YARA malware scanning, real-time network & process monitoring, ML threat scoring, encrypted quarantine, and Windows Firewall blocking. Built for Windows 10/11. Open source, runs locally.

---

## System Requirements

- **OS:** Windows 10 or Windows 11
- **Privileges:** Administrator (for UAC elevation, Windows Firewall, secure-memory helpers, and system scans)
- **Python:** 3.11+
- **RAM:** 4GB+ recommended for ML/heuristic scanning

---

## Installation

1. Clone the repository:

   ```powershell
   git clone https://github.com/soluzka/antivirus-yara-rules.git
   cd antivirus-yara-rules
   ```

2. Install dependencies:

   ```powershell
   pip install -r requirements.txt
   ```

   If `pywin32` fails on some setups:

   ```powershell
   pip install pywin32==306 --no-deps --only-binary=:all: --force-reinstall
   ```

3. Create a `.env` file in the project root with at least:

   ```dotenv
   FERNET_KEY=<44-character base64 Fernet key>
   ```

   Generate a key with:

   ```powershell
   python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
   ```

   For the full list of optional settings (Flask secret, admin credentials, quarantine limits), see `.env.example`.

---

## Running the Application

```powershell
python quick_start.py
```

`quick_start.py` checks for administrator rights and prompts for UAC elevation if needed. Once running, the dashboard is available at:

```
http://127.0.0.1:5000
```

(Port falls back to `5001` if `5000` is in use.)

A local DNS server, folder watcher, and real-time network monitor start automatically in the background.

---

## Command-Line Usage

```powershell
python antivirus_cli.py scan <path>
python antivirus_cli.py quarantine list
python antivirus_cli.py quarantine release <file.enc> <dest_dir>
python antivirus_cli.py quarantine delete <file.enc>
python antivirus_cli.py monitor
python antivirus_cli.py update-signatures
```

- `scan` detects malware, prompts to quarantine, and deletes the original only after confirmation.
- `quarantine release` decrypts a `.enc` file to the destination and removes the encrypted copy.
- `quarantine delete` permanently removes a `.enc` file from quarantine.

---

## Building the Standalone EXE

```powershell
python build_config.py
```

The built executable is placed in `dist/antivirus_server.exe` and can be run or distributed without a Python install.

### Installing as a Startup Application

The built `antivirus_server.exe` auto-installs its startup entry the first time it is launched, so it will run at every user logon after the first run. It uses its own full path (`sys.executable`), so it does not matter whether it stays in `dist` or is moved elsewhere.

---

## Optional Environment Flags

- `AV_ENABLE_TEMP_CLEANUP=1` — Delete files under temp directories during startup.
- `AV_ENABLE_ROUTINE_MAINTENANCE=1` — Run a deeper scan battery over critical system directories.

---

## Testing

```powershell
python -m pytest test_antivirus_cli.py -v
python simple_yara_test.py
python test_yara.py
python fernet_decrypt_test.py
python test_environment.py
```

---

## Technical Highlights

- Persistent scan cache with atomic save/backup/reset logic.
- Safe `tarfile` extraction with member validation and `filter="data"`.
- SHA1/MD5 used with `usedforsecurity=False` for non-cryptographic file hashing.
- Subprocess hardening with `sys.executable`, `shutil.which` resolution, and escaped paths.
- `.snyk` exclusions for vendored `scikit-learn-main` and test files.

---

## Known Limitations

- `quick_start.py` uses Flask's built-in development server — not intended for production internet exposure.
- UAC elevation, Windows Firewall blocking, WMI, and secure-memory helpers require Windows.
- `pywin32` installation may need manual steps on some environments.

---

## License

This project is released under the [MIT License](LICENSE).

---

## Repository

[https://github.com/soluzka/antivirus-yara-rules](https://github.com/soluzka/antivirus-yara-rules)
