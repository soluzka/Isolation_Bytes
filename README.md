# Windows Defender — Advanced Antivirus Dashboard

A Windows-first security suite with YARA malware scanning, real-time network and process monitoring, ML-assisted threat detection, encrypted quarantine, and a live Flask dashboard.

- Scan files and running processes with YARA rules, hash signatures, fuzzy hashing, and heuristics.
- Monitor network traffic and DNS requests for suspicious patterns.
- Quarantine and encrypt suspect files using Fernet.
- Review results and manage quarantine through a local browser-based UI.

> This is a local, research-oriented antivirus dashboard. It is **not** a replacement for commercial endpoint protection and should not be exposed to the public internet. `quick_start.py` uses Flask's built-in development server, which is not intended for production use.

---

## Key Features

### Detection & Scanning
- **YARA Rule Scanning** — Signature-based detection with the rule sets in `security/yara_rules/`.
- **Real-Time Process Monitor** — Scans running user processes, flags suspicious activity, and can terminate infected processes.
- **Network Traffic Monitoring** — Live connection, protocol, and process statistics plus heuristic C2-pattern and DNS reputation detection. Suspicious connections trigger an automatic scan of the owning process.
- **ML & Heuristic Threat Detection** — EMBER, BODMAS, BODMAS 1D-CNN via ONNX Runtime, synthetic-ML scoring, and ransomware heuristic checks.
- **Folder Watching** — Tracks configured directories and performs live on-access scanning.

### Quarantine & Remediation
- **Encrypted Quarantine** — Fernet-encrypted quarantine files with user-confirmed safe release and deletion.
- **Safe Quarantine Logic** — Does not leave encrypted copies when the original file cannot be safely removed, and protects Windows system / installed-software paths.
- **Heuristic Review & Bulk Actions** — Review ransomware/persistence heuristic findings with checkboxes, then quarantine selected items.
- **Quarantine Restore/Delete/Delete-All** — Authenticated UI to restore, remove individual, or purge all quarantined payloads.

### Dashboard & Control
- **Flask Web Dashboard** — Browser-based UI with live tiles for scans, quarantine, process events, ML detections, ransomware indicators, and persistence indicators.
- **Conditional Startup Scan** — One-click combined scan of monitored directories, running processes, and startup areas with live progress reporting.
- **Break the Cycle** — In-dashboard button to request an immediate, cooperative stop of a running conditional startup scan.
- **Windows Firewall Integration** — Optionally blocks remote IPs associated with malicious processes (requires admin privileges).
- **File Encryption/Decryption** — In-browser file encryption for sensitive files, capped at 125 MB.

### Packaging & Distribution
- **One-Step PyInstaller Build** — `python build_config.py` builds `dist\antivirus_server\antivirus_server.exe` plus bundled assets.
- **Store-Ready MSIX Package** — `build_config.py` also produces `dist\AntivirusServer_Store.msix`, signed for upload to Microsoft Partner Center and not trusted locally.
- **Local Test Launcher MSIX** — `dist\AntivirusServer_Test_Launcher.msix` is signed and trusted for local sideload testing.

---

## Discord Server Blurb

**Windows Defender AV Dashboard** — YARA malware scanning, real-time network and process monitoring, ML threat scoring, encrypted quarantine, and Windows Firewall blocking. Built for Windows 10/11. Open source, runs locally.

---

## System Requirements

- **OS:** Windows 10 or Windows 11
- **Privileges:** Administrator for UAC elevation, Windows Firewall blocking, and some system scans
- **Python:** 3.11+ (required only for source/development runs)
- **RAM:** 4 GB+ recommended for ML/heuristic scanning

---

## Source Quick Start

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

3. Create a `.env` file in the project root with a valid Fernet key:

   ```dotenv
   FERNET_KEY=<44-character base64 Fernet key>
   ```

   Generate a key with:

   ```powershell
   python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
   ```

   `quick_start.py` loads `.env` through `python-dotenv`. See `.env.example` for additional options such as `FLASK_SECRET_KEY`, admin credentials, `MALWAREBAZAAR_API_KEY`, and `VT_API_KEY`.

4. Start the application:

   ```powershell
   python quick_start.py
   ```

   Then open the dashboard at:

   ```
   http://127.0.0.1:5000
   ```

   (Port falls back to `5001` if `5000` is in use.)

A local DNS server, folder watcher, and real-time network monitor start automatically in the background.

### Logging In

The dashboard uses HTTP Basic/Digest-style admin authentication. The default credentials are:

- **Username:** `admin`
- **Password:** `admin123`

Set different values in the `.env` file:

```dotenv
ADMIN_USERNAME=admin
ADMIN_PASSWORD=admin123
```

> **Warning:** Change `ADMIN_PASSWORD` before exposing the dashboard. This is a local, single-user dashboard and the default credentials are not secure.

---

## Building the Standalone Application

The project is packaged as a **onedir** PyInstaller distribution. This means the `antivirus_server.exe` entry point lives inside a folder (`dist\antivirus_server\`) that contains all of its Python modules, native extensions, models, YARA rules, signatures, blocklists, and other runtime assets.

Build everything with:

```powershell
python build_config.py
```

`build_config.py`:

- Builds `dist\antivirus_server\antivirus_server.exe` as an onedir bundle.
- Builds `dist\ssdeep_runner.exe` as a one-file bundle.
- Bundles the `models\`, `security\`, `templates\`, `static\`, and related runtime directories.
- Uses `--noconfirm` so existing build and dist folders are replaced without prompting.
- Does **not** request UAC elevation through the manifest, so the executable can be launched by a normal user.

### Packaged Application Layout

After a successful build, `dist\antivirus_server\` contains:

```
dist\antivirus_server\
  antivirus_server.exe          # Main entry point
  *.dll, _internal\              # Python runtime and extensions
  security\                      # YARA rules, scanners, and related modules
  models\                        # EMBER and other machine-learning resources
  templates\                     # Flask HTML templates
  static\                        # CSS, JS, icons, and favicon
  utils\                         # Supporting utilities
  malware_signatures.json        # Bundled signature seed
  ...                             # Additional bundled data files
```

`dist\ssdeep_runner.exe` is built as a sibling file for fuzzy-hash scanning.

### Creating Installer Files

The onedir package at `dist\antivirus_server` can be wrapped in either an executable installer (Inno Setup) or a per-user Windows Installer (MSI).

Both require the onedir build to exist first:

```powershell
python build_config.py
```

#### Inno Setup `.exe` Installer

1. Install **Inno Setup 6** from [jrsoftware.org](https://jrsoftware.org/isinfo.php).
2. Run:

   ```powershell
   build_installer.bat
   ```

3. The installer is created at:

   ```
   dist\AntivirusServer_Setup.exe
   ```

By default `installer.iss` requests admin privileges. To make the installer per-user, change `PrivilegesRequired` in `installer.iss` to:

```iss
PrivilegesRequired=lowest
```

#### WiX Toolset `.msi` Installer

1. Install **WiX Toolset v3.11** from [wixtoolset.org/docs/wix3](https://wixtoolset.org/docs/wix3/).
2. Run:

   ```powershell
   build_msi.bat
   ```

3. The MSI is created at:

   ```
   dist\AntivirusServer.msi
   ```

`installer.wxs` is already configured for a per-user install in the current user's local programs folder (`%LOCALAPPDATA%\Programs\Antivirus Server`).

### Datasets and Models

The project can be trained on several malware detection datasets:

- **EMBER 2018** — `data\ember2018\ember2018\`
  - Public PE feature dataset from Endgame.
  - Files: `train_features_0.jsonl` .. `train_features_5.jsonl` and `test_features.jsonl`.
  - Train the EMBER classifier with:
    ```powershell
    python train_ember_classifier.py --data-dir data\ember2018\ember2018
    ```

- **BODMAS** — `data\bodmas\`
  - 134,435 Windows PE feature vectors with benign/malicious labels.
  - Downloaded from: https://drive.google.com/drive/folders/1Uf-LebLWyi9eCv97iBal7kL1NgiGEsv_?usp=sharing
  - The included BODMAS malware classifier is saved as `models\bodmas_malware_classifier.pkl`.
  - It scores ~0.999 AUC and ~0.997 F1 on the BODMAS test split.
  - A 1D-CNN trained on BODMAS is exported to `models\bodmas_cnn.onnx` with `models\bodmas_cnn_scaler.pkl` and used via ONNX Runtime at scan time.

- **Synthetic threat-type models** — `data\labeled\`
  - Labeled JSON files for ~150 threat categories.
  - Train all category models with:
    ```powershell
    python train_with_real_data.py
    ```
  - Produces `models\<threat_type>_model.pkl` for each discovered category.

- **Static file malware classifier** — `train_malware_classifier.py`
  - Trains on `data\labeled\` for adware/malware/trojan/worm.
  - Produces `models\file_malware_classifier.pkl`.
  - The reported score is static-only (dynamic features zeroed), giving a realistic real-world estimate.

### Running the Packaged Application

The onedir executable should be launched from its own directory. For debugging, keep the console open and visible:

```powershell
$exeDir = "C:\Users\<you>\...\dist\antivirus_server"
& "$exeDir\antivirus_server.exe" --debug
```

Or, if you are in the project root after building:

```powershell
dist\antivirus_server\antivirus_server.exe --debug
```

Use `--debug` to enable tracebacks and extra startup output. When running without `--debug`, the Flask server and background services still start, but unhandled exceptions are reported more quietly.

**Important:** Do not run the packaged executable from `C:\Windows` or other protected directories. The application writes logs and runtime state next to the executable, and protected locations will cause permission errors.

### Runtime Directories

The packaged executable creates the following runtime directories next to `antivirus_server.exe` as needed:

- `data\` — Scan cache and temporary working data
- `uploads\` — Files uploaded through the dashboard
- `quarantine\` — Fernet-encrypted quarantine files
- `failed_quarantine\` — Files that could not be quarantined
- `encrypted\` — User-encrypted files from the browser UI
- `instance\` — Flask instance files
- `logs\` — Application log output

`dns_server.py` writes `dns_server.log` and `malicious_domains.json` directly in the executable directory.

---

## Configuration and Secrets

Create a `.env` file next to `antivirus_server.exe` (for the packaged app) or in the project root (for source runs). The following variables are the most important:

| Variable | Purpose |
|----------|---------|
| `FERNET_KEY` | **Required.** 44-character base64 Fernet key used for quarantine and file encryption. |
| `FLASK_SECRET_KEY` | Optional Flask session secret. |
| `MALWAREBAZAAR_API_KEY` | Optional API key for downloading malware hashes. |
| `VT_API_KEY` | Optional VirusTotal API key for hash enrichment. |

Generate a Fernet key:

```powershell
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Example `.env`:

```dotenv
FERNET_KEY=your-44-char-fernet-key-here
FLASK_SECRET_KEY=a-random-secret
```

Never commit `.env`, `key.pem`, `cert.pem`, or any real private key. The `.gitignore` already excludes `.env`, `*.pem`, build folders, logs, quarantine, encrypted files, and other runtime artifacts. If these files were previously committed, remove them from the Git index without deleting the local files:

```powershell
git rm --cached .env key.pem cert.pem
```

---

## YARA Scanning and Heuristics

- On-demand scans are available from the dashboard YARA scanner page.
- The conditional startup scan launches automatically when the scanner page is opened.
- YARA rules are loaded from `security\yara_rules\`.
- Media files (common image, video, and audio extensions) are skipped during scanning to improve performance.
- The `fast_match` YARA argument is not used because it is unsupported.
- Broad YARA matches in legitimate Windows system files (for example, `Widgets.exe`, `ShellExperienceHost.exe`, `taskhostw.exe`) are treated as heuristic indicators, not automatic malware confirmations.

### Stopping a Runaway Scan

If a scan becomes unresponsive or consumes excessive resources, terminate the `antivirus_server.exe` process from Task Manager or PowerShell:

```powershell
Get-Process -Name antivirus_server -ErrorAction SilentlyContinue | Stop-Process -Force
```

Check that the process is gone before starting another scan.

---

## Conditional Startup Scan

`conditional_startup.py` performs a combined startup scan. Critical YARA matches, high-confidence ML detections (BODMAS CNN / EMBER / synthetic), and ransomware heuristics are all treated as malware and quarantined automatically. In the packaged onedir environment it uses normal package imports; in source runs it falls back to file-based loading. The result is a structured dictionary with the following keys:

- `scanned_files`
- `quarantined_files`
- `errors`
- `process_events`
- `results`
- routine maintenance results
- `ml_detections`
- `ransomware_indicators`
- `persistence_indicators`
- `log_output`

---

## ssdeep Fuzzy-Hash Runner

Build the standalone ssdeep runner with:

```powershell
python tools\build_runner_exe.py
```

The output is placed at `dist\ssdeep_runner.exe`.

Run a directory scan:

```powershell
dist\ssdeep_runner.exe --rules security\yara_rules\yara_rules.yar --dir security\yara_rules --threshold 60
```

Scan a single file:

```powershell
dist\ssdeep_runner.exe --rules security\yara_rules\yara_rules.yar --target "path\to\file.exe"
```

The `--rules` argument is required. Use `--threshold` to set the ssdeep match cutoff.

---

## Signature Updates

The scanner uses `malware_signatures.txt` for hash-based detection (MD5, SHA1, SHA256, SHA512). To fetch the latest sample hashes from MalwareBazaar:

1. Get a free API key from [Abuse.ch](https://auth.abuse.ch/).
2. Copy `.env.example` to `.env` and set:

   ```dotenv
   MALWAREBAZAAR_API_KEY=your-key-here
   ```

3. Run:

   ```powershell
   python update_signatures.py
   ```

In the packaged app the signature database is created or updated next to the executable on first startup if it does not already exist.

---

## Optional: VirusTotal Enrichment

If you add a `VT_API_KEY` to `.env`, the scanner will:

1. Query VirusTotal for any file whose hash is not in the local signature list.
2. Add the file's MD5/SHA1/SHA256/SHA512 to the signature database if VirusTotal reports it malicious.
3. Check quarantined files against VirusTotal and record flagged hashes.

```dotenv
VT_API_KEY=your-vt-key-here
```

---

## Command-Line Usage

The source tree includes `antivirus_cli.py` for command-line operations:

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

- Persistent scan cache with atomic save, backup, and reset logic.
- Safe `tarfile` extraction with member validation and `filter="data"`.
- SHA1/MD5 used with `usedforsecurity=False` for non-cryptographic file hashing.
- Subprocess hardening: `build_config.py` now calls PyInstaller in-process instead of `subprocess.run`.
- ONNX Runtime inference with `models\bodmas_cnn.onnx` for a 1D-CNN trained on BODMAS PE features.
- Static frontend JavaScript uses `document.createElement()` and `textContent` instead of HTML string sinks.

---

## Known Limitations

- The bundled WSGI server is **Waitress**. It is suitable for local and trusted-LAN use; for internet-facing or high-traffic deployments, run behind a reverse proxy with HTTPS (IIS, nginx, Caddy).
- UAC elevation, Windows Firewall blocking, WMI, and some secure-memory helpers require Windows.
- `pywin32` installation may need manual steps on some environments.
- The packaged executable is a local onedir bundle. It is meant to be moved as a whole directory, not as a single `.exe` file.
- YARA rules have been tuned to produce very few false positives on legitimate Windows components, but high-confidence matches should still be reviewed before quarantining system files.

---

## License

This project is released under the [MIT License](LICENSE).

---

## Repository

[https://github.com/soluzka/antivirus-yara-rules](https://github.com/soluzka/antivirus-yara-rules)
