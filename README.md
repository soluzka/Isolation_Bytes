# Antivirus (YARA-based)

A Flask-based antivirus/security dashboard for Windows featuring YARA-based
malware scanning, real-time network traffic monitoring, folder watching,
process scanning, quarantine management, and file encryption/decryption.

## Requirements

- Windows (several features rely on Windows-specific APIs: Windows Firewall
  via `netsh`, `VirtualLock`/`VirtualUnlock` for secure key storage, etc.)
- Python 3.11+
- Dependencies from `requirements.txt`:

  ```
  pip install -r requirements.txt
  ```

  Note: `pywin32` may need a separate install step on some setups:

  ```
  pip install pywin32==306 --no-deps --only-binary=:all: --force-reinstall
  ```

## Setup

1. Copy/create a `.env` file in the project root with at least:

   ```
   FERNET_KEY=<44-character base64 Fernet key>
   ```

   Generate one with:

   ```
   python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
   ```

   `FERNET_KEY` is required by the quarantine encryption and file
   encrypt/decrypt features; the app will fail to start those features
   without it.

2. Other optional settings live in `.env` (secret key, admin credentials,
   quarantine size limits, etc.) -- see the comments in that file.

## Running

```
python quick_start.py
```

This starts the Flask app on `http://127.0.0.1:5000` (falls back to 5001 if
5000 is in use), along with a local DNS server and a background thread that
continuously YARA-scans monitored directories.

## Features

- **YARA scanning** -- signature-based malware detection using rule sets in
  `security/yara_rules/`, with real-time and on-demand scanning.
- **Network traffic monitoring** -- live connection/protocol/process stats
  via `psutil` (`/get_traffic_stats`), plus a lightweight heuristic that
  flags established connections to uncommon ports on external hosts
  (`/get_c2_patterns`).
- **Folder watching / monitored directories** -- tracks a configurable set
  of directories and reports file counts, high-risk file types, and
  accessibility per directory (`/get_network_monitored_directories`,
  `/get_folder_watcher_paths`). These endpoints scan one level deep per
  call rather than recursing through the whole tree, to keep response
  times bounded even for large directories.
- **Conditional startup scan** -- a combined scan (`/run_startup`) covering
  monitored directories and running processes, with live progress reported
  via `/api/conditional_startup/status` (files scanned, quarantined,
  errors, process events, start/last-updated/last-run timestamps).
  - Two optional, off-by-default steps can be enabled via environment
    variables since they are expensive and destructive/slow by default:
    - `AV_ENABLE_TEMP_CLEANUP=1` -- deletes all files under `%TEMP%`,
      `%SYSTEMROOT%\Temp`, and `%USERPROFILE%\AppData\Local\Temp`.
    - `AV_ENABLE_ROUTINE_MAINTENANCE=1` -- runs a much larger battery of
      scans (YARA, ML, heuristic, signature, etc.) over critical system
      directories including `C:\Windows\System32`.
- **Quarantine** -- detected threats are encrypted (Fernet) and moved to
  `%TEMP%\Defender_Quarantine`; manage/restore/delete via `/quarantine`,
  `/quarantine/list`.
- **File encryption/decryption** -- upload a file to encrypt or decrypt via
  the dashboard or `/file_crypto`. Uploads are capped at 125MB.

## Known limitations

- `data_analysis.py`'s `analyze_data()` (used by the quarantine/file-crypto
  encryption path) can be configured to run verbose debug analysis
  (hex-dumping file contents, plotting byte-frequency charts) on every
  call. This is significantly slower and can affect stability on large
  files; a lightweight version that skips this analysis is available in
  the function's history if performance/stability is a priority over the
  debug output.
- This runs Flask's built-in development server (`app.run(...)`), which is
  not intended for production use.
- Several features (Windows Firewall blocking, secure in-memory key
  storage, WMI-based checks) are Windows-only.
