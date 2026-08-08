# Antivirus (YARA-based)

A Windows-first security dashboard and CLI for YARA-based malware scanning,
real-time network and process monitoring, encrypted quarantine, and folder
watching. It is built around a Flask web UI (`quick_start.py`) and a
companion command-line tool (`antivirus_cli.py`).

## Requirements

- Windows 10/11 (UAC elevation, Windows Firewall, WMI, and secure-memory
  helpers are Windows-specific)
- Python 3.11+
- Dependencies in `requirements.txt`:

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

   `FERNET_KEY` is required by quarantine encryption and the file
   encrypt/decrypt features.

2. Optional `.env` settings include the Flask secret key, admin credentials,
   quarantine size limits, etc. See `.env.example` for the full list.

## Running the app

```
python quick_start.py
```

On Windows, `quick_start.py` first checks for administrator rights. If it is
not running elevated, it prompts via UAC and relaunches itself. This is needed
for system-directory scanning, firewall blocking, and other protected
operations.

The Flask dashboard starts on `http://127.0.0.1:5000` (falling back to 5001 if
5000 is in use). A local DNS server and a background YARA folder-watcher also
start automatically.

## Command-line usage

```
python antivirus_cli.py scan <path>
python antivirus_cli.py quarantine list
python antivirus_cli.py quarantine release <file.enc> <dest_dir>
python antivirus_cli.py quarantine delete <file.enc>
python antivirus_cli.py monitor
python antivirus_cli.py update-signatures
```

- `scan` detects malware, prompts to quarantine, and deletes the original only
  after the user confirms.
- `quarantine release` decrypts a `.enc` file to the destination and removes
  the encrypted copy from quarantine.
- `quarantine delete` permanently removes a `.enc` file from quarantine.

## Tests

The root test scripts can be run individually:

```
python -m pytest test_antivirus_cli.py -v
python simple_yara_test.py
python test_yara.py            # scans the project root; can take a while
python fernet_decrypt_test.py  # requires the same FERNET_KEY that encrypted the sample
python test_environment.py
```

## Features

- **YARA scanning** -- signature-based detection using rule sets in
  `security/yara_rules/`, with on-demand and background scanning.
- **Persistent scan cache** -- `data/scan_cache.json` stores file
  fingerprints/verdicts to avoid rescanning unchanged files. It is saved
  atomically and is automatically backed up and reset if it becomes corrupt
  or truncated.
- **Safe quarantine** -- protected system locations, oversized files, and
  unreadable files are skipped; encryption (Fernet) and original-file removal
  happen only when the user confirms.
- **Network traffic monitoring** -- live connection/protocol/process stats
  plus heuristic C2-pattern detection.
- **Folder watching** -- tracks configured directories and reports file
  counts, high-risk file types, and accessibility.
- **Conditional startup scan** -- a combined scan of monitored directories and
  running processes with live progress reporting.
  - Optional, off-by-default steps:
    - `AV_ENABLE_TEMP_CLEANUP=1` -- deletes files under temp directories.
    - `AV_ENABLE_ROUTINE_MAINTENANCE=1` -- runs a larger scan battery over
      critical system directories.
- **File encryption/decryption** -- upload a file to encrypt or decrypt
  through the dashboard or `/file_crypto`; uploads are capped at 125MB.

## Known limitations

- `quick_start.py` runs Flask's built-in development server, which is not
  intended for production.
- Several features (UAC elevation, Windows Firewall blocking, in-memory secure
  key storage, WMI checks) are Windows-only.
