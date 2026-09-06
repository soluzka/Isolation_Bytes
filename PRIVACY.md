# Privacy Policy

**Effective date:** August 17, 2026

This Privacy Policy describes how the Antivirus Server application ("the application") handles information.

## Local-first design

The application is designed to run locally on your Windows computer. The dashboard binds to `127.0.0.1` (localhost) by default and is not intended to be exposed to the public internet.

## Information the application accesses

Depending on your configuration and the actions you choose, the application may access:

- Files and directories you select for scanning
- Running process metadata
- Network connection and DNS metadata
- Quarantine records stored by the application
- Optional external malware reputation services, such as MalwareBazaar or VirusTotal, when an API key is configured
- The optional local GGUF assistant model, if included

## How information is used

Accessed information is used only to provide security features:

- Malware detection and YARA rule matching
- Real-time process and network monitoring
- Firewall block and unblock operations
- Encrypted quarantine, restore, and deletion
- Local scan reports and findings review

The application does not upload files or scan results to a central server unless you explicitly enable and configure an external API key.

## Information stored on disk

The application stores the following locally:

- Scan history and findings
- Encrypted quarantine files
- Logs and runtime state
- Configuration and secrets (e.g., `.env` file)
- Optional local model files

These files are stored in the application runtime directory or `C:\ProgramData\AntivirusServer`, depending on the installation type.

## Optional external services

When you configure an optional API key, the application may request malware reputation or IP reputation information from third-party services. Those requests are subject to the privacy policies of the respective services:

- [MalwareBazaar](https://bazaar.abuse.ch/)
- [VirusTotal](https://www.virustotal.com/)
- [Project Honeypot](https://www.projecthoneypot.org/)

## Administrator service

The packaged administrator service runs under the LocalSystem account so it can perform privileged security operations. It communicates with the dashboard through a restricted local named pipe. It does not expose arbitrary shell commands or unrestricted file paths.

## Your responsibilities

To protect your data:

- Keep the dashboard bound to localhost.
- Use strong, unique administrator credentials.
- Do not commit `.env`, `.pfx`, `.p12`, private keys, API keys, quarantine data, or local model files.
- Review quarantine and firewall actions before confirming them.

## Changes to this policy

This policy may be updated as the application changes. The latest version is available in the repository and included with distributed packages.

## Contact

For privacy questions or concerns, open an issue in the project repository.
