# Antivirus Server — Privacy Policy

Last updated: 2026-08-14

## 1. Information We Collect

Antivirus Server is a local-first security application. It operates primarily on your device and does not send your files, file contents, or personal data to our servers. The application does not send usage telemetry or analytics to the developer by default.

The application may collect or process the following types of data locally on your device:

- **File metadata** — file names, paths, sizes, hashes (MD5/SHA1/SHA256), and file system properties during scans.
- **File hashes and signatures** — hashes are compared against local malware signature databases and, when enabled, third-party threat intelligence feeds (e.g., MalwareBazaar, ThreatFox, URLhaus).
- **Process and network events** — running process names, network connection endpoints, and related security telemetry for real-time protection and network monitoring.
- **Quarantine records** — file paths, original locations, and cryptographic metadata required to restore or delete quarantined files.
- **Application logs** — diagnostic and runtime logs stored on your device for troubleshooting.

## 2. How We Use Information

All processing is performed locally to provide the following security features:

- On-demand and scheduled malware scanning
- Real-time file and process monitoring
- Network threat detection and IP/domain reputation checking
- Machine-learning-based malware classification
- Quarantine and remediation of detected threats

File hashes and signatures may be sent to third-party threat intelligence services only when an **automatic signature update** is performed, and only the relevant hash values or queries are transmitted — never the full file contents.

## 3. Data Sharing

We do not sell, rent, or share your personal data. The application may contact the following external services solely for security lookups and updates:

- MalwareBazaar
- ThreatFox
- URLhaus
- Abuse.ch DNS Blocklist (DNSBL) and similar public threat feeds

These services receive only the minimum data necessary for the lookup or update (e.g., a hash value or domain name).

## 4. Security and Access Controls

- **Authentication** — The dashboard requires a username and password configured in `.env` (`ADMIN_USERNAME` and `ADMIN_PASSWORD`).
- **CSRF protection** — State-changing requests from the browser must include a per-session `X-CSRF-Token` header.
- **Session cookies** — Login state is stored in a browser cookie signed with the `SECRET_KEY` from `.env`.

## 5. Data Storage and Security

- File scan results, quarantine data, logs, and runtime state are stored locally on your device.
- Quarantined files are stored in a dedicated, access-controlled directory.
- Quarantined payloads are encrypted before storage. Metadata sidecars are JSON and do not contain the encryption key.
- Cryptographic keys for quarantine/restore operations are generated and stored on your device.
- The web server is **Waitress**, bound to `127.0.0.1` by default, so it is not exposed to the internet.
- The application does not maintain an account or collect personally identifiable information (PII) such as email addresses, phone numbers, or postal addresses.

## 6. Scan Controls

- **Conditional startup** and other scans run locally and can be cancelled at any time using the dashboard's **Break the Cycle** control.
- Scans respect user-defined monitored folders and do not automatically upload files to external services.

## 7. Your Choices

You may at any time:

- Disable automatic signature updates.
- Remove or add monitored directories.
- Delete quarantined files.
- Clear application logs and runtime data from the local storage directory.

## 8. Children’s Privacy

This product is not intended for use by children under 13. We do not knowingly collect data from children.

## 9. Changes to This Policy

We may update this Privacy Policy from time to time. Changes will be posted with an updated effective date.

## 10. Contact

For questions or concerns about this Privacy Policy, please open an issue in the project repository or contact the project maintainer.
