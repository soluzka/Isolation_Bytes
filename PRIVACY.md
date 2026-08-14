# Privacy & Data Handling

## Local-Only by Default

All scans, quarantine data, logs, and cached results stay on your local machine inside `data\` and the configured quarantine folder.

## No Telemetry

This application does not send crash reports, usage analytics, or scan results to the developer by default.

## Optional External Lookups

When API keys are configured in `.env`, the app may query external services for hash reputation and IOC enrichment:

- MalwareBazaar
- VirusTotal
- ThreatFox
- URLhaus
- HTTPBL

Only the hash or identifier you submit is sent to those services.

## Quarantine Encryption

Quarantined payloads are encrypted before storage. Metadata sidecars are stored as JSON and do not contain the encryption key.

## Session Cookies

Session state is kept in a browser cookie using the `SECRET_KEY` from `.env`.
