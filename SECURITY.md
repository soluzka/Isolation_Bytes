# Security Policy

## Supported Versions

Security fixes are applied to the current release line shown in `version.txt`.
The current project version is **1.0.966.0**.

| Version | Supported |
| ------- | --------- |
| 1.0.966.x | Yes |
| Older releases | No |

Update to the latest release before reporting an issue that may already be fixed.

## Reporting a Vulnerability

Please report suspected security vulnerabilities privately through the repository's
GitHub security reporting process rather than opening a public issue. Include:

- A clear description of the vulnerability and its impact
- The affected version
- Reproduction steps or a minimal proof of concept
- Any relevant logs or screenshots with secrets removed
- Suggested mitigation, if known

Do not include passwords, private keys, API tokens, malware samples, or other
sensitive material in a public issue. Reports will be reviewed and acknowledged
as soon as practical.

## Scope and Deployment Notes

This project is a local Windows antivirus research dashboard. It should not be
exposed to the public internet. Keep the dashboard, administrator service, MSIX
certificate material, API keys, quarantine data, and local model files protected.
