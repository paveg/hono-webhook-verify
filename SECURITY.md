# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability, please report it responsibly:

1. **Do NOT open a public GitHub issue**
2. Use [GitHub Security Advisories](https://github.com/paveg/hono-webhook-verify/security/advisories/new) to report privately
3. Include steps to reproduce, affected versions, and potential impact

## Response Timeline

- **Acknowledgment**: Within 48 hours
- **Initial assessment**: Within 1 week
- **Fix release**: As soon as possible, depending on severity

## Scope

This policy covers the `hono-webhook-verify` npm package. Security issues in dependencies should be reported to the respective maintainers.

## Security Design

This library follows these security principles:

- **Constant-time signature comparison** to prevent timing attacks
- **Timestamp validation** to mitigate replay attacks (where supported by provider)
- **Empty secret rejection** at construction time to prevent misconfiguration
- **Web Crypto API** for all cryptographic operations (no custom implementations)
