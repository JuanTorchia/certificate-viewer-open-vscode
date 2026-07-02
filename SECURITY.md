# Security Policy

CertView parses certificate-related files inside the VS Code extension host. Treat all parsed files as untrusted input.

## Supported Versions

Security fixes are applied to the latest published version.

## Reporting a Vulnerability

Please report suspected vulnerabilities privately through GitHub Security Advisories when available. If that is not available, open an issue with minimal detail and ask for a private contact path.

Do not include private keys, production certificates, customer data, passwords, or exploit payloads in public issues.

Useful reports include:

- A minimal synthetic file or generator script.
- The affected CertView version.
- VS Code version and operating system.
- Expected behavior and observed behavior.
- Whether the issue causes extension-host blocking, crash, incorrect parsing, unsafe rendering, or secret exposure.

## Security Boundaries

CertView:

- Works offline.
- Does not establish certificate trust.
- Does not perform full RFC 5280 path validation.
- Does not check revocation status.
- Does not decrypt encrypted private keys.
- Does not provide compliance, audit, FIPS, WebPKI, or legal assurance.

Security-sensitive changes should include tests for malformed, oversized, or adversarial inputs where practical.
