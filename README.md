# CertView

**Inspect X.509 certificates directly inside VS Code — no terminal, no online tools.**

![CertView logo](images/icon.svg)

---

## Features

- **Rich certificate viewer** — subject, issuer, validity dates, serial number, fingerprints, SANs, and all extensions at a glance
- **Chain support** — PEM files with multiple certificates are displayed as a navigable chain
- **Expiry warnings** — certificates expiring soon are highlighted in the editor and the sidebar
- **Certificate Explorer** — sidebar panel listing all cert files in your workspace
- **Syntax highlighting** — PEM blocks get proper colorization in text mode
- **Copy fingerprint** — one click to copy SHA-1 or SHA-256 fingerprint to clipboard

### Supported file types

| Extension | Format |
|-----------|--------|
| `.pem` | PEM (text, single or chain) |
| `.cer` `.crt` | DER or PEM certificate |
| `.der` | DER binary |
| `.p7b` `.p7c` `.p7` | PKCS#7 certificate bundle |
| `.pfx` `.p12` | PKCS#12 (metadata only) |
| `.csr` `.req` | Certificate Signing Request |
| `.crl` | Certificate Revocation List |

---

## Usage

1. Open any supported certificate file — CertView opens automatically
2. Navigate between **Summary**, **Details**, and **Raw** tabs
3. Use the **Certificates** panel in the Explorer sidebar to browse all certs in your workspace
4. Right-click a cert file → **CertView: Open Certificate** to force the custom viewer

---

## Extension Settings

| Setting | Default | Description |
|---------|---------|-------------|
| `certview.showExpiredWarning` | `true` | Highlight expired certificates |
| `certview.warningDaysBeforeExpiry` | `30` | Days before expiry to show warning |
| `certview.defaultView` | `"summary"` | Default tab: `summary`, `details`, or `raw` |

---

## Requirements

- VS Code 1.85 or later
- No external tools required — parsing is done with the Node.js built-in `crypto` module

---

## Known Issues

- PKCS#12 (`.pfx`/`.p12`) files require no password for metadata display; encrypted private keys are not shown
- Very large CRL files (>10 MB) may take a moment to parse

---

## Release Notes

### 0.1.0

Initial release:
- Custom editor for all major certificate formats
- Certificate Explorer sidebar
- Expiry warnings and fingerprint copy
- PEM syntax highlighting
