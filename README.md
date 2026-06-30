# X509 Certificate Utility

**Stop opening terminals just to inspect a certificate.**
View X.509 certificates, keystores, and signing requests directly inside VS Code — no OpenSSL commands needed.

![Certificate details view](https://raw.githubusercontent.com/JuanTorchia/certview-assets/main/preview-cert-details.png)

## What it does

Double-click any certificate file and instantly see:

- **Subject & Issuer** — Common Name, Organization, Country, and more
- **Validity period** — clear expiry date with a visual status banner (valid / expiring soon / expired)
- **Fingerprints** — certificate SHA-1/SHA-256 and key SPKI SHA-1/SHA-256 with one-click copy
- **Public key** — algorithm and key size
- **Key parameters** — RSA public exponent and EC named curve aliases where the runtime exposes them
- **Extensions** — SANs, Key Usage, Extended Key Usage, Basic Constraints, Name Constraints, SCTs, and arbitrary critical or noncritical extensions
- **CSRs and CRLs** — requested CSR SANs/extensions, CSR key fingerprints, and CRL issuer/update/signature metadata
- **Lint findings** — errors, warnings, and informational notices tied to RFC references
- **RFC tooltips** — hover over sections and fields for relevant RFC guidance

## Expiry warnings at a glance

Never get caught by a surprise certificate expiration. Files expiring within 30 days get a yellow warning banner; expired certificates show a red one.

![Expiry warning banner](https://raw.githubusercontent.com/JuanTorchia/certview-assets/main/preview-expiry-warning.png)

## Certificate chains

Multi-certificate files (chains, P7B bundles) are displayed as tabbed panels — one tab per certificate in the chain.

![Certificate chain with tabs](https://raw.githubusercontent.com/JuanTorchia/certview-assets/main/preview-chain-bundle.png)

## CA certificates

Self-signed and CA certificates are clearly identified.

![CA certificate view](https://raw.githubusercontent.com/JuanTorchia/certview-assets/main/preview-ca-certificate.png)

## Certificate Revocation Lists

CRL files open with issuer and update timestamps — no more decoding DER by hand.

![CRL viewer](https://raw.githubusercontent.com/JuanTorchia/certview-assets/main/preview-crl-viewer.png)

## Supported formats

| Extension | Format |
| --- | --- |
| `.pem` | PEM — single certificate, certificate chain, public key, private key, or mixed certificate/key bundle |
| `.cer` `.crt` | DER or PEM certificate |
| `.der` | DER binary certificate, with DER SPKI/PKCS#8 key fallback |
| `.p7b` `.p7c` `.p7` | PKCS#7 certificate bundle |
| `.crl` | Certificate Revocation List |
| `.csr` | Certificate Signing Request (PKCS#10) |
| `.p12` `.pfx` | PKCS#12 keystore — password prompt if protected |
| `.key` `.pub` | PEM or DER public keys and unencrypted private keys, plus encrypted private-key detection without decryption prompts |
| `.jwk` | JSON Web Key public keys |

## Usage

- **Open a file** → the viewer opens automatically on double-click
- **Right-click** any supported file → *X509 Certificate Utility: Open*
- **Certificates panel** in the Explorer sidebar lists all cert files in the workspace
- **Hover** sections or fields in the certificate view to see RFC context
- **Hover or focus** the `?` indicator beside fields and sections to see RFC context inside the webview
- **Copy lint report** from the validation banner for JSON output suitable for issue comments or reviews

## Settings

| Setting | Default | Description |
| --- | --- | --- |
| `certview.warningDaysBeforeExpiry` | `30` | Days before expiry to show the warning banner |
| `certview.showExpiredWarning` | `true` | Highlight expired certificates |

## Requirements

- VS Code 1.85 or later
- Works fully offline — no network access, no telemetry
- Files larger than 5 MiB are refused before parsing to protect the VS Code extension host from unbounded certificate, PKCS#7, or PKCS#12 processing

## Security and validation notes

- The viewer performs offline structural and profile lint checks for validity dates, CA/key usage consistency, SAN presence and criticality, extension criticality, and unrecognized extensions.
- Multi-certificate files are checked for issuer/subject ordering, CA marking, keyCertSign usage, validity nesting, and path length constraints. These checks are not full RFC 5280 certification path validation.
- Critical and noncritical X.509 v3 extensions are shown with OID, display name, and decoded or hexadecimal value where available. The local OID registry includes common X.520/RDN, PKCS #9, EKU, CA/B Forum policy, public-key algorithm, named-curve, Brainpool, SM2, Microsoft, and Certificate Transparency OIDs. Well-formed Certificate Transparency SCT lists are decoded into SCT entries with version, known log name, log ID, timestamp, and signature algorithm; malformed SCT values fall back to raw DER. The built-in CT log names cover current and recent Google CT log list v3 entries for major operators, including Google, Cloudflare, DigiCert, Sectigo, Let's Encrypt, TrustAsia, Geomys, and IPng Networks.
- CSR parsing extracts subject fields, requested subjectAltName entries, requested extension names, public-key metadata, public-key PEM, and SPKI fingerprints where supported by the runtime.
- CRL parsing extracts issuer, thisUpdate, nextUpdate, revoked-entry count, signature algorithm, selected CRL extensions, and CRL fingerprints.
- Mixed PEM files that contain both certificate and key blocks are shown as a bundle instead of dropping key blocks.
- Public and private key views include SHA-1 and SHA-256 fingerprints over the DER-encoded SubjectPublicKeyInfo.
- Newer algorithms such as ML-DSA depend on the VS Code extension host's Node.js and OpenSSL support.
- Algorithm support is runtime-dependent. CertView displays algorithms that Node.js can parse from X.509 SubjectPublicKeyInfo, PKCS#8, SPKI, or JWK inputs. RSA, RSA-PSS, EC, Ed25519, Ed448, and runtime-supported ML-DSA keys are covered by tests or guarded runtime checks. ML-KEM support depends on the extension host's Node.js/OpenSSL key import support and is not guaranteed on older runtimes.
- Encrypted private keys are detected but not decrypted; CertView does not prompt for private-key passwords.
- Lint findings are advisory. They do not establish certificate trust, revocation status, WebPKI compliance, RFC 5280 path validation, FIPS compliance, Common Criteria conformance, or organizational policy compliance.

This project and its documentation include AI-assisted content. Outputs should be reviewed by a qualified security, PKI, and compliance professional before use as compliance evidence, audit evidence, legal submission, accreditation material, or external assurance material.

## Release Notes

### 0.3.5

- Bumped package metadata for the expanded certificate/key linting release

### 0.3.4

- Added certificate lint findings in the viewer and native VS Code Problems diagnostics
- Added broader X.509 extension decoding, chain checks, and path length validation
- Added PEM, DER, JWK, and runtime-dependent ML-DSA key viewing support
- Detects encrypted private keys without password prompts or decryption
- Hardened parsing with input limits and safer handling for newer certificate algorithms

### 0.3.1

- CI pipeline improvements and lint cleanup

### 0.3.0

- Added `.csr` support — Certificate Signing Request viewer
- Added `.p12` / `.pfx` support — extracts certificates from PKCS#12 keystores with password prompt

### 0.1.4

- Initial release — local certificate viewing
