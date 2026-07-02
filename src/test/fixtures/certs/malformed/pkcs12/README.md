# Malformed PKCS#12 Fixtures

These fixtures are synthetic test inputs for PKCS#12/PFX parser coverage.

- `wrong-password.p12` is a generated PKCS#12 bundle containing a short-lived self-signed certificate and test key. Its password is intentionally public: `correct-password`.
- `truncated.p12` is the first 24 bytes of that generated bundle.
- `empty.p12` is a zero-byte file.
- `non-pkcs12-der.p12` reuses a minimal DER value with an unexpected top-level ASN.1 tag.

Do not replace these with private or production PKCS#12 files.
