import * as assert from "assert";
import * as crypto from "crypto";
import { CertificateExtension } from "../../models/certificate";
import { validateCertificate } from "../../parsers/certLinter";
import { CT_LOG_NAMES } from "../../parsers/ctLogs";

suite("certLinter", () => {
  test("flags duplicate extensions and weak RSA keys in isolation", () => {
    const x509 = {
      serialNumber: "01",
      validFrom: "Jan 01 00:00:00 2026 GMT",
      validTo: "Jan 01 00:00:00 2027 GMT",
      subjectAltName: undefined,
      ca: false,
    } as unknown as crypto.X509Certificate;
    const extensions: CertificateExtension[] = [
      { oid: "2.5.29.17", name: "Subject Alternative Name", critical: false, value: "DNS:example.com" },
      { oid: "2.5.29.17", name: "Subject Alternative Name", critical: false, value: "DNS:www.example.com" },
    ];

    const findings = validateCertificate({
      x509,
      subject: { commonName: "example.com" },
      keyUsage: [],
      extendedKeyUsage: ["TLS Web Server Authentication"],
      extensions,
      publicKeyAlgorithm: "RSA",
      publicKeySize: 1024,
      signatureAlgorithm: "sha256WithRSAEncryption",
    });

    assert.ok(findings.some(finding => finding.message.includes("Duplicate extension OID 2.5.29.17")));
    assert.ok(findings.some(finding => finding.message.includes("RSA public key is 1024 bits")));
  });
});

suite("CT log names", () => {
  test("includes current and recent logs from major operators", () => {
    const names = Object.values(CT_LOG_NAMES);
    assert.ok(names.length >= 50);
    for (const expected of [
      "Google Argon2026h1",
      "Google Xenon2026h2",
      "Cloudflare Nimbus2027",
      "DigiCert Wyvern2026h1",
      "Sectigo Mammoth2026h1",
      "Sectigo Sabre2026h2",
      "TrustAsia HETU2027",
    ]) {
      assert.ok(names.includes(expected), `${expected} missing`);
    }
  });
});
