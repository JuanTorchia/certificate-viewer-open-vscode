import * as assert from "assert";
import * as crypto from "crypto";
import { p384 } from "@noble/curves/nist.js";
import { CertificateExtension } from "../../models/certificate";
import { validateCertificate } from "../../parsers/certLinter";
import { CT_LOG_NAMES } from "../../parsers/ctLogs";

function p384PublicKeyForScalar(scalar: bigint): crypto.KeyObject {
  const privateBytes = Buffer.alloc(48);
  privateBytes.writeBigUInt64BE(scalar, 40);
  const rawPublicKey = p384.getPublicKey(privateBytes, false);
  return crypto.createPublicKey({
    key: {
      kty: "EC",
      crv: "P-384",
      x: Buffer.from(rawPublicKey.subarray(1, 49)).toString("base64url"),
      y: Buffer.from(rawPublicKey.subarray(49)).toString("base64url"),
    },
    format: "jwk",
  });
}

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

  test("detects P-384 public keys whose private scalar is below 2^32", () => {
    const x509 = {
      serialNumber: "01",
      validFrom: "Jan 01 00:00:00 2026 GMT",
      validTo: "Jan 01 00:00:00 2027 GMT",
      subjectAltName: undefined,
      ca: false,
      publicKey: p384PublicKeyForScalar((1n << 32n) - 1n),
    } as unknown as crypto.X509Certificate;

    const input = {
      x509,
      subject: { commonName: "example.com" },
      keyUsage: [],
      extendedKeyUsage: [],
      extensions: [],
      publicKeyAlgorithm: "EC",
      publicKeySize: 384,
      signatureAlgorithm: "sha384WithECDSA",
    };

    const findings = validateCertificate(input);
    assert.ok(findings.some(finding => finding.message.includes("matches a private scalar in the first 2^32 values")));

    const outOfRange = validateCertificate({
      ...input,
      x509: { ...x509, publicKey: p384PublicKeyForScalar(1n << 32n) } as crypto.X509Certificate,
    });
    assert.ok(!outOfRange.some(finding => finding.message.includes("first 2^32 values")));
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
