import * as assert from "assert";
import * as fs from "fs";
import * as path from "path";
import {
  getCertificateStatus,
  getDaysUntilExpiry,
  CertificateInfo,
} from "../../models/certificate";
import { parseCertificateFile } from "../../parsers/certParser";

const FIXTURES = path.resolve(__dirname, "../fixtures/certs");
const readText = (f: string): string => fs.readFileSync(path.join(FIXTURES, f), "utf-8");

function makeCert(notBefore: Date, notAfter: Date): CertificateInfo {
  return {
    pem: "",
    version: 3,
    serialNumber: "01",
    subject: { commonName: "test" },
    issuer: { commonName: "test" },
    validity: { notBefore, notAfter },
    subjectAltNames: [],
    keyUsage: [],
    extendedKeyUsage: [],
    extensions: [],
    signatureAlgorithm: "sha256WithRSAEncryption",
    publicKeyAlgorithm: "RSA",
    publicKeySize: 2048,
    fingerprints: { sha1: "", sha256: "" },
    isSelfSigned: true,
    isCA: false,
    findings: [],
  };
}

suite("getCertificateStatus", () => {
  test("returns 'valid' for cert valid for 100 days", () => {
    const now = new Date();
    const cert = makeCert(
      new Date(now.getTime() - 86400000),
      new Date(now.getTime() + 100 * 86400000)
    );
    assert.strictEqual(getCertificateStatus(cert), "valid");
  });

  test("returns 'expired' for cert whose notAfter is in the past", () => {
    const now = new Date();
    const cert = makeCert(
      new Date(now.getTime() - 200 * 86400000),
      new Date(now.getTime() - 86400000)
    );
    assert.strictEqual(getCertificateStatus(cert), "expired");
  });

  test("returns 'expiring-soon' for cert expiring in 15 days (default threshold=30)", () => {
    const now = new Date();
    const cert = makeCert(
      new Date(now.getTime() - 86400000),
      new Date(now.getTime() + 15 * 86400000)
    );
    assert.strictEqual(getCertificateStatus(cert), "expiring-soon");
  });

  test("returns 'expiring-soon' exactly at threshold boundary (30 days)", () => {
    const now = new Date();
    const cert = makeCert(
      new Date(now.getTime() - 86400000),
      new Date(now.getTime() + 30 * 86400000)
    );
    assert.strictEqual(getCertificateStatus(cert), "expiring-soon");
  });

  test("returns 'valid' just above threshold (31 days)", () => {
    const now = new Date();
    const cert = makeCert(
      new Date(now.getTime() - 86400000),
      new Date(now.getTime() + 31 * 86400000)
    );
    assert.strictEqual(getCertificateStatus(cert), "valid");
  });

  test("returns 'not-yet-valid' for cert whose notBefore is in the future", () => {
    const now = new Date();
    const cert = makeCert(
      new Date(now.getTime() + 86400000),
      new Date(now.getTime() + 365 * 86400000)
    );
    assert.strictEqual(getCertificateStatus(cert), "not-yet-valid");
  });

  test("respects custom warningDays parameter", () => {
    const now = new Date();
    const cert = makeCert(
      new Date(now.getTime() - 86400000),
      new Date(now.getTime() + 15 * 86400000)
    );
    assert.strictEqual(getCertificateStatus(cert, 10), "valid");
    assert.strictEqual(getCertificateStatus(cert, 20), "expiring-soon");
  });
});

suite("getCertificateStatus — with real fixtures", () => {
  test("expired fixture returns 'expired'", () => {
    const [cert] = parseCertificateFile(readText("expired.pem"));
    assert.strictEqual(getCertificateStatus(cert), "expired");
  });

  test("synthetic near-expiry cert returns 'expiring-soon'", () => {
    const now = new Date();
    const cert = makeCert(new Date(now.getTime() - 86400000), new Date(now.getTime() + 10 * 86400000));
    assert.strictEqual(getCertificateStatus(cert, 30), "expiring-soon");
  });

  test("self-signed fixture returns 'valid'", () => {
    const [cert] = parseCertificateFile(readText("self-signed.pem"));
    assert.strictEqual(getCertificateStatus(cert), "valid");
  });
});

suite("getDaysUntilExpiry", () => {
  test("returns negative days for expired cert", () => {
    const [cert] = parseCertificateFile(readText("expired.pem"));
    assert.ok(getDaysUntilExpiry(cert) < 0);
  });

  test("returns positive days for valid cert", () => {
    const [cert] = parseCertificateFile(readText("self-signed.pem"));
    assert.ok(getDaysUntilExpiry(cert) > 0);
  });

  test("returns approximately 10 days for synthetic near-expiry cert", () => {
    const now = new Date();
    const cert = makeCert(new Date(now.getTime() - 86400000), new Date(now.getTime() + 10 * 86400000));
    const days = getDaysUntilExpiry(cert);
    assert.ok(days >= 0 && days <= 12, `Expected 0-12 days, got ${days}`);
  });
});
