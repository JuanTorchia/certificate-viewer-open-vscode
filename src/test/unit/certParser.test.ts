import * as assert from "assert";
import * as fs from "fs";
import * as path from "path";
import * as forge from "node-forge";
import { parseCertificateFile, parseX509Name } from "../../parsers/certParser";

const FIXTURES = path.resolve(__dirname, "../fixtures/certs");
const CERT_FIXTURES = {
  "ca.pem": path.join(FIXTURES, "ca.pem"),
  "chain.pem": path.join(FIXTURES, "chain.pem"),
  "ec-key.pem": path.join(FIXTURES, "ec-key.pem"),
  "expired.pem": path.join(FIXTURES, "expired.pem"),
  "self-signed.der": path.join(FIXTURES, "self-signed.der"),
  "self-signed.pem": path.join(FIXTURES, "self-signed.pem"),
};
const readText = (f: keyof typeof CERT_FIXTURES): string => fs.readFileSync(CERT_FIXTURES[f], "utf-8");
const readBin = (f: keyof typeof CERT_FIXTURES): Buffer => fs.readFileSync(CERT_FIXTURES[f]);

interface TestCert {
  cert: forge.pki.Certificate;
  key: forge.pki.rsa.PrivateKey;
  pem: string;
}

function makeTestCert(options: { commonName: string; isCA: boolean; pathLenConstraint?: number; issuer?: TestCert; extraExtensions?: Array<Record<string, unknown>> }): TestCert {
  const keys = forge.pki.rsa.generateKeyPair(1024);
  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = cryptoSafeSerial(options.commonName);
  cert.validity.notBefore = new Date(Date.now() - 86400000);
  cert.validity.notAfter = new Date(Date.now() + 86400000);
  const attrs = [{ name: "commonName", value: options.commonName }];
  cert.setSubject(attrs);
  cert.setIssuer(options.issuer ? options.issuer.cert.subject.attributes : attrs);
  cert.setExtensions([
    {
      name: "basicConstraints",
      cA: options.isCA,
      critical: options.isCA,
      ...(options.pathLenConstraint !== undefined ? { pathLenConstraint: options.pathLenConstraint } : {}),
    },
    options.isCA
      ? { name: "keyUsage", keyCertSign: true, cRLSign: true, critical: true }
      : { name: "keyUsage", digitalSignature: true, critical: true },
    ...(options.extraExtensions ?? []),
  ] as Parameters<typeof cert.setExtensions>[0]);
  cert.sign(options.issuer?.key ?? keys.privateKey, forge.md.sha256.create());
  return { cert, key: keys.privateKey, pem: forge.pki.certificateToPem(cert) };
}

function makeCertWithSctExtension(value: Buffer): TestCert {
  return makeTestCert({
    commonName: "sct.example.com",
    isCA: false,
    extraExtensions: [{ id: "1.3.6.1.4.1.11129.2.4.2", critical: false, value: value.toString("binary") }],
  });
}

function makeSctList(...scts: Buffer[]): Buffer {
  const entries = scts.flatMap(sct => [uint16(sct.length), sct]);
  const body = Buffer.concat(entries);
  return Buffer.concat([uint16(body.length), body]);
}

function makeSct(options: { timestamp?: bigint; extensions?: Buffer; signature?: Buffer; logId?: Buffer } = {}): Buffer {
  const extensions = options.extensions ?? Buffer.alloc(0);
  const signature = options.signature ?? Buffer.from([0xde, 0xad, 0xbe, 0xef]);
  const sct = Buffer.alloc(1 + 32 + 8 + 2 + extensions.length + 2 + 2 + signature.length);
  let offset = 0;
  sct[offset++] = 0;
  (options.logId ?? Buffer.alloc(32, 0xab)).copy(sct, offset);
  offset += 32;
  sct.writeBigUInt64BE(options.timestamp ?? BigInt(Date.UTC(2024, 0, 1)), offset);
  offset += 8;
  sct.writeUInt16BE(extensions.length, offset);
  offset += 2;
  extensions.copy(sct, offset);
  offset += extensions.length;
  sct[offset++] = 4;
  sct[offset++] = 3;
  sct.writeUInt16BE(signature.length, offset);
  offset += 2;
  signature.copy(sct, offset);
  return sct;
}

function uint16(value: number): Buffer {
  const buffer = Buffer.alloc(2);
  buffer.writeUInt16BE(value);
  return buffer;
}

function cryptoSafeSerial(seed: string): string {
  return Buffer.from(seed).toString("hex").slice(0, 32) || "01";
}

suite("certParser — error cases", () => {
  test("throws on empty string", () => {
    assert.throws(() => parseCertificateFile(""), /No CERTIFICATE blocks found/);
  });

  test("throws when no CERTIFICATE block present", () => {
    assert.throws(
      () => parseCertificateFile("-----BEGIN PRIVATE KEY-----\naGVsbG8=\n-----END PRIVATE KEY-----"),
      /No CERTIFICATE blocks found/
    );
  });

  test("rejects oversized input before certificate parsing", () => {
    const hugePem = `-----BEGIN CERTIFICATE-----\n${"A".repeat(6 * 1024 * 1024)}\n-----END CERTIFICATE-----`;
    assert.throws(() => parseCertificateFile(hugePem), /larger than/);
  });
});

suite("certParser — X.509 name parsing", () => {
  test("does not split escaped commas in common names", () => {
    const subject = parseX509Name("CN=F5\\, Inc., O=F5\\, Inc., C=US");
    assert.strictEqual(subject.commonName, "F5, Inc.");
    assert.deepStrictEqual(subject.organization, ["F5, Inc."]);
    assert.deepStrictEqual(subject.country, ["US"]);
  });
});

suite("certParser — self-signed PEM", () => {
  let certs: ReturnType<typeof parseCertificateFile>;

  suiteSetup(() => {
    certs = parseCertificateFile(readText("self-signed.pem"));
  });

  test("returns exactly one cert", () => {
    assert.strictEqual(certs.length, 1);
  });

  test("common name is correct", () => {
    assert.strictEqual(certs[0].subject.commonName, "self-signed.example.com");
  });

  test("is self-signed", () => {
    assert.strictEqual(certs[0].isSelfSigned, true);
  });

  test("has sha1 fingerprint", () => {
    assert.ok(certs[0].fingerprints.sha1.length > 0);
    assert.ok(/^[A-F0-9:]+$/.test(certs[0].fingerprints.sha1));
  });

  test("has sha256 fingerprint", () => {
    assert.ok(certs[0].fingerprints.sha256.length > 0);
    assert.ok(/^[A-F0-9:]+$/.test(certs[0].fingerprints.sha256));
  });

  test("has subjectAltNames", () => {
    const dns = certs[0].subjectAltNames.filter(s => s.type === "dns");
    assert.ok(dns.length >= 1);
    assert.ok(dns.some(s => s.value === "self-signed.example.com"));
  });

  test("has IP SAN 127.0.0.1", () => {
    const ips = certs[0].subjectAltNames.filter(s => s.type === "ip");
    assert.ok(ips.some(s => s.value === "127.0.0.1"));
  });

  test("has keyUsage", () => {
    assert.ok(certs[0].keyUsage.length > 0);
  });

  test("extendedKeyUsage is an array", () => {
    assert.ok(Array.isArray(certs[0].extendedKeyUsage));
  });

  test("has RSA public key", () => {
    assert.ok(certs[0].publicKeyAlgorithm.includes("RSA"));
  });

  test("has 2048-bit key", () => {
    assert.strictEqual(certs[0].publicKeySize, 2048);
  });

  test("has RSA public exponent", () => {
    assert.strictEqual(certs[0].publicKeyExponent, "65537");
  });

  test("has valid notBefore/notAfter dates", () => {
    assert.ok(certs[0].validity.notBefore instanceof Date);
    assert.ok(certs[0].validity.notAfter instanceof Date);
    assert.ok(certs[0].validity.notAfter > certs[0].validity.notBefore);
  });

  test("serialNumber is colon-separated hex", () => {
    assert.ok(/^[A-F0-9:]+$/.test(certs[0].serialNumber));
  });

  test("pem field is populated", () => {
    assert.ok(certs[0].pem.includes("BEGIN CERTIFICATE"));
  });
});

suite("certParser — CA cert", () => {
  let certs: ReturnType<typeof parseCertificateFile>;

  suiteSetup(() => {
    certs = parseCertificateFile(readText("ca.pem"));
  });

  test("isCA is true", () => {
    assert.strictEqual(certs[0].isCA, true);
  });

  test("isSelfSigned is true", () => {
    assert.strictEqual(certs[0].isSelfSigned, true);
  });

  test("CN is Test CA", () => {
    assert.strictEqual(certs[0].subject.commonName, "Test CA");
  });

  test("organization is CertView Tests", () => {
    assert.deepStrictEqual(certs[0].subject.organization, ["CertView Tests"]);
  });
});

suite("certParser — chain PEM (2 certs)", () => {
  let certs: ReturnType<typeof parseCertificateFile>;

  suiteSetup(() => {
    certs = parseCertificateFile(readText("chain.pem"));
  });

  test("returns 2 certs", () => {
    assert.strictEqual(certs.length, 2);
  });

  test("first cert is leaf", () => {
    assert.strictEqual(certs[0].subject.commonName, "leaf.example.com");
  });

  test("second cert is CA", () => {
    assert.strictEqual(certs[1].subject.commonName, "Test CA");
  });

  test("leaf is not self-signed", () => {
    assert.strictEqual(certs[0].isSelfSigned, false);
  });

  test("leaf issuer matches CA subject", () => {
    assert.strictEqual(certs[0].issuer.commonName, certs[1].subject.commonName);
  });
});

suite("certParser — path length constraints", () => {
  test("flags pathLen violations on intermediate CAs", () => {
    const root = makeTestCert({ commonName: "Root CA", isCA: true, pathLenConstraint: 2 });
    const intermediate = makeTestCert({ commonName: "Intermediate pathLen0", isCA: true, pathLenConstraint: 0, issuer: root });
    const subCa = makeTestCert({ commonName: "Subordinate CA", isCA: true, pathLenConstraint: 0, issuer: intermediate });
    const leaf = makeTestCert({ commonName: "Leaf", isCA: false, issuer: subCa });
    const certs = parseCertificateFile([leaf, subCa, intermediate, root].map(item => item.pem).join("\n"));
    const parsedIntermediate = certs.find(cert => cert.subject.commonName === "Intermediate pathLen0");
    assert.ok(parsedIntermediate?.findings.some(finding => finding.severity === "error" && finding.message.includes("Path length constraint 0 is exceeded by 1 subordinate CA")));
  });
});

suite("certParser — signed certificate timestamps", () => {
  test("decodes a well-formed embedded SCT list", () => {
    const googleArgonLogId = Buffer.from("0E5794BCF3AEA93E331B2C9907B3F790DF9BC23D713225DD21A925AC61C54E21", "hex");
    const cert = makeCertWithSctExtension(makeSctList(makeSct({ logId: googleArgonLogId })));
    const parsed = parseCertificateFile(cert.pem)[0];
    const ext = parsed.extensions.find(item => item.oid === "1.3.6.1.4.1.11129.2.4.2");
    assert.ok(ext);
    assert.ok(ext.value.includes("SCT 1: v1"), ext.value);
    assert.ok(ext.value.includes("Google Argon2026h1"), ext.value);
    assert.ok(ext.value.includes("timestamp 2024-01-01T00:00:00.000Z"), ext.value);
    assert.ok(ext.value.includes("SHA-256 with ECDSA"), ext.value);
  });

  test("falls back to DER when SCT list length has trailing bytes", () => {
    const cert = makeCertWithSctExtension(Buffer.from([0x00, 0x00, 0xff]));
    const parsed = parseCertificateFile(cert.pem)[0];
    const ext = parsed.extensions.find(item => item.oid === "1.3.6.1.4.1.11129.2.4.2");
    assert.ok(ext?.value.startsWith("DER:"), ext?.value);
  });

  test("labels truncated SCT entries as malformed without throwing", () => {
    const cert = makeCertWithSctExtension(makeSctList(Buffer.alloc(10)));
    const parsed = parseCertificateFile(cert.pem)[0];
    const ext = parsed.extensions.find(item => item.oid === "1.3.6.1.4.1.11129.2.4.2");
    assert.ok(ext?.value.includes("SCT 1: malformed (10 bytes)"), ext?.value);
  });

  test("labels SCT timestamps outside JavaScript date range as malformed", () => {
    const cert = makeCertWithSctExtension(makeSctList(makeSct({ timestamp: BigInt(Number.MAX_SAFE_INTEGER) + 1n })));
    const parsed = parseCertificateFile(cert.pem)[0];
    const ext = parsed.extensions.find(item => item.oid === "1.3.6.1.4.1.11129.2.4.2");
    assert.ok(ext?.value.includes("malformed timestamp"), ext?.value);
  });

  test("labels impossible SCT extension length as malformed", () => {
    const sct = makeSct();
    sct.writeUInt16BE(0xffff, 41);
    const cert = makeCertWithSctExtension(makeSctList(sct));
    const parsed = parseCertificateFile(cert.pem)[0];
    const ext = parsed.extensions.find(item => item.oid === "1.3.6.1.4.1.11129.2.4.2");
    assert.ok(ext?.value.includes("malformed extensions"), ext?.value);
  });
});

suite("certParser — expired cert", () => {
  let certs: ReturnType<typeof parseCertificateFile>;

  suiteSetup(() => {
    certs = parseCertificateFile(readText("expired.pem"));
  });

  test("parses without throwing", () => {
    assert.ok(certs.length >= 1);
  });

  test("notAfter is in the past", () => {
    assert.ok(certs[0].validity.notAfter < new Date());
  });
});

suite("certParser — EC key cert", () => {
  let certs: ReturnType<typeof parseCertificateFile>;

  suiteSetup(() => {
    certs = parseCertificateFile(readText("ec-key.pem"));
  });

  test("parses without throwing", () => {
    assert.ok(certs.length === 1);
  });

  test("public key algorithm is EC", () => {
    assert.ok(certs[0].publicKeyAlgorithm.includes("EC"));
  });

  test("has no key size (EC uses curve name)", () => {
    assert.ok(certs[0].publicKeyAlgorithm.includes("P-256") || certs[0].publicKeySize === undefined);
  });

  test("resolves named curve aliases", () => {
    assert.strictEqual(certs[0].publicKeyCurve, "secp256r1 / prime256v1 / P-256");
  });
});

suite("certParser — DER input", () => {
  let certs: ReturnType<typeof parseCertificateFile>;

  suiteSetup(() => {
    certs = parseCertificateFile(readBin("self-signed.der"));
  });

  test("parses DER cert correctly", () => {
    assert.strictEqual(certs.length, 1);
    assert.strictEqual(certs[0].subject.commonName, "self-signed.example.com");
  });

  test("DER and PEM yield identical fingerprints", () => {
    const pemCerts = parseCertificateFile(readText("self-signed.pem"));
    assert.strictEqual(certs[0].fingerprints.sha256, pemCerts[0].fingerprints.sha256);
  });
});
