import * as assert from "assert";
import * as fs from "fs";
import * as path from "path";
import { extractCertsFromPkcs7 } from "../../parsers/pkcs7Parser";
import { parseCertificateFile } from "../../parsers/certParser";

const FIXTURES = path.resolve(__dirname, "../fixtures/certs");
const readText = (f: string): string => fs.readFileSync(path.join(FIXTURES, f), "utf-8");
const readBin = (f: string): Buffer => fs.readFileSync(path.join(FIXTURES, f));

suite("pkcs7Parser — error cases", () => {
  test("returns empty array for plain text input", () => {
    assert.deepStrictEqual(extractCertsFromPkcs7("not pkcs7"), []);
  });

  test("returns empty array for empty string", () => {
    assert.deepStrictEqual(extractCertsFromPkcs7(""), []);
  });

  test("preserves original DER parser error as cause when wrapping PKCS#7 errors", () => {
    assert.throws(
      () => extractCertsFromPkcs7(Buffer.from([0x31, 0x00])),
      (error: unknown) => {
        assert.ok(error instanceof Error);
        assert.match(error.message, /Failed to parse PKCS#7 structure:/);
        assert.ok((error as Error & { cause?: unknown }).cause instanceof Error);
        return true;
      }
    );
  });
});

suite("pkcs7Parser — bundle.p7b (PEM-wrapped)", () => {
  let pems: string[];

  suiteSetup(() => {
    pems = extractCertsFromPkcs7(readText("bundle.p7b"));
  });

  test("extracts 2 PEM strings", () => {
    assert.strictEqual(pems.length, 2);
  });

  test("all items start with BEGIN CERTIFICATE", () => {
    for (const pem of pems) {
      assert.ok(pem.includes("BEGIN CERTIFICATE"), `Expected PEM header in: ${pem.slice(0, 60)}`);
    }
  });

  test("extracted PEMs are parseable by certParser", () => {
    for (const pem of pems) {
      const certs = parseCertificateFile(pem);
      assert.strictEqual(certs.length, 1);
      assert.ok(certs[0].subject.commonName);
    }
  });

  test("contains leaf.example.com", () => {
    const all = pems.flatMap(pem => parseCertificateFile(pem));
    assert.ok(all.some(c => c.subject.commonName === "leaf.example.com"));
  });

  test("contains Test CA", () => {
    const all = pems.flatMap(pem => parseCertificateFile(pem));
    assert.ok(all.some(c => c.subject.commonName === "Test CA"));
  });
});

suite("pkcs7Parser — bundle-der.p7b (DER binary)", () => {
  let pems: string[];

  suiteSetup(() => {
    pems = extractCertsFromPkcs7(readBin("bundle-der.p7b"));
  });

  test("extracts certs from DER PKCS7", () => {
    assert.ok(pems.length >= 1);
  });

  test("DER and PEM extraction yield same certs", () => {
    const fromPem = extractCertsFromPkcs7(readText("bundle.p7b"))
      .flatMap(p => parseCertificateFile(p))
      .map(c => c.fingerprints.sha256)
      .sort();
    const fromDer = pems
      .flatMap(p => parseCertificateFile(p))
      .map(c => c.fingerprints.sha256)
      .sort();
    assert.deepStrictEqual(fromDer, fromPem);
  });
});

suite("pkcs7Parser — fallback to CERTIFICATE blocks", () => {
  test("falls back when PKCS7 block has invalid DER but CERTIFICATE blocks present", () => {
    // Build a PEM with an invalid PKCS7 block followed by a real CERTIFICATE block
    const selfSignedPem = readText("self-signed.pem").replace(/\r\n/g, "\n").trim();
    const certBlock = selfSignedPem
      .split("-----BEGIN CERTIFICATE-----")[1]
      .split("-----END CERTIFICATE-----")[0]
      .trim();
    const mixed =
      "-----BEGIN PKCS7-----\naW52YWxpZA==\n-----END PKCS7-----\n" +
      `-----BEGIN CERTIFICATE-----\n${certBlock}\n-----END CERTIFICATE-----`;
    const result = extractCertsFromPkcs7(mixed);
    assert.strictEqual(result.length, 1);
  });
});
