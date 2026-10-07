import * as assert from "assert";
import * as fs from "fs";
import * as path from "path";
import {
  splitPemBlocks,
  isPemContent,
  isDerBuffer,
  derToPem,
  detectFormat,
} from "../../parsers/pemParser";

const FIXTURES = path.resolve(__dirname, "../fixtures/certs");
const read = (f: string): Buffer => fs.readFileSync(path.join(FIXTURES, f));
const readText = (f: string): string => fs.readFileSync(path.join(FIXTURES, f), "utf-8");

suite("pemParser — splitPemBlocks", () => {
  test("extracts single CERTIFICATE block", () => {
    const pem = "-----BEGIN CERTIFICATE-----\naGVsbG8=\n-----END CERTIFICATE-----";
    const blocks = splitPemBlocks(pem);
    assert.strictEqual(blocks.length, 1);
    assert.strictEqual(blocks[0].type, "CERTIFICATE");
    assert.strictEqual(blocks[0].base64, "aGVsbG8=");
    assert.ok(blocks[0].pem.includes("BEGIN CERTIFICATE"));
  });

  test("extracts multiple CERTIFICATE blocks", () => {
    const pem = [
      "-----BEGIN CERTIFICATE-----\naGVsbG8=\n-----END CERTIFICATE-----",
      "-----BEGIN CERTIFICATE-----\nd29ybGQ=\n-----END CERTIFICATE-----",
    ].join("\n");
    const blocks = splitPemBlocks(pem);
    assert.strictEqual(blocks.length, 2);
    assert.strictEqual(blocks[1].base64, "d29ybGQ=");
  });

  test("handles CRLF line endings", () => {
    const pem = "-----BEGIN CERTIFICATE-----\r\naGVsbG8=\r\n-----END CERTIFICATE-----";
    const blocks = splitPemBlocks(pem);
    assert.strictEqual(blocks.length, 1);
  });

  test("extracts X509 CRL block", () => {
    const crl = readText("test.crl");
    const blocks = splitPemBlocks(crl);
    assert.ok(blocks.length >= 1);
    assert.strictEqual(blocks[0].type, "X509 CRL");
  });

  test("returns empty array for non-PEM input", () => {
    assert.deepStrictEqual(splitPemBlocks("not pem at all"), []);
  });

  test("ignores content outside blocks", () => {
    const pem = "some header text\n-----BEGIN CERTIFICATE-----\naGVsbG8=\n-----END CERTIFICATE-----\nsome footer";
    assert.strictEqual(splitPemBlocks(pem).length, 1);
  });

  test("chain.pem yields 2 CERTIFICATE blocks", () => {
    const blocks = splitPemBlocks(readText("chain.pem")).filter(b => b.type === "CERTIFICATE");
    assert.strictEqual(blocks.length, 2);
  });

  test("parses line-heavy PEM input without quadratic parsing time", function () {
    this.timeout(5_000);
    const pem = [
      "-----BEGIN CERTIFICATE-----",
      ...Array(20_000).fill("A"),
      "-----END CERTIFICATE-----",
    ].join("\n");
    assert.ok(Buffer.byteLength(pem, "utf8") < 256 * 1024);

    const startedAt = process.hrtime.bigint();
    const blocks = splitPemBlocks(pem);
    const elapsedMs = Number(process.hrtime.bigint() - startedAt) / 1_000_000;

    assert.strictEqual(blocks.length, 1);
    assert.ok(elapsedMs < 500, `Expected parsing below 500 ms, took ${elapsedMs.toFixed(1)} ms`);
  });
});

suite("pemParser — isPemContent", () => {
  test("returns true for valid PEM", () => {
    assert.ok(isPemContent("-----BEGIN CERTIFICATE-----\nfoo\n-----END CERTIFICATE-----"));
  });

  test("returns false for plain text", () => {
    assert.ok(!isPemContent("not pem content"));
  });

  test("returns false for empty string", () => {
    assert.ok(!isPemContent(""));
  });

  test("returns true when explanatory text precedes the BEGIN boundary", () => {
    assert.ok(isPemContent("Certificate:\n    Data:\n-----BEGIN CERTIFICATE-----\nfoo\n-----END CERTIFICATE-----"));
  });

  test("returns true for CRLF content with text before BEGIN", () => {
    assert.ok(isPemContent("Bag Attributes\r\n    friendlyName: x\r\n-----BEGIN CERTIFICATE-----\r\nfoo\r\n-----END CERTIFICATE-----\r\n"));
  });

  test("returns false when BEGIN appears only inside a line", () => {
    assert.ok(!isPemContent("note: -----BEGIN CERTIFICATE----- is the header"));
  });

  test("returns true for self-signed fixture", () => {
    assert.ok(isPemContent(readText("self-signed.pem")));
  });

  test("returns false for DER bytes converted to string", () => {
    const der = read("self-signed.der");
    const asStr = Buffer.from(der).toString("utf-8");
    assert.ok(!isPemContent(asStr));
  });
});

suite("pemParser — isDerBuffer", () => {
  test("returns true for DER fixture (starts with 0x30)", () => {
    assert.ok(isDerBuffer(read("self-signed.der")));
  });

  test("returns false for PEM bytes", () => {
    const pemBytes = new TextEncoder().encode(readText("self-signed.pem"));
    assert.ok(!isDerBuffer(pemBytes));
  });

  test("returns false for empty buffer", () => {
    assert.ok(!isDerBuffer(new Uint8Array(0)));
  });

  test("returns false for single byte", () => {
    assert.ok(!isDerBuffer(new Uint8Array([0x30])));
  });
});

suite("pemParser — derToPem", () => {
  test("round-trips DER → PEM → parseable", () => {
    const der = read("self-signed.der");
    const pem = derToPem(der);
    assert.ok(pem.startsWith("-----BEGIN CERTIFICATE-----"));
    assert.ok(pem.endsWith("-----END CERTIFICATE-----"));
    const blocks = splitPemBlocks(pem);
    assert.strictEqual(blocks.length, 1);
  });
});

suite("pemParser — detectFormat", () => {
  test("detects CERTIFICATE for .pem", () => {
    assert.strictEqual(detectFormat(readText("self-signed.pem"), ".pem"), "CERTIFICATE");
  });

  test("detects DER for binary buffer", () => {
    assert.strictEqual(detectFormat(read("self-signed.der"), ".der"), "DER");
  });

  test("detects X509 CRL for CRL file", () => {
    assert.strictEqual(detectFormat(readText("test.crl"), ".crl"), "X509 CRL");
  });

  test("detects PKCS7 for p7b file", () => {
    assert.strictEqual(detectFormat(readText("bundle.p7b"), ".p7b"), "PKCS7");
  });
});
