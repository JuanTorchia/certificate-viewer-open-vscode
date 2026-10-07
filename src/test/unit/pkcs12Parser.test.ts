import * as assert from "assert";
import * as fs from "fs";
import * as path from "path";
import * as forge from "node-forge";
import { parsePkcs12, Pkcs12PasswordError } from "../../parsers/pkcs12Parser";

const FIXTURES = path.resolve(__dirname, "../fixtures/certs/malformed/pkcs12");
const PKCS12_FIXTURES = {
  "empty.p12": path.join(FIXTURES, "empty.p12"),
  "non-pkcs12-der.p12": path.join(FIXTURES, "non-pkcs12-der.p12"),
  "truncated.p12": path.join(FIXTURES, "truncated.p12"),
  "wrong-password.p12": path.join(FIXTURES, "wrong-password.p12"),
} as const;
const readBin = (f: keyof typeof PKCS12_FIXTURES): Buffer => fs.readFileSync(PKCS12_FIXTURES[f]);

suite("pkcs12Parser — corrupt input handling", () => {
  test("distinguishes wrong passwords from generic parser failures", () => {
    assert.throws(
      () => parsePkcs12(readBin("wrong-password.p12"), "incorrect-password"),
      (error: unknown) => error instanceof Pkcs12PasswordError
    );
  });

  test("extracts certificates from the password-protected fixture with the right password", () => {
    const certs = parsePkcs12(readBin("wrong-password.p12"), "correct-password");
    assert.strictEqual(certs.length, 1);
    assert.strictEqual(certs[0].subject.commonName, "pkcs12-test.example.com");
  });

  test("throws controlled parser errors for corrupt PKCS#12 fixtures", () => {
    for (const fixture of ["empty.p12", "truncated.p12", "non-pkcs12-der.p12"] as const) {
      assert.throws(
        () => parsePkcs12(readBin(fixture), ""),
        (error: unknown) => {
          assert.ok(error instanceof Error);
          assert.ok(error.message.length > 0, fixture);
          assert.ok(!(error instanceof Pkcs12PasswordError), fixture);
          return true;
        },
        fixture
      );
    }
  });

  test("rejects an enormous MAC iteration count before invoking node-forge PKCS#12 parsing", function (): void {
    this.timeout(2_000);
    const pfx = minimalPfxWithMacIterations("\x00" + "\xff".repeat(128));
    const originalParser = forge.pkcs12.pkcs12FromAsn1;
    let forgeParserCalled = false;
    forge.pkcs12.pkcs12FromAsn1 = (): never => {
      forgeParserCalled = true;
      throw new Error("node-forge PKCS#12 parser must not be called");
    };

    try {
      const startedAt = process.hrtime.bigint();
      assert.throws(
        () => parsePkcs12(pfx, ""),
        (error: unknown) => {
          assert.ok(error instanceof Error);
          assert.match(error.message, /PKCS#12 MAC iteration count exceeds the maximum/);
          return true;
        }
      );
      const elapsedMs = Number(process.hrtime.bigint() - startedAt) / 1_000_000;
      assert.ok(elapsedMs < 500, `Expected rejection below 500 ms, took ${elapsedMs.toFixed(1)} ms`);
      assert.strictEqual(forgeParserCalled, false);
    } finally {
      forge.pkcs12.pkcs12FromAsn1 = originalParser;
    }
  });

  test("rejects an enormous visible PBES2 iteration count before invoking node-forge PKCS#12 parsing", function (): void {
    this.timeout(2_000);
    const pfx = minimalPfxWithVisibleAlgorithm(pbes2Algorithm("\x00" + "\xff".repeat(128)));
    const originalParser = forge.pkcs12.pkcs12FromAsn1;
    let forgeParserCalled = false;
    forge.pkcs12.pkcs12FromAsn1 = (): never => {
      forgeParserCalled = true;
      throw new Error("node-forge PKCS#12 parser must not be called");
    };

    try {
      const startedAt = process.hrtime.bigint();
      assert.throws(
        () => parsePkcs12(pfx, ""),
        (error: unknown) => {
          assert.ok(error instanceof Error);
          assert.match(error.message, /PKCS#12 PBES2 iteration count exceeds the maximum/);
          return true;
        }
      );
      const elapsedMs = Number(process.hrtime.bigint() - startedAt) / 1_000_000;
      assert.ok(elapsedMs < 500, `Expected rejection below 500 ms, took ${elapsedMs.toFixed(1)} ms`);
      assert.strictEqual(forgeParserCalled, false);
    } finally {
      forge.pkcs12.pkcs12FromAsn1 = originalParser;
    }
  });

  test("rejects an enormous visible PKCS#12 PBE iteration count before invoking node-forge PKCS#12 parsing", function (): void {
    this.timeout(2_000);
    const pfx = minimalPfxWithVisibleAlgorithm(pkcs12PbeAlgorithm("\x00" + "\xff".repeat(128)));
    const originalParser = forge.pkcs12.pkcs12FromAsn1;
    let forgeParserCalled = false;
    forge.pkcs12.pkcs12FromAsn1 = (): never => {
      forgeParserCalled = true;
      throw new Error("node-forge PKCS#12 parser must not be called");
    };

    try {
      const startedAt = process.hrtime.bigint();
      assert.throws(
        () => parsePkcs12(pfx, ""),
        (error: unknown) => {
          assert.ok(error instanceof Error);
          assert.match(error.message, /PKCS#12 PBE iteration count exceeds the maximum/);
          return true;
        }
      );
      const elapsedMs = Number(process.hrtime.bigint() - startedAt) / 1_000_000;
      assert.ok(elapsedMs < 500, `Expected rejection below 500 ms, took ${elapsedMs.toFixed(1)} ms`);
      assert.strictEqual(forgeParserCalled, false);
    } finally {
      forge.pkcs12.pkcs12FromAsn1 = originalParser;
    }
  });
});

function minimalPfxWithMacIterations(iterations: string): Buffer {
  const asn1 = forge.asn1;
  const emptyAuthenticatedSafe = asn1.toDer(
    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [])
  ).getBytes();
  const pfx = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.INTEGER, false, "\x03"),
    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
      asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false, asn1.oidToDer(forge.pki.oids.data).getBytes()),
      asn1.create(asn1.Class.CONTEXT_SPECIFIC, 0, true, [
        asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OCTETSTRING, false, emptyAuthenticatedSafe),
      ]),
    ]),
    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
      asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
        asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
          asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false, asn1.oidToDer(forge.pki.oids.sha256).getBytes()),
        ]),
        asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OCTETSTRING, false, "\x00".repeat(32)),
      ]),
      asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OCTETSTRING, false, "12345678"),
      asn1.create(asn1.Class.UNIVERSAL, asn1.Type.INTEGER, false, iterations),
    ]),
  ]);
  return Buffer.from(asn1.toDer(pfx).getBytes(), "binary");
}

function minimalPfxWithVisibleAlgorithm(algorithm: forge.asn1.Asn1): Buffer {
  const asn1 = forge.asn1;
  const safeContents = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [algorithm]);
  const authenticatedSafe = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
    dataContentInfo(asn1.toDer(safeContents).getBytes()),
  ]);
  const pfx = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.INTEGER, false, "\x03"),
    dataContentInfo(asn1.toDer(authenticatedSafe).getBytes()),
  ]);
  return Buffer.from(asn1.toDer(pfx).getBytes(), "binary");
}

function dataContentInfo(payload: string): forge.asn1.Asn1 {
  const asn1 = forge.asn1;
  return asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false, asn1.oidToDer(forge.pki.oids.data).getBytes()),
    asn1.create(asn1.Class.CONTEXT_SPECIFIC, 0, true, [
      asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OCTETSTRING, false, payload),
    ]),
  ]);
}

function pbes2Algorithm(iterations: string): forge.asn1.Asn1 {
  const asn1 = forge.asn1;
  return asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false, asn1.oidToDer("1.2.840.113549.1.5.13").getBytes()),
    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
      asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
        asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false, asn1.oidToDer("1.2.840.113549.1.5.12").getBytes()),
        asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
          asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OCTETSTRING, false, "12345678"),
          asn1.create(asn1.Class.UNIVERSAL, asn1.Type.INTEGER, false, iterations),
        ]),
      ]),
      asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
        asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false, asn1.oidToDer("2.16.840.1.101.3.4.1.42").getBytes()),
        asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OCTETSTRING, false, "\x00".repeat(16)),
      ]),
    ]),
  ]);
}

function pkcs12PbeAlgorithm(iterations: string): forge.asn1.Asn1 {
  const asn1 = forge.asn1;
  return asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false, asn1.oidToDer("1.2.840.113549.1.12.1.3").getBytes()),
    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
      asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OCTETSTRING, false, "12345678"),
      asn1.create(asn1.Class.UNIVERSAL, asn1.Type.INTEGER, false, iterations),
    ]),
  ]);
}
