import * as assert from "assert";
import * as fs from "fs";
import * as path from "path";
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
});
