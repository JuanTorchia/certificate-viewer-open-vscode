import * as assert from "assert";
import { spawnSync } from "child_process";
import { parseCsrFile } from "../../parsers/csrParser";
import { splitPemBlocks } from "../../parsers/pemParser";

suite("node-forge — runtime security regressions", () => {
  test("bounds malformed PEM decoding in a killable child process", () => {
    runIsolated(`
      const newline = String.fromCharCode(10);
      const pem = '-----BEGIN CERTIFICATE REQUEST-----' + newline +
        newline.repeat(200000) + '-----END CERTIFICATE-----';
      assert.throws(() => forge.pem.decode(pem));
    `);
  });

  test("bounds long encapsulated-header decoding without a colon", () => {
    runIsolated(`
      const newline = String.fromCharCode(10);
      const pem = ['-----BEGIN CERTIFICATE-----', 'A'.repeat(100000),
        '', 'AA==', '-----END CERTIFICATE-----'].join(newline);
      try { forge.pem.decode(pem); } catch (error) {
        assert.ok(error instanceof Error);
      }
    `);
  });

  test("rejects constant-key PKCS#12 derivation for non-positive iterations", () => {
    runIsolated(`
      for (const iterations of [0, -1]) {
        assert.throws(() => forge.pkcs12.generateKey('untrusted-password',
          forge.util.createBuffer('synthetic-salt'), 3, iterations, 32,
          forge.md.sha256.create()), /iteration count/);
      }
    `);
  });

  test("rejects mismatched CSR boundaries before parsing untrusted content", () => {
    const pem = "-----BEGIN CERTIFICATE REQUEST-----\nAA==\n-----END CERTIFICATE-----";
    assert.throws(() => splitPemBlocks(pem), /does not match BEGIN/);
    assert.throws(() => parseCsrFile(pem), /does not match BEGIN/);
  });
});

function runIsolated(body: string): void {
  const script = `
    const assert = require('assert');
    const forge = require(${JSON.stringify(require.resolve("node-forge"))});
    ${body}
  `;
  const result = spawnSync(process.execPath, ["-e", script], {
    encoding: "utf8",
    timeout: 3_000,
    maxBuffer: 16 * 1024,
  });
  assert.ifError(result.error);
  assert.strictEqual(result.signal, null, `Parser was terminated: ${result.signal}`);
  assert.strictEqual(result.status, 0, result.stderr);
}
