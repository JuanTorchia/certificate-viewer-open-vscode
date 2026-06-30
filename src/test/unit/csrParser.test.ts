import * as assert from "assert";
import * as forge from "node-forge";
import { parseCsrFile } from "../../parsers/csrParser";

suite("csrParser", () => {
  test("extracts SANs, requested extensions, SPKI fingerprints, and RSA exponent", () => {
    const keys = forge.pki.rsa.generateKeyPair(2048);
    const csr = forge.pki.createCertificationRequest();
    csr.publicKey = keys.publicKey;
    csr.setSubject([{ name: "commonName", value: "csr.example.com" }]);
    csr.setAttributes([{ name: "extensionRequest", extensions: [{ name: "subjectAltName", altNames: [{ type: 2, value: "csr.example.com" }, { type: 1, value: "admin@example.com" }] }] }]);
    csr.sign(keys.privateKey, forge.md.sha256.create());

    const parsed = parseCsrFile(forge.pki.certificationRequestToPem(csr))[0];

    assert.strictEqual(parsed.subject.commonName, "csr.example.com");
    assert.ok(parsed.publicKeyAlgorithm.includes("RSA"));
    assert.strictEqual(parsed.publicKeySize, 2048);
    assert.strictEqual(parsed.publicKeyExponent, "65537");
    assert.ok(parsed.publicKeyPem?.includes("BEGIN PUBLIC KEY"));
    assert.match(parsed.spkiFingerprints?.sha256 ?? "", /^[A-F0-9:]+$/);
    assert.ok(parsed.subjectAltNames.includes("DNS:csr.example.com"));
    assert.ok(parsed.subjectAltNames.includes("email:admin@example.com"));
    assert.ok(parsed.requestedExtensions.includes("subjectAltName"));
  });
});
