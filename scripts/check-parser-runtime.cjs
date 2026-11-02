// Run with Node 18 after compilation and before packaging cleans out/.
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const forge = require("node-forge");
const { parseCertificateFile } = require("../out/parsers/certParser");
const { parseCsrFile } = require("../out/parsers/csrParser");
const { parsePkcs12, Pkcs12PasswordError } = require("../out/parsers/pkcs12Parser");

const fixtures = path.resolve(__dirname, "../out/test/fixtures/certs");
const certificate = fs.readFileSync(path.join(fixtures, "self-signed.pem"), "utf8");
assert.equal(parseCertificateFile(certificate).length, 1);

const pfx = fs.readFileSync(path.join(fixtures, "malformed/pkcs12/wrong-password.p12"));
assert.equal(parsePkcs12(pfx, "correct-password").length, 1);
assert.throws(() => parsePkcs12(pfx, "wrong-password"), Pkcs12PasswordError);

// Generate a disposable CSR in memory; never persist or print its private key.
const keys = crypto.generateKeyPairSync("rsa", { modulusLength: 1024 });
const request = forge.pki.createCertificationRequest();
request.publicKey = forge.pki.publicKeyFromPem(keys.publicKey.export({ type: "spki", format: "pem" }).toString());
request.setSubject([{ name: "commonName", value: "runtime-check.example.com" }]);
request.sign(forge.pki.privateKeyFromPem(keys.privateKey.export({ type: "pkcs1", format: "pem" }).toString()), forge.md.sha256.create());
assert.equal(parseCsrFile(forge.pki.certificationRequestToPem(request))[0].subject.commonName, "runtime-check.example.com");

assert.throws(() => parseCsrFile("-----BEGIN CERTIFICATE REQUEST-----\nAA==\n-----END CERTIFICATE-----"), /does not match BEGIN/);
assert.throws(() => forge.pkcs12.generateKey("synthetic", forge.util.createBuffer("salt"), 3, 0, 32), /iteration count/);
console.log(`Parser compatibility checks passed on ${process.version}: certificate, CSR, PFX and security rejection paths.`);
