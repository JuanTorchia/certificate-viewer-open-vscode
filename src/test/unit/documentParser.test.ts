/**
 * documentParser tests — pipeline completo desde bytes hasta ParsedDocument.
 *
 * Estos tests simulan exactamente lo que el usuario experimenta:
 * "abro este archivo → ¿qué ve en el viewer?"
 *
 * Cada test corresponde a un escenario real de usuario, no a una unidad interna.
 */
import * as assert from "assert";
import * as crypto from "crypto";
import * as fs from "fs";
import * as path from "path";
import { parseDocument } from "../../parsers/documentParser";
import { CertificateInfo, getCertificateStatus } from "../../models/certificate";

const FIXTURES = path.resolve(__dirname, "../fixtures/certs");
const CERT_FIXTURES = {
  "self-signed.pem": path.join(FIXTURES, "self-signed.pem"),
  "chain.pem": path.join(FIXTURES, "chain.pem"),
  "expired.pem": path.join(FIXTURES, "expired.pem"),
  "self-signed.cer": path.join(FIXTURES, "self-signed.cer"),
  "self-signed-der.cer": path.join(FIXTURES, "self-signed-der.cer"),
  "self-signed.der": path.join(FIXTURES, "self-signed.der"),
  "bundle.p7b": path.join(FIXTURES, "bundle.p7b"),
  "bundle-der.p7b": path.join(FIXTURES, "bundle-der.p7b"),
  "test.crl": path.join(FIXTURES, "test.crl"),
  "bom.pem": path.join(FIXTURES, "bom.pem"),
  "crlf.pem": path.join(FIXTURES, "crlf.pem"),
} as const;
const load = (f: keyof typeof CERT_FIXTURES): Buffer => fs.readFileSync(CERT_FIXTURES[f]);

// ── Escenario: usuario abre un .pem estándar ──────────────────────────────────

suite("parseDocument — usuario abre .pem", () => {
  test("devuelve type=certificates (no error)", () => {
    const doc = parseDocument(load("self-signed.pem"), "self-signed.pem");
    assert.strictEqual(doc.type, "certificates");
  });

  test("el CN del certificado es correcto", () => {
    const doc = parseDocument(load("self-signed.pem"), "self-signed.pem");
    assert.strictEqual(doc.type, "certificates");
    assert.strictEqual(doc.items[0].subject.commonName, "self-signed.example.com");
  });

  test("cadena de 2 certs muestra 2 items", () => {
    const doc = parseDocument(load("chain.pem"), "chain.pem");
    assert.strictEqual(doc.type, "certificates");
    assert.strictEqual(doc.items.length, 2);
  });

  test("cert vencido muestra notAfter en el pasado", () => {
    const doc = parseDocument(load("expired.pem"), "expired.pem");
    assert.strictEqual(doc.type, "certificates");
    assert.ok(doc.items[0].validity.notAfter < new Date());
  });
});

// ── Escenario: usuario abre un .cer (formato ambiguo) ────────────────────────

suite("parseDocument — usuario abre .cer", () => {
  test(".cer con contenido PEM → se parsea como certificado", () => {
    const doc = parseDocument(load("self-signed.cer"), "self-signed.cer");
    assert.strictEqual(doc.type, "certificates");
    assert.strictEqual(doc.items[0].subject.commonName, "self-signed.example.com");
  });

  test(".cer con contenido DER → se parsea como certificado (no error)", () => {
    // Caso real: Windows exporta certs como .cer en formato DER
    const doc = parseDocument(load("self-signed-der.cer"), "self-signed-der.cer");
    assert.strictEqual(doc.type, "certificates");
    assert.strictEqual(doc.items[0].subject.commonName, "self-signed.example.com");
  });

  test(".cer PEM y .cer DER dan el mismo fingerprint", () => {
    const fromPem = parseDocument(load("self-signed.cer"), "self-signed.cer");
    const fromDer = parseDocument(load("self-signed-der.cer"), "self-signed-der.cer");
    assert.strictEqual(fromPem.type, "certificates");
    assert.strictEqual(fromDer.type, "certificates");
    assert.strictEqual(
      fromPem.items[0].fingerprints.sha256,
      fromDer.items[0].fingerprints.sha256
    );
  });
});

// ── Escenario: usuario abre un .der ──────────────────────────────────────────

suite("parseDocument — usuario abre .der", () => {
  test("archivo DER devuelve el certificado correcto", () => {
    const doc = parseDocument(load("self-signed.der"), "self-signed.der");
    assert.strictEqual(doc.type, "certificates");
    assert.strictEqual(doc.items[0].subject.commonName, "self-signed.example.com");
  });

  test("DER y PEM del mismo cert tienen fingerprints idénticos", () => {
    const fromDer = parseDocument(load("self-signed.der"), "self-signed.der");
    const fromPem = parseDocument(load("self-signed.pem"), "self-signed.pem");
    assert.strictEqual(fromDer.type, "certificates");
    assert.strictEqual(fromPem.type, "certificates");
    assert.strictEqual(
      fromDer.items[0].fingerprints.sha256,
      fromPem.items[0].fingerprints.sha256
    );
  });
});

// ── Escenario: usuario abre un .p7b (bundle PKCS7) ───────────────────────────

suite("parseDocument — usuario abre .p7b", () => {
  test("bundle PEM devuelve 2 certificados", () => {
    const doc = parseDocument(load("bundle.p7b"), "bundle.p7b");
    assert.strictEqual(doc.type, "certificates");
    assert.strictEqual(doc.items.length, 2);
  });

  test("bundle DER devuelve 2 certificados", () => {
    const doc = parseDocument(load("bundle-der.p7b"), "bundle-der.p7b");
    assert.strictEqual(doc.type, "certificates");
    assert.strictEqual(doc.items.length, 2);
  });

  test("bundle contiene leaf.example.com y Test CA", () => {
    const doc = parseDocument(load("bundle.p7b"), "bundle.p7b");
    assert.strictEqual(doc.type, "certificates");
    const cns = doc.items.map(c => c.subject.commonName);
    assert.ok(cns.includes("leaf.example.com"));
    assert.ok(cns.includes("Test CA"));
  });
});

// ── Escenario: usuario abre un .crl ──────────────────────────────────────────

suite("parseDocument — usuario abre .crl", () => {
  test("CRL devuelve type=crl (no certificates)", () => {
    const doc = parseDocument(load("test.crl"), "test.crl");
    assert.strictEqual(doc.type, "crl");
  });

  test("CRL muestra el issuer del CA que la firmó", () => {
    const doc = parseDocument(load("test.crl"), "test.crl");
    assert.strictEqual(doc.type, "crl");
    // extractCrlIssuer debe encontrar "Test CA" o "CertView Tests"
    assert.notStrictEqual(doc.issuer, "Unknown", "Issuer no fue extraído — extractCrlIssuer falló");
    assert.ok(doc.issuer.length > 0);
  });

  test("CRL muestra fechas, conteo, algoritmo y fingerprints", () => {
    const doc = parseDocument(load("test.crl"), "test.crl");
    assert.strictEqual(doc.type, "crl");
    assert.notStrictEqual(doc.thisUpdate, "See raw file");
    assert.notStrictEqual(doc.nextUpdate, "See raw file");
    assert.ok(doc.revokedCount >= 0);
    assert.ok(doc.signatureAlgorithm);
    assert.match(doc.fingerprints?.sha256 ?? "", /^[A-F0-9:]+$/);
  });
});

// ── Escenario: usuario abre un archivo con BOM (editores Windows) ─────────────

suite("parseDocument — usuario abre PEM con BOM (UTF-8)", () => {
  test("PEM con BOM se parsea sin error", () => {
    const doc = parseDocument(load("bom.pem"), "bom.pem");
    assert.notStrictEqual(doc.type, "error",
      `Falló con BOM: ${doc.type === "error" ? doc.message : ""}`);
    assert.strictEqual(doc.type, "certificates");
  });

  test("PEM con BOM devuelve el mismo CN que sin BOM", () => {
    const withBom = parseDocument(load("bom.pem"), "bom.pem");
    const withoutBom = parseDocument(load("self-signed.pem"), "self-signed.pem");
    assert.strictEqual(withBom.type, "certificates");
    assert.strictEqual(withoutBom.type, "certificates");
    assert.strictEqual(
      withBom.items[0].subject.commonName,
      withoutBom.items[0].subject.commonName
    );
  });
});

// ── Escenario: usuario abre PEM con CRLF (Windows line endings) ──────────────

suite("parseDocument — usuario abre PEM con CRLF", () => {
  test("PEM con CRLF se parsea sin error", () => {
    const doc = parseDocument(load("crlf.pem"), "crlf.pem");
    assert.notStrictEqual(doc.type, "error",
      `Falló con CRLF: ${doc.type === "error" ? doc.message : ""}`);
    assert.strictEqual(doc.type, "certificates");
  });

  test("PEM con CRLF devuelve el mismo fingerprint que LF", () => {
    const crlf = parseDocument(load("crlf.pem"), "crlf.pem");
    const lf   = parseDocument(load("self-signed.pem"), "self-signed.pem");
    assert.strictEqual(crlf.type, "certificates");
    assert.strictEqual(lf.type, "certificates");
    assert.strictEqual(
      crlf.items[0].fingerprints.sha256,
      lf.items[0].fingerprints.sha256
    );
  });
});

// ── Escenario: usuario arrastra un archivo equivocado ─────────────────────────

suite("parseDocument — usuario abre archivo incorrecto", () => {
  test("archivo de texto plano → type=error (no crash)", () => {
    const garbage = Buffer.from("this is not a certificate at all");
    const doc = parseDocument(garbage, "garbage.txt");
    assert.strictEqual(doc.type, "error");
  });

  test("mensaje de error menciona el nombre del archivo", () => {
    const garbage = Buffer.from("this is not a certificate at all");
    const doc = parseDocument(garbage, "my-cert.pem");
    assert.strictEqual(doc.type, "error");
    assert.ok(doc.message.includes("my-cert.pem"),
      `Expected filename in error message, got: "${doc.message}"`);
  });

  test("buffer vacío → type=error (no crash)", () => {
    const doc = parseDocument(new Uint8Array(0), "empty.pem");
    assert.strictEqual(doc.type, "error");
  });

  test("invalid PEM private key block → type=error", () => {
    const privateKey = Buffer.from(
      "-----BEGIN PRIVATE KEY-----\naGVsbG8=\n-----END PRIVATE KEY-----"
    );
    const doc = parseDocument(privateKey, "key.pem");
    assert.strictEqual(doc.type, "error");
  });
});

suite("parseDocument — usuario abre llaves", () => {
  test("mixed PEM certificate and private key returns certificate and key bundle", () => {
    const { privateKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
    const keyPem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();
    const doc = parseDocument(Buffer.concat([load("self-signed.pem"), Buffer.from("\n" + keyPem)]), "mixed.pem");
    assert.strictEqual(doc.type, "bundle");
    assert.strictEqual(doc.certificates[0].subject.commonName, "self-signed.example.com");
    assert.strictEqual(doc.keys[0].kind, "private");
    assert.ok(doc.keys[0].spkiFingerprints?.sha256);
  });

  test("mixed PEM preserves certificates when a key block is malformed", () => {
    const badKey = "-----BEGIN PRIVATE KEY-----\naGVsbG8=\n-----END PRIVATE KEY-----";
    const doc = parseDocument(Buffer.concat([load("self-signed.pem"), Buffer.from("\n" + badKey)]), "mixed.pem");
    assert.strictEqual(doc.type, "bundle");
    assert.strictEqual(doc.certificates[0].subject.commonName, "self-signed.example.com");
    assert.strictEqual(doc.keys[0].algorithm, "Unsupported private key");
    assert.ok(doc.keys[0].note);
  });

  test("mixed PEM bundle is detected even with .key extension", () => {
    const { privateKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
    const keyPem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();
    const doc = parseDocument(Buffer.concat([load("self-signed.pem"), Buffer.from("\n" + keyPem)]), "mixed.key");
    assert.strictEqual(doc.type, "bundle");
    assert.strictEqual(doc.certificates[0].subject.commonName, "self-signed.example.com");
    assert.strictEqual(doc.keys[0].kind, "private");
  });

  test("JWK public key is rendered as a key document", () => {
    const { publicKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
    const jwk = publicKey.export({ format: "jwk" });
    const doc = parseDocument(Buffer.from(JSON.stringify(jwk)), "key.jwk");
    assert.strictEqual(doc.type, "keys");
    assert.strictEqual(doc.items[0].algorithm, "RSA");
    assert.strictEqual(doc.items[0].format, "JWK");
    assert.ok(doc.items[0].spkiFingerprints?.sha256);
  });

  test("ML-DSA public key is rendered when runtime supports it", function () {
    let publicKey: crypto.KeyObject;
    try {
      const generateKeyPairSync = crypto.generateKeyPairSync as (type: string) => crypto.KeyPairKeyObjectResult;
      publicKey = generateKeyPairSync("ml-dsa-65").publicKey;
    } catch {
      this.skip();
      return;
    }
    const pem = publicKey.export({ type: "spki", format: "pem" }).toString();
    const doc = parseDocument(Buffer.from(pem), "mldsa.pub");
    assert.strictEqual(doc.type, "keys");
    assert.strictEqual(doc.items[0].algorithm, "ML-DSA-65");
  });

  test("encrypted private keys are detected without password prompts", () => {
    const { privateKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
    const encrypted = privateKey.export({
      type: "pkcs8",
      format: "pem",
      cipher: "aes-256-cbc",
      passphrase: "secret",
    });
    const doc = parseDocument(Buffer.from(encrypted), "encrypted.key");
    assert.strictEqual(doc.type, "keys");
    assert.strictEqual(doc.items[0].kind, "private");
    assert.strictEqual(doc.items[0].encrypted, true);
    assert.ok(doc.items[0].note?.includes("does not prompt"));
    assert.strictEqual(doc.items[0].publicKeyPem, undefined);
  });

  test("DER SPKI public key is rendered as a key document", () => {
    const { publicKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
    const der = publicKey.export({ type: "spki", format: "der" });
    const doc = parseDocument(der, "public.pub");
    assert.strictEqual(doc.type, "keys");
    assert.strictEqual(doc.items[0].kind, "public");
    assert.strictEqual(doc.items[0].algorithm, "RSA");
    assert.strictEqual(doc.items[0].format, "DER");
    assert.match(doc.items[0].spkiFingerprints?.sha256 ?? "", /^[A-F0-9:]+$/);
  });

  test("DER SPKI public key with .der extension falls back to key parsing", () => {
    const { publicKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
    const der = publicKey.export({ type: "spki", format: "der" });
    const doc = parseDocument(der, "public.der");
    assert.strictEqual(doc.type, "keys");
    assert.strictEqual(doc.items[0].kind, "public");
    assert.strictEqual(doc.items[0].format, "DER");
  });

  test("DER PKCS#8 private key is rendered as a key document", () => {
    const { privateKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
    const der = privateKey.export({ type: "pkcs8", format: "der" });
    const doc = parseDocument(der, "private.key");
    assert.strictEqual(doc.type, "keys");
    assert.strictEqual(doc.items[0].kind, "private");
    assert.strictEqual(doc.items[0].algorithm, "RSA");
    assert.strictEqual(doc.items[0].format, "DER");
  });

  test("DER PKCS#8 private key with .der extension falls back to key parsing", () => {
    const { privateKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
    const der = privateKey.export({ type: "pkcs8", format: "der" });
    const doc = parseDocument(der, "private.der");
    assert.strictEqual(doc.type, "keys");
    assert.strictEqual(doc.items[0].kind, "private");
    assert.strictEqual(doc.items[0].format, "DER");
  });

  test("DER encrypted PKCS#8 private key is detected without decryption", () => {
    const { privateKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
    const der = privateKey.export({ type: "pkcs8", format: "der", cipher: "aes-256-cbc", passphrase: "secret" });
    const doc = parseDocument(der, "encrypted.key");
    assert.strictEqual(doc.type, "keys");
    assert.strictEqual(doc.items[0].encrypted, true);
    assert.strictEqual(doc.items[0].publicKeyPem, undefined);
  });
});

// ── Escenario: configuración warningDays afecta lo que ve el usuario ──────────

suite("parseDocument + getCertificateStatus — warningDays config", () => {
  function nearExpiryCert(): CertificateInfo {
    const doc = parseDocument(load("self-signed.pem"), "self-signed.pem");
    assert.strictEqual(doc.type, "certificates");
    const now = new Date();
    return {
      ...doc.items[0],
      validity: {
        notBefore: new Date(now.getTime() - 86400000),
        notAfter: new Date(now.getTime() + 10 * 86400000),
      },
    };
  }

  test("cert que vence en 10 días: con warningDays=30 → expiring-soon", () => {
    assert.strictEqual(getCertificateStatus(nearExpiryCert(), 30), "expiring-soon");
  });

  test("cert que vence en 10 días: con warningDays=5 → valid", () => {
    // Con threshold de 5 días, 10 días restantes es "valid"
    assert.strictEqual(getCertificateStatus(nearExpiryCert(), 5), "valid");
  });

  test("cambiar warningDays cambia el status que ve el usuario", () => {
    const cert = nearExpiryCert();
    // El mismo cert puede ser "valid" o "expiring-soon" según la config del usuario
    const withHighThreshold = getCertificateStatus(cert, 30);
    const withLowThreshold  = getCertificateStatus(cert, 5);
    assert.strictEqual(withHighThreshold, "expiring-soon");
    assert.strictEqual(withLowThreshold, "valid");
  });
});
