/**
 * documentParser tests — pipeline completo desde bytes hasta ParsedDocument.
 *
 * Estos tests simulan exactamente lo que el usuario experimenta:
 * "abro este archivo → ¿qué ve en el viewer?"
 *
 * Cada test corresponde a un escenario real de usuario, no a una unidad interna.
 */
import * as assert from "assert";
import * as fs from "fs";
import * as path from "path";
import { parseDocument } from "../../parsers/documentParser";
import { getCertificateStatus } from "../../models/certificate";

const FIXTURES = path.resolve(__dirname, "../fixtures/certs");
const load = (f: string) => fs.readFileSync(path.join(FIXTURES, f));

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

  test("PEM con bloque PRIVATE KEY en vez de CERTIFICATE → type=error", () => {
    const privateKey = Buffer.from(
      "-----BEGIN PRIVATE KEY-----\naGVsbG8=\n-----END PRIVATE KEY-----"
    );
    const doc = parseDocument(privateKey, "key.pem");
    assert.strictEqual(doc.type, "error");
  });
});

// ── Escenario: configuración warningDays afecta lo que ve el usuario ──────────

suite("parseDocument + getCertificateStatus — warningDays config", () => {
  test("cert que vence en 10 días: con warningDays=30 → expiring-soon", () => {
    const doc = parseDocument(load("expiring-soon.pem"), "expiring-soon.pem");
    assert.strictEqual(doc.type, "certificates");
    assert.strictEqual(getCertificateStatus(doc.items[0], 30), "expiring-soon");
  });

  test("cert que vence en 10 días: con warningDays=5 → valid", () => {
    const doc = parseDocument(load("expiring-soon.pem"), "expiring-soon.pem");
    assert.strictEqual(doc.type, "certificates");
    // Con threshold de 5 días, 10 días restantes es "valid"
    assert.strictEqual(getCertificateStatus(doc.items[0], 5), "valid");
  });

  test("cambiar warningDays cambia el status que ve el usuario", () => {
    const doc = parseDocument(load("expiring-soon.pem"), "expiring-soon.pem");
    assert.strictEqual(doc.type, "certificates");
    const cert = doc.items[0];
    // El mismo cert puede ser "valid" o "expiring-soon" según la config del usuario
    const withHighThreshold = getCertificateStatus(cert, 30);
    const withLowThreshold  = getCertificateStatus(cert, 5);
    assert.strictEqual(withHighThreshold, "expiring-soon");
    assert.strictEqual(withLowThreshold, "valid");
  });
});
