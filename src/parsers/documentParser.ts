import * as path from "path";
import { splitPemBlocks, isPemContent, isDerBuffer, detectFormat } from "./pemParser";
import { parseCertificateFile } from "./certParser";
import { extractCertsFromPkcs7 } from "./pkcs7Parser";
import { parseCsrFile } from "./csrParser";
import { parseKeyFile } from "./keyParser";
import { ParsedDocument } from "../models/parsedDocument";
import { assertWithinInputLimit } from "./limits";

/**
 * Parses raw file bytes into a ParsedDocument.
 * Pure function — no VSCode dependency, fully testable.
 */
export function parseDocument(raw: Uint8Array, filename: string): ParsedDocument {
  assertWithinInputLimit(raw.byteLength, "Input file");
  const ext = path.extname(filename).toLowerCase();

  try {
    if ([".key", ".pub", ".jwk"].includes(ext)) {
      return { type: "keys", items: parseKeyFile(raw, filename) };
    }

    // PKCS7 DER binary (.p7b/.p7c/.p7) — must check before generic DER path
    if ([".p7b", ".p7c", ".p7"].includes(ext) && isDerBuffer(raw)) {
      const pems = extractCertsFromPkcs7(raw);
      return { type: "certificates", items: pems.flatMap(pem => parseCertificateFile(pem)) };
    }

    if (ext !== ".der" && !isDerBuffer(raw)) {
      const text = Buffer.from(raw).toString("utf-8").replace(/^\uFEFF/, ""); // strip BOM

      if (!isPemContent(text)) {
        return parseDer(raw);
      }

      if (/-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----/.test(text) || /-----BEGIN (?:[A-Z ]+ )?PUBLIC KEY-----/.test(text)) {
        return { type: "keys", items: parseKeyFile(raw, filename) };
      }

      const format = detectFormat(text, ext);

      if (format === "X509 CRL") {
        return parseCrlPem(text);
      }

      if (format === "PKCS7") {
        const pems = extractCertsFromPkcs7(text);
        return { type: "certificates", items: pems.flatMap(pem => parseCertificateFile(pem)) };
      }

      if (format === "CERTIFICATE REQUEST" || format === "NEW CERTIFICATE REQUEST") {
        return { type: "csr", items: parseCsrFile(text) };
      }

      return { type: "certificates", items: parseCertificateFile(text) };
    }

    return parseDer(raw);

  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    const stack = err instanceof Error ? err.stack ?? "" : "";
    return {
      type: "error",
      message: `Failed to parse ${path.basename(filename)}`,
      detail: message + (stack ? `\n\n${stack.split("\n").slice(0, 5).join("\n")}` : ""),
    };
  }
}

function parseDer(raw: Uint8Array): ParsedDocument {
  assertWithinInputLimit(raw.byteLength, "DER file");
  return { type: "certificates", items: parseCertificateFile(raw) };
}

function parseCrlPem(text: string): ParsedDocument {
  const blocks = splitPemBlocks(text).filter(b => b.type === "X509 CRL");
  if (blocks.length === 0) {
    throw new Error("No X509 CRL block found.");
  }
  const der = Buffer.from(blocks[0].base64, "base64");
  return {
    type: "crl",
    issuer: extractCrlIssuer(der),
    thisUpdate: "See raw file",
    nextUpdate: "See raw file",
    revokedCount: -1,
    rawPem: blocks[0].pem,
  };
}

function extractCrlIssuer(der: Buffer): string {
  try {
    for (let i = 0; i < der.length - 2; i++) {
      const tag = der[i];
      if (tag !== 0x0c && tag !== 0x13) continue;
      const len = der[i + 1];
      if (len >= 0x80 || i + 2 + len > der.length) continue;
      const str = der.slice(i + 2, i + 2 + len).toString("utf8");
      if (str.length > 0 && /^[\x20-\x7e\u00a0-\ufffd]+$/.test(str)) return str;
    }
  } catch { /* ignore */ }
  return "Unknown";
}
