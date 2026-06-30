import * as path from "path";
import * as crypto from "crypto";
import * as forge from "node-forge";
import { splitPemBlocks, isPemContent, isDerBuffer, detectFormat } from "./pemParser";
import { parseCertificateFile } from "./certParser";
import { extractCertsFromPkcs7 } from "./pkcs7Parser";
import { parseCsrFile } from "./csrParser";
import { parseKeyFile, parseKeyPemBlocks } from "./keyParser";
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
      const text = Buffer.from(raw).toString("utf-8").replace(/^\uFEFF/, "");
      if (isPemContent(text)) {
        const blocks = splitPemBlocks(text);
        const hasCertificates = blocks.some(block => block.type === "CERTIFICATE");
        const hasKeys = blocks.some(isKeyPemBlock);
        if (hasCertificates && hasKeys) {
          return { type: "bundle", certificates: parseCertificateFile(text), keys: parseKeyPemBlocks(text) };
        }
      }
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
        return parseDer(raw, filename);
      }

      const blocks = splitPemBlocks(text);
      const hasCertificates = blocks.some(block => block.type === "CERTIFICATE");
      const hasKeys = blocks.some(isKeyPemBlock);
      if (hasCertificates && hasKeys) {
        return { type: "bundle", certificates: parseCertificateFile(text), keys: parseKeyPemBlocks(text) };
      }

      if (hasCertificates) {
        return { type: "certificates", items: parseCertificateFile(text) };
      }

      if (hasKeys) {
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

    return parseDer(raw, filename);

  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return {
      type: "error",
      message: `Failed to parse ${path.basename(filename)}`,
      detail: message,
    };
  }
}

function isKeyPemBlock(block: { type: string }): boolean {
  return /(?:^| )PRIVATE KEY$/.test(block.type) || /(?:^| )PUBLIC KEY$/.test(block.type);
}

function parseDer(raw: Uint8Array, filename: string): ParsedDocument {
  assertWithinInputLimit(raw.byteLength, "DER file");
  try {
    return { type: "certificates", items: parseCertificateFile(raw) };
  } catch (certificateError) {
    try {
      return { type: "keys", items: parseKeyFile(raw, filename) };
    } catch (keyError) {
      const certMessage = certificateError instanceof Error ? certificateError.message : String(certificateError);
      const keyMessage = keyError instanceof Error ? keyError.message : String(keyError);
      throw new Error(`DER data is neither a supported certificate nor key. Certificate parse failed: ${certMessage}. Key parse failed: ${keyMessage}`);
    }
  }
}

function parseCrlPem(text: string): ParsedDocument {
  const blocks = splitPemBlocks(text).filter(b => b.type === "X509 CRL");
  if (blocks.length === 0) {
    throw new Error("No X509 CRL block found.");
  }
  const der = Buffer.from(blocks[0].base64, "base64");
  const parsed = parseCrlDer(der);
  return {
    type: "crl",
    issuer: parsed.issuer,
    thisUpdate: parsed.thisUpdate,
    nextUpdate: parsed.nextUpdate,
    revokedCount: parsed.revokedCount,
    signatureAlgorithm: parsed.signatureAlgorithm,
    crlNumber: parsed.crlNumber,
    authorityKeyIdentifier: parsed.authorityKeyIdentifier,
    fingerprints: { sha1: fingerprint(der, "sha1"), sha256: fingerprint(der, "sha256") },
    rawPem: blocks[0].pem,
  };
}

function parseCrlDer(der: Buffer): { issuer: string; thisUpdate: string; nextUpdate: string; revokedCount: number; signatureAlgorithm?: string; crlNumber?: string; authorityKeyIdentifier?: string } {
  try {
    const root = forge.asn1.fromDer(der.toString("binary"));
    const top = Array.isArray(root.value) ? root.value as forge.asn1.Asn1[] : [];
    const tbs = top[0];
    if (!tbs || !Array.isArray(tbs.value)) throw new Error("missing tbsCertList");
    const nodes = tbs.value as forge.asn1.Asn1[];
    let index = nodes[0]?.type === forge.asn1.Type.INTEGER ? 1 : 0;
    const sigAlg = algorithmName(oidFromNode((nodes[index++]?.value as forge.asn1.Asn1[] | undefined)?.[0]));
    const issuerNode = nodes[index++];
    const thisUpdateNode = nodes[index++];
    const nextUpdateNode = nodes[index]?.type === forge.asn1.Type.UTCTIME || nodes[index]?.type === forge.asn1.Type.GENERALIZEDTIME ? nodes[index++] : undefined;
    const revokedNode = nodes[index]?.type === forge.asn1.Type.SEQUENCE ? nodes[index++] : undefined;
    const extWrapper = nodes.find(node => node.tagClass === forge.asn1.Class.CONTEXT_SPECIFIC && node.type === 0);
    const extensions = parseCrlExtensions(extWrapper);
    return {
      issuer: issuerFromAsn1(issuerNode),
      thisUpdate: timeFromAsn1(thisUpdateNode),
      nextUpdate: nextUpdateNode ? timeFromAsn1(nextUpdateNode) : "Not present",
      revokedCount: Array.isArray(revokedNode?.value) ? revokedNode.value.length : 0,
      signatureAlgorithm: sigAlg,
      crlNumber: extensions.crlNumber,
      authorityKeyIdentifier: extensions.authorityKeyIdentifier,
    };
  } catch { /* ignore */ }
  return { issuer: "Unknown", thisUpdate: "Unknown", nextUpdate: "Unknown", revokedCount: -1 };
}

function parseCrlExtensions(wrapper: forge.asn1.Asn1 | undefined): { crlNumber?: string; authorityKeyIdentifier?: string } {
  const result: { crlNumber?: string; authorityKeyIdentifier?: string } = {};
  const seq = Array.isArray(wrapper?.value) ? wrapper.value[0] as forge.asn1.Asn1 : undefined;
  if (!seq || !Array.isArray(seq.value)) return result;
  for (const ext of seq.value as forge.asn1.Asn1[]) {
    if (!Array.isArray(ext.value)) continue;
    const values = ext.value as forge.asn1.Asn1[];
    const oid = oidFromNode(values[0]);
    const valueNode = values.find(node => node.type === forge.asn1.Type.OCTETSTRING);
    if (!oid || typeof valueNode?.value !== "string") continue;
    if (oid === "2.5.29.20") result.crlNumber = parseCrlNumber(valueNode.value);
    if (oid === "2.5.29.35") result.authorityKeyIdentifier = parseAuthorityKeyIdentifier(valueNode.value);
  }
  return result;
}

function issuerFromAsn1(node: forge.asn1.Asn1 | undefined): string {
  if (!node) return "Unknown";
  try {
    const attrs = (forge.pki as unknown as { RDNAttributesAsArray: (rdn: forge.asn1.Asn1) => Array<{ shortName?: string; name?: string; value: unknown }> }).RDNAttributesAsArray(node);
    return attrs.map(attr => `${attr.shortName ?? attr.name ?? "OID"}=${String(attr.value)}`).join(", ") || "Unknown";
  } catch {
    return "Unknown";
  }
}

function timeFromAsn1(node: forge.asn1.Asn1 | undefined): string {
  if (!node || typeof node.value !== "string") return "Unknown";
  try {
    const date = node.type === forge.asn1.Type.UTCTIME ? forge.asn1.utcTimeToDate(node.value) : forge.asn1.generalizedTimeToDate(node.value);
    return date.toISOString();
  } catch {
    return String(node.value);
  }
}

function oidFromNode(node: forge.asn1.Asn1 | undefined): string | undefined {
  return typeof node?.value === "string" ? forge.asn1.derToOid(node.value) : undefined;
}

function algorithmName(oid: string | undefined): string | undefined {
  const names: Record<string, string> = {
    "1.2.840.113549.1.1.11": "sha256WithRSAEncryption",
    "1.2.840.113549.1.1.12": "sha384WithRSAEncryption",
    "1.2.840.113549.1.1.13": "sha512WithRSAEncryption",
    "1.2.840.10045.4.3.2": "ecdsa-with-SHA256",
    "1.3.101.112": "Ed25519",
  };
  return oid ? names[oid] ?? oid : undefined;
}

function parseCrlNumber(value: string): string {
  try {
    const node = forge.asn1.fromDer(value);
    if (typeof node.value !== "string") return "Unknown";
    const hex = Buffer.from(node.value, "binary").toString("hex").toUpperCase() || "00";
    const number = BigInt(`0x${hex}`).toString(10);
    return `${number} (0x${hex})`;
  } catch {
    return "Unknown";
  }
}

function parseAuthorityKeyIdentifier(value: string): string {
  try {
    const node = forge.asn1.fromDer(value);
    const values = Array.isArray(node.value) ? node.value as forge.asn1.Asn1[] : [];
    const keyIdentifier = values.find(item => item.tagClass === forge.asn1.Class.CONTEXT_SPECIFIC && item.type === 0);
    if (typeof keyIdentifier?.value === "string") return formatColonHex(Buffer.from(keyIdentifier.value, "binary"));
  } catch { /* ignore */ }
  return formatColonHex(Buffer.from(value, "binary"));
}

function formatColonHex(bytes: Buffer): string {
  return bytes.toString("hex").toUpperCase().match(/.{2}/g)?.join(":") ?? "";
}

function fingerprint(bytes: Buffer, algorithm: "sha1" | "sha256"): string {
  return crypto.createHash(algorithm).update(bytes).digest("hex").toUpperCase().match(/.{2}/g)?.join(":") ?? "";
}
