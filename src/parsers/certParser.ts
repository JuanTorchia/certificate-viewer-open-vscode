import * as crypto from "crypto";
import {
  CertificateInfo,
  CertificateSubject,
  SubjectAlternativeName,
  CertificateExtension,
} from "../models/certificate";
import { derToPem, splitPemBlocks } from "./pemParser";

const EXTENDED_KEY_USAGE_OID: Record<string, string> = {
  "1.3.6.1.5.5.7.3.1": "TLS Web Server Authentication",
  "1.3.6.1.5.5.7.3.2": "TLS Web Client Authentication",
  "1.3.6.1.5.5.7.3.3": "Code Signing",
  "1.3.6.1.5.5.7.3.4": "Email Protection",
  "1.3.6.1.5.5.7.3.8": "Time Stamping",
  "1.3.6.1.5.5.7.3.9": "OCSP Signing",
};

/**
 * Parses a PEM or DER certificate file.
 * Handles multi-cert PEM chains (returns one entry per cert).
 */
export function parseCertificateFile(content: string | Uint8Array): CertificateInfo[] {
  let pems: string[];

  if (typeof content === "string") {
    const blocks = splitPemBlocks(content).filter(b => b.type === "CERTIFICATE");
    if (blocks.length === 0) {
      throw new Error("No CERTIFICATE blocks found in the file.");
    }
    pems = blocks.map(b => b.pem);
  } else {
    pems = [derToPem(content)];
  }

  return pems.map((pem, idx) => {
    try {
      return parseSinglePem(pem);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      throw new Error(`Certificate #${idx + 1}: ${msg}`);
    }
  });
}

function parseSinglePem(pem: string): CertificateInfo {
  const x509 = new crypto.X509Certificate(pem);

  const subject = parseX509Name(x509.subject);
  const issuer = parseX509Name(x509.issuer);

  // keyUsage is string[] in Node.js ≥15.6
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const x509any = x509 as any;
  const keyUsage = normalizeKeyUsage(x509any.keyUsage);
  const extendedKeyUsage = parseExtendedKeyUsage(x509any.extendedKeyUsage ?? []);
  const { algorithm, keySize } = getPublicKeyInfo(x509.publicKey);

  return {
    pem,
    version: 3,
    serialNumber: formatSerial(x509.serialNumber),
    subject,
    issuer,
    validity: {
      notBefore: new Date(x509.validFrom),
      notAfter: new Date(x509.validTo),
    },
    subjectAltNames: parseSubjectAltNames(x509.subjectAltName ?? ""),
    keyUsage,
    extendedKeyUsage,
    extensions: buildExtensions(x509),
    signatureAlgorithm: extractSignatureAlgorithm(x509),
    publicKeyAlgorithm: algorithm,
    publicKeySize: keySize,
    fingerprints: {
      sha1: x509.fingerprint.toUpperCase(),
      sha256: x509.fingerprint256.toUpperCase(),
    },
    isSelfSigned: x509.subject === x509.issuer,
    isCA: safeCA(x509),
  };
}

// Node.js ≥18 returns string[], ≤17 returned a comma-separated string.
// Handle both to be safe.
function normalizeKeyUsage(raw: string[] | string | undefined): string[] {
  if (!raw) return [];
  if (Array.isArray(raw)) return raw;
  return raw.split(/,\s*/).map(s => s.trim()).filter(Boolean);
}

function parseExtendedKeyUsage(ekus: string[]): string[] {
  return ekus.map(oid => EXTENDED_KEY_USAGE_OID[oid] ?? oid);
}

function parseX509Name(nameStr: string): CertificateSubject {
  const result: CertificateSubject = {};
  if (!nameStr) return result;

  // Node formats as "CN=foo\nO=bar" or "CN=foo, O=bar"
  const parts = nameStr.replace(/\r?\n/g, "\n").split(/[\n,]/).map(s => s.trim()).filter(Boolean);

  for (const part of parts) {
    const eq = part.indexOf("=");
    if (eq < 0) continue;
    const key = part.slice(0, eq).trim().toUpperCase();
    const value = part.slice(eq + 1).trim();

    switch (key) {
      case "CN":            result.commonName = value; break;
      case "O":             (result.organization ??= []).push(value); break;
      case "OU":            (result.organizationalUnit ??= []).push(value); break;
      case "C":             (result.country ??= []).push(value); break;
      case "ST": case "S":  (result.state ??= []).push(value); break;
      case "L":             (result.locality ??= []).push(value); break;
      case "EMAILADDRESS": case "E": (result.emailAddress ??= []).push(value); break;
    }
  }
  return result;
}

function parseSubjectAltNames(altNameStr: string): SubjectAlternativeName[] {
  if (!altNameStr) return [];
  const results: SubjectAlternativeName[] = [];

  for (const entry of altNameStr.split(/,\s*/)) {
    const colon = entry.indexOf(":");
    if (colon < 0) continue;
    const type = entry.slice(0, colon).trim().toLowerCase();
    const value = entry.slice(colon + 1).trim();

    if (type === "dns")        results.push({ type: "dns", value });
    else if (type === "ip" || type === "ip address") results.push({ type: "ip", value });
    else if (type === "email") results.push({ type: "email", value });
    else if (type === "uri")   results.push({ type: "uri", value });
  }
  return results;
}

function getPublicKeyInfo(key: crypto.KeyObject): { algorithm: string; keySize?: number } {
  try {
    const type = (key.asymmetricKeyType ?? "unknown").toUpperCase();
    const details = key.asymmetricKeyDetails ?? {};
    const keySize = "modulusLength" in details ? (details.modulusLength as number) : undefined;
    const curve = "namedCurve" in details ? ` (${details.namedCurve})` : "";
    return { algorithm: type + curve, keySize };
  } catch {
    return { algorithm: "unknown" };
  }
}

const SIG_ALG_OID: Record<string, string> = {
  "1.2.840.113549.1.1.4":  "MD5withRSA",
  "1.2.840.113549.1.1.5":  "SHA1withRSA",
  "1.2.840.113549.1.1.11": "SHA256withRSA",
  "1.2.840.113549.1.1.12": "SHA384withRSA",
  "1.2.840.113549.1.1.13": "SHA512withRSA",
  "1.2.840.10045.4.3.2":   "SHA256withECDSA",
  "1.2.840.10045.4.3.3":   "SHA384withECDSA",
  "1.2.840.10045.4.3.4":   "SHA512withECDSA",
  "1.3.101.112":            "Ed25519",
  "1.3.101.113":            "Ed448",
};

function extractSignatureAlgorithm(x509: crypto.X509Certificate): string {
  try {
    // x509.raw is the full DER-encoded certificate (available since Node 15.6)
    // Certificate ::= SEQUENCE { TBSCertificate, AlgorithmIdentifier, BIT STRING }
    const der = x509.raw;
    const cert = readCertTlv(der, 0);
    const tbs  = readCertTlv(der, cert.contentStart);
    const alg  = readCertTlv(der, tbs.nextOffset);
    if (alg.tag !== 0x30) return "Unknown";
    const oidTlv = readCertTlv(der, alg.contentStart);
    if (oidTlv.tag !== 0x06) return "Unknown";
    const oidStr = decodeCertOid(der.slice(oidTlv.contentStart, oidTlv.contentStart + oidTlv.contentLength));
    return SIG_ALG_OID[oidStr] ?? oidStr;
  } catch {
    return "Unknown";
  }
}

function buildExtensions(x509: crypto.X509Certificate): CertificateExtension[] {
  const exts: CertificateExtension[] = [];

  if (x509.subjectAltName) {
    exts.push({ oid: "2.5.29.17", name: "Subject Alternative Name", critical: false, value: x509.subjectAltName });
  }

  const ku = normalizeKeyUsage(x509.keyUsage);
  if (ku.length) {
    exts.push({ oid: "2.5.29.15", name: "Key Usage", critical: true, value: ku.join(", ") });
  }

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const eku: string[] = (x509 as any).extendedKeyUsage ?? [];
  if (eku.length) {
    exts.push({ oid: "2.5.29.37", name: "Extended Key Usage", critical: false, value: eku.join(", ") });
  }

  if (x509.infoAccess) {
    exts.push({ oid: "1.3.6.1.5.5.7.1.1", name: "Authority Information Access", critical: false, value: x509.infoAccess });
  }

  return exts;
}

function safeCA(x509: crypto.X509Certificate): boolean {
  try { return x509.ca; } catch { return false; }
}

function formatSerial(serial: string): string {
  // Node returns hex string, format as colon-separated pairs
  return (serial.length % 2 === 0 ? serial : "0" + serial)
    .match(/.{1,2}/g)!
    .join(":")
    .toUpperCase();
}

// ── DER helpers for certParser ─────────────────────────────────────────────────

function readCertTlv(
  buf: Buffer,
  offset: number
): { tag: number; contentStart: number; contentLength: number; nextOffset: number } {
  const tag = buf[offset];
  const first = buf[offset + 1];
  let headerBytes: number;
  let length: number;
  if (first < 0x80) {
    headerBytes = 2;
    length = first;
  } else {
    const numBytes = first & 0x7f;
    if (numBytes === 0 || numBytes > 4) throw new Error(`Unsupported DER length at offset ${offset}`);
    headerBytes = 2 + numBytes;
    length = 0;
    for (let i = 0; i < numBytes; i++) {
      length = (length << 8) | buf[offset + 2 + i];
    }
  }
  const contentStart = offset + headerBytes;
  return { tag, contentStart, contentLength: length, nextOffset: contentStart + length };
}

function decodeCertOid(bytes: Buffer): string {
  if (bytes.length === 0) return "";
  const parts: number[] = [Math.floor(bytes[0] / 40), bytes[0] % 40];
  let value = 0;
  for (let i = 1; i < bytes.length; i++) {
    value = (value << 7) | (bytes[i] & 0x7f);
    if ((bytes[i] & 0x80) === 0) {
      parts.push(value);
      value = 0;
    }
  }
  return parts.join(".");
}
