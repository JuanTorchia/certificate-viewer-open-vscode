import * as crypto from "crypto";
import { CertificateSubject } from "../models/certificate";
import { splitPemBlocks, base64ToDer } from "./pemParser";

export interface CsrInfo {
  pem: string;
  subject: CertificateSubject;
  publicKeyAlgorithm: string;
  publicKeySize?: number;
  subjectAltNames: string[];
  requestedExtensions: string[];
  signatureAlgorithm: string;
}

/**
 * Parses one or more CSR blocks from PEM content.
 */
export function parseCsrFile(content: string): CsrInfo[] {
  const blocks = splitPemBlocks(content).filter(
    b => b.type === "CERTIFICATE REQUEST" || b.type === "NEW CERTIFICATE REQUEST"
  );

  if (blocks.length === 0) {
    throw new Error("No CERTIFICATE REQUEST blocks found.");
  }

  return blocks.map(b => parseSingleCsr(b.pem, b.base64));
}

function parseSingleCsr(pem: string, base64: string): CsrInfo {
  // Node.js doesn't expose a CSR API, so we parse the ASN.1 structure minimally.
  // The CSR (PKCS#10) DER structure:
  //   SEQUENCE {
  //     CertificationRequestInfo {
  //       INTEGER version
  //       SEQUENCE subject (RDNSequence)
  //       SubjectPublicKeyInfo
  //       [0] IMPLICIT Attributes
  //     }
  //     AlgorithmIdentifier
  //     BIT STRING signature
  //   }
  //
  // We extract the public key by creating a temporary self-signed cert context.
  // For the subject we use a creative workaround: sign a cert request using
  // the raw public key from the CSR.

  const der = base64ToDer(base64);
  const subject = extractCsrSubject(der);
  const { algorithm, keySize } = extractCsrPublicKey(der);

  return {
    pem,
    subject,
    publicKeyAlgorithm: algorithm,
    publicKeySize: keySize,
    subjectAltNames: extractCsrSANs(der),
    requestedExtensions: [],
    signatureAlgorithm: detectCsrSignatureAlgorithm(der),
  };
}

/**
 * Extracts the subject RDN from CSR DER bytes.
 * Walks the ASN.1 manually: SEQUENCE > SEQUENCE(CertReqInfo) > SEQUENCE(subject).
 */
function extractCsrSubject(der: Uint8Array): CertificateSubject {
  try {
    // CertificationRequestInfo starts at the inner SEQUENCE
    // der[0] = 0x30 (outer SEQUENCE)
    const certReqInfo = getSequenceContent(der, 0);
    if (!certReqInfo) return {};

    // Skip version INTEGER (first element)
    const versionHeaderSize = getHeaderSize(certReqInfo, 0);
    const versionLen = getElementLength(certReqInfo, 0);
    const subjectOffset = versionHeaderSize + versionLen;

    const subjectBytes = getElement(certReqInfo, subjectOffset);
    if (!subjectBytes) return {};

    return parseRdn(subjectBytes);
  } catch {
    return {};
  }
}

function extractCsrPublicKey(der: Uint8Array): { algorithm: string; keySize?: number } {
  try {
    // Try importing as a public key via spki extraction
    // CertReqInfo: version, subject, subjectPublicKeyInfo
    const certReqInfo = getSequenceContent(der, 0);
    if (!certReqInfo) return { algorithm: "Unknown" };

    const versionHeaderSize = getHeaderSize(certReqInfo, 0);
    const versionLen = getElementLength(certReqInfo, 0);
    const subjectOffset = versionHeaderSize + versionLen;
    const subjectHeaderSize = getHeaderSize(certReqInfo, subjectOffset);
    const subjectLen = getElementLength(certReqInfo, subjectOffset);
    const spkiOffset = subjectOffset + subjectHeaderSize + subjectLen;

    const spkiBytes = getElement(certReqInfo, spkiOffset);
    if (!spkiBytes) return { algorithm: "Unknown" };

    // Wrap SPKI in proper DER for import
    const spkiDer = buildDerSequence(spkiBytes);
    const key = crypto.createPublicKey({ key: Buffer.from(spkiDer), format: "der", type: "spki" });
    const type = (key.asymmetricKeyType ?? "unknown").toUpperCase();
    const details = key.asymmetricKeyDetails ?? {};
    const keySize = "modulusLength" in details ? (details.modulusLength as number) : undefined;
    const curve = "namedCurve" in details ? ` (${details.namedCurve})` : "";
    return { algorithm: type + curve, keySize };
  } catch {
    return { algorithm: "Unknown" };
  }
}

function extractCsrSANs(_der: Uint8Array): string[] {
  // Full SAN extraction from CSR attributes requires deep ASN.1 parsing.
  // Deferred to a future implementation.
  return [];
}

function detectCsrSignatureAlgorithm(der: Uint8Array): string {
  // The algorithm OID is in the AlgorithmIdentifier at the end of the outer SEQUENCE.
  // Common OIDs:
  const OID_MAP: Record<string, string> = {
    "2a864886f70d01010b": "SHA256withRSA",
    "2a864886f70d01010d": "SHA512withRSA",
    "2a864886f70d010105": "SHA1withRSA",
    "2a8648ce3d040302":   "SHA256withECDSA",
    "2a8648ce3d040303":   "SHA512withECDSA",
  };

  try {
    // Scan for known OID bytes
    const hex = Buffer.from(der).toString("hex");
    for (const [oidHex, name] of Object.entries(OID_MAP)) {
      if (hex.includes(oidHex)) return name;
    }
  } catch { /* ignore */ }
  return "Unknown";
}

// ── Minimal ASN.1 helpers ─────────────────────────────────────────────────────

function getElementLength(buf: Uint8Array, offset: number): number {
  if (offset >= buf.length) return 0;
  const lenByte = buf[offset + 1];
  if (lenByte < 0x80) return lenByte;
  const numBytes = lenByte & 0x7f;
  let len = 0;
  for (let i = 0; i < numBytes; i++) {
    len = (len << 8) | buf[offset + 2 + i];
  }
  return len;
}

function getHeaderSize(buf: Uint8Array, offset: number): number {
  const lenByte = buf[offset + 1];
  if (lenByte < 0x80) return 2;
  return 2 + (lenByte & 0x7f);
}

function getSequenceContent(buf: Uint8Array, offset: number): Uint8Array | null {
  if (buf[offset] !== 0x30) return null;
  const headerSize = getHeaderSize(buf, offset);
  const len = getElementLength(buf, offset);
  return buf.slice(offset + headerSize, offset + headerSize + len);
}

function getElement(buf: Uint8Array, offset: number): Uint8Array | null {
  if (offset >= buf.length) return null;
  const headerSize = getHeaderSize(buf, offset);
  const len = getElementLength(buf, offset);
  return buf.slice(offset, offset + headerSize + len);
}

function buildDerSequence(content: Uint8Array): Uint8Array {
  const lenBytes = encodeDerLength(content.length);
  const result = new Uint8Array(1 + lenBytes.length + content.length);
  result[0] = 0x30;
  result.set(lenBytes, 1);
  result.set(content, 1 + lenBytes.length);
  return result;
}

function encodeDerLength(len: number): Uint8Array {
  if (len < 0x80) return new Uint8Array([len]);
  if (len < 0x100) return new Uint8Array([0x81, len]);
  return new Uint8Array([0x82, (len >> 8) & 0xff, len & 0xff]);
}

// OID string → RDN attribute name
const RDN_ATTR: Record<string, string> = {
  "2.5.4.3":              "CN",
  "2.5.4.10":             "O",
  "2.5.4.11":             "OU",
  "2.5.4.6":              "C",
  "2.5.4.8":              "ST",
  "2.5.4.7":              "L",
  "1.2.840.113549.1.9.1": "EMAIL",
};

/**
 * Walks an RDNSequence TLV (tag 0x30 included) and extracts subject attributes.
 * Structure: SEQUENCE → SET[] → SEQUENCE(AttributeTypeAndValue) → OID + value
 */
function parseRdn(subjectBytes: Uint8Array): CertificateSubject {
  const result: CertificateSubject = {};
  try {
    const seq = readCsrTlv(subjectBytes, 0);
    if (seq.tag !== 0x30) return result;

    let pos = seq.contentStart;
    while (pos < seq.nextOffset) {
      const set = readCsrTlv(subjectBytes, pos);
      pos = set.nextOffset;
      if (set.tag !== 0x31) continue;

      let setPos = set.contentStart;
      while (setPos < set.nextOffset) {
        const atv = readCsrTlv(subjectBytes, setPos);
        setPos = atv.nextOffset;
        if (atv.tag !== 0x30) continue;

        const oidTlv = readCsrTlv(subjectBytes, atv.contentStart);
        if (oidTlv.tag !== 0x06) continue;
        const oidStr = decodeCsrOid(subjectBytes.slice(oidTlv.contentStart, oidTlv.contentStart + oidTlv.contentLength));

        const valueTlv = readCsrTlv(subjectBytes, oidTlv.nextOffset);
        // UTF8String(0x0c), PrintableString(0x13), IA5String(0x16), TeletexString(0x14), BMPString(0x1e)
        const value = Buffer.from(subjectBytes.slice(valueTlv.contentStart, valueTlv.contentStart + valueTlv.contentLength)).toString("utf8");

        const attr = RDN_ATTR[oidStr];
        if (attr && value) setRdnValue(result, attr, value);
      }
    }
  } catch { /* ignore malformed input */ }
  return result;
}

function setRdnValue(subject: CertificateSubject, attr: string, value: string): void {
  switch (attr) {
    case "CN":    subject.commonName = value; break;
    case "O":     (subject.organization ??= []).push(value); break;
    case "OU":    (subject.organizationalUnit ??= []).push(value); break;
    case "C":     (subject.country ??= []).push(value); break;
    case "ST":    (subject.state ??= []).push(value); break;
    case "L":     (subject.locality ??= []).push(value); break;
    case "EMAIL": (subject.emailAddress ??= []).push(value); break;
  }
}

// ── DER helpers for csrParser ──────────────────────────────────────────────────

function readCsrTlv(
  buf: Uint8Array,
  offset: number
): { tag: number; contentStart: number; contentLength: number; nextOffset: number } {
  if (offset >= buf.length) throw new Error(`CSR TLV offset ${offset} out of bounds`);
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

function decodeCsrOid(bytes: Uint8Array): string {
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
