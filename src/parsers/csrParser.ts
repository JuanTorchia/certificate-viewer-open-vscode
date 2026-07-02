import * as crypto from "crypto";
import * as forge from "node-forge";
import { CertificateSubject } from "../models/certificate";
import { splitPemBlocks, base64ToDer } from "./pemParser";

export interface CsrInfo {
  pem: string;
  subject: CertificateSubject;
  publicKeyAlgorithm: string;
  publicKeyDisplay: string;
  publicKeySize?: number;
  publicKeyCurve?: string;
  publicKeyExponent?: string;
  publicKeyPem?: string;
  spkiFingerprints?: {
    sha1: string;
    sha256: string;
  };
  fingerprints: {
    sha1: string;
    sha256: string;
  };
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
  const forgeCsr = tryParseForgeCsr(pem);
  const keyInfo = extractForgePublicKey(forgeCsr) ?? extractCsrPublicKey(der);
  const subject = extractForgeSubject(forgeCsr) ?? extractCsrSubject(der);
  const requestedExtensions = extractRequestedExtensions(forgeCsr);

  return {
    pem,
    subject,
    publicKeyAlgorithm: keyInfo.algorithm,
    publicKeyDisplay: keyInfo.display,
    publicKeySize: keyInfo.keySize,
    publicKeyCurve: keyInfo.curve,
    publicKeyExponent: keyInfo.exponent,
    publicKeyPem: keyInfo.publicKeyPem,
    spkiFingerprints: keyInfo.spkiFingerprints,
    fingerprints: { sha1: fingerprint(Buffer.from(der), "sha1"), sha256: fingerprint(Buffer.from(der), "sha256") },
    subjectAltNames: extractCsrSANs(forgeCsr),
    requestedExtensions,
    signatureAlgorithm: detectCsrSignatureAlgorithm(der),
  };
}

function extractForgePublicKey(csr: forge.pki.CertificateSigningRequest | undefined): ReturnType<typeof extractCsrPublicKey> | undefined {
  if (!csr?.publicKey) return undefined;
  try {
    return keyInfoFromObject(crypto.createPublicKey(forge.pki.publicKeyToPem(csr.publicKey)));
  } catch {
    return undefined;
  }
}

function extractForgeSubject(csr: forge.pki.CertificateSigningRequest | undefined): CertificateSubject | undefined {
  if (!csr?.subject.attributes.length) return undefined;
  const subject: CertificateSubject = {};
  for (const attr of csr.subject.attributes) {
    const value = String(attr.value);
    switch (attr.type ?? attr.name) {
      case "2.5.4.3": subject.commonName = value; break;
      case "commonName": subject.commonName = value; break;
      case "2.5.4.10": (subject.organization ??= []).push(value); break;
      case "organizationName": (subject.organization ??= []).push(value); break;
      case "2.5.4.11": (subject.organizationalUnit ??= []).push(value); break;
      case "organizationalUnitName": (subject.organizationalUnit ??= []).push(value); break;
      case "2.5.4.6": (subject.country ??= []).push(value); break;
      case "countryName": (subject.country ??= []).push(value); break;
      case "2.5.4.8": (subject.state ??= []).push(value); break;
      case "stateOrProvinceName": (subject.state ??= []).push(value); break;
      case "2.5.4.7": (subject.locality ??= []).push(value); break;
      case "localityName": (subject.locality ??= []).push(value); break;
      case "1.2.840.113549.1.9.1": (subject.emailAddress ??= []).push(value); break;
      case "emailAddress": (subject.emailAddress ??= []).push(value); break;
    }
  }
  return subject;
}

function tryParseForgeCsr(pem: string): forge.pki.CertificateSigningRequest | undefined {
  try { return forge.pki.certificationRequestFromPem(pem); } catch { return undefined; }
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

function extractCsrPublicKey(der: Uint8Array): { algorithm: string; display: string; keySize?: number; curve?: string; exponent?: string; publicKeyPem?: string; spkiFingerprints?: { sha1: string; sha256: string } } {
  try {
    // Try importing as a public key via spki extraction
    // CertReqInfo: version, subject, subjectPublicKeyInfo
    const certReqInfo = getSequenceContent(der, 0);
    if (!certReqInfo) return { algorithm: "Unknown", display: "Unknown" };

    const versionHeaderSize = getHeaderSize(certReqInfo, 0);
    const versionLen = getElementLength(certReqInfo, 0);
    const subjectOffset = versionHeaderSize + versionLen;
    const subjectHeaderSize = getHeaderSize(certReqInfo, subjectOffset);
    const subjectLen = getElementLength(certReqInfo, subjectOffset);
    const spkiOffset = subjectOffset + subjectHeaderSize + subjectLen;

    const spkiBytes = getElement(certReqInfo, spkiOffset);
    if (!spkiBytes) return { algorithm: "Unknown", display: "Unknown" };

    return keyInfoFromObject(crypto.createPublicKey({ key: Buffer.from(spkiBytes), format: "der", type: "spki" }));
  } catch {
    return { algorithm: "Unknown", display: "Unknown" };
  }
}

function keyInfoFromObject(key: crypto.KeyObject): { algorithm: string; display: string; keySize?: number; curve?: string; exponent?: string; publicKeyPem?: string; spkiFingerprints?: { sha1: string; sha256: string } } {
  const type = (key.asymmetricKeyType ?? "unknown").toUpperCase();
  const details = key.asymmetricKeyDetails ?? {};
  const keySize = "modulusLength" in details ? (details.modulusLength as number) : undefined;
  const curve = "namedCurve" in details && typeof details.namedCurve === "string" ? friendlyCurveName(details.namedCurve) : undefined;
  const exponent = "publicExponent" in details && details.publicExponent !== undefined ? details.publicExponent.toString() : undefined;
  const exported = key.export({ type: "spki", format: "der" }) as Buffer;
  return {
    algorithm: type,
    display: publicKeyDisplay(type, keySize, curve),
    keySize,
    curve,
    exponent,
    publicKeyPem: key.export({ type: "spki", format: "pem" }).toString(),
    spkiFingerprints: { sha1: fingerprint(exported, "sha1"), sha256: fingerprint(exported, "sha256") },
  };
}

function publicKeyDisplay(type: string, keySize?: number, curve?: string): string {
  if (keySize) return `${type}-${keySize}`;
  if (curve) return `${type}-${shortCurveName(curve)}`;
  return type;
}

function shortCurveName(curve: string): string {
  const match = curve.match(/P-\d+/);
  return match ? match[0] : curve.split("/")[0].trim();
}

function extractCsrSANs(csr: forge.pki.CertificateSigningRequest | undefined): string[] {
  return csrExtensions(csr)
    .filter(ext => ext.name === "subjectAltName" || ext.id === "2.5.29.17")
    .flatMap(ext => ((ext as Record<string, unknown>).altNames as Array<{ type?: number; value?: unknown; ip?: string }> | undefined) ?? [])
    .map(name => {
      if (name.type === 2) return `DNS:${String(name.value ?? "")}`;
      if (name.type === 1) return `email:${String(name.value ?? "")}`;
      if (name.type === 6) return `URI:${String(name.value ?? "")}`;
      if (name.type === 7) return `IP:${name.ip ?? String(name.value ?? "")}`;
      return `type ${name.type ?? "unknown"}:${String(name.value ?? "")}`;
    })
    .filter(value => !value.endsWith(":"));
}

function extractRequestedExtensions(csr: forge.pki.CertificateSigningRequest | undefined): string[] {
  return csrExtensions(csr).map(ext => String(ext.name ?? ext.id ?? "unknown"));
}

function csrExtensions(csr: forge.pki.CertificateSigningRequest | undefined): Array<Record<string, unknown>> {
  const attr = csr?.getAttribute({ name: "extensionRequest" }) as { extensions?: Array<Record<string, unknown>> } | null;
  return attr?.extensions ?? [];
}

function friendlyCurveName(curve: string): string {
  const normalized = curve.toLowerCase();
  if (normalized === "prime256v1" || normalized === "secp256r1") return "secp256r1 / prime256v1 / P-256";
  if (normalized === "secp384r1") return "secp384r1 / P-384";
  if (normalized === "secp521r1") return "secp521r1 / P-521";
  return curve;
}

function fingerprint(bytes: Buffer, algorithm: "sha1" | "sha256"): string {
  return crypto.createHash(algorithm).update(bytes).digest("hex").toUpperCase().match(/.{2}/g)?.join(":") ?? "";
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
