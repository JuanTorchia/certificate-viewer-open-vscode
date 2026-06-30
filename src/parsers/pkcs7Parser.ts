import { derToPem, splitPemBlocks } from "./pemParser";
import { assertWithinInputLimit, MAX_CERTIFICATES, MAX_PEM_BLOCK_CHARS } from "./limits";

/**
 * Extracts DER-encoded X.509 certificates from a PKCS#7 (CMS) SignedData structure.
 *
 * Handles both:
 *   - PEM-wrapped PKCS#7  (-----BEGIN PKCS7-----)
 *   - Raw DER PKCS#7
 *
 * PKCS#7 SignedData ASN.1 layout:
 *   SEQUENCE (ContentInfo)
 *     OID  1.2.840.113549.1.7.2  (signedData)
 *     [0]  (content)
 *       SEQUENCE (SignedData)
 *         INTEGER   version
 *         SET       digestAlgorithms
 *         SEQUENCE  encapContentInfo
 *         [0]       certificates   ← what we extract
 *           SEQUENCE  Certificate
 *           SEQUENCE  Certificate …
 *         [1]       crls (optional)
 *         SET       signerInfos
 */
export function extractCertsFromPkcs7(input: string | Uint8Array): string[] {
  assertWithinInputLimit(typeof input === "string" ? Buffer.byteLength(input, "utf8") : input.byteLength, "PKCS#7 file");
  let der: Uint8Array;

  if (typeof input === "string") {
    // PEM-wrapped: find the PKCS7 block
    const blocks = splitPemBlocks(input).filter(b => b.type === "PKCS7");
    if (blocks.length === 0) {
      // Maybe it has direct CERTIFICATE blocks (some tools do this)
      const certBlocks = splitPemBlocks(input).filter(b => b.type === "CERTIFICATE");
      if (certBlocks.length > MAX_CERTIFICATES) throw new Error(`PKCS#7 file exceeds the maximum of ${MAX_CERTIFICATES} certificates.`);
      return certBlocks.map(b => b.pem);
    }
    der = new Uint8Array(Buffer.from(blocks[0].base64, "base64"));
  } else {
    der = input;
  }

  try {
    return extractCertsFromDer(der);
  } catch (err) {
    if (typeof input === "string") {
        const certBlocks = splitPemBlocks(input).filter(b => b.type === "CERTIFICATE");
        if (certBlocks.length > 0) {
          if (certBlocks.length > MAX_CERTIFICATES) throw new Error(`PKCS#7 file exceeds the maximum of ${MAX_CERTIFICATES} certificates.`);
          return certBlocks.map(b => b.pem);
      }
    }
    const msg = err instanceof Error ? err.message : String(err);
    throw new Error(`Failed to parse PKCS#7 structure: ${msg}`);
  }
}

function extractCertsFromDer(der: Uint8Array): string[] {
  let pos = 0;

  // 1. ContentInfo SEQUENCE
  const ci = readSeq(der, pos);
  pos = ci.contentStart;

  // 2. Skip OID (signedData OID)
  const oid = readElement(der, pos);
  if (oid.tag !== 0x06) throw new Error("Expected OID in ContentInfo");
  pos = oid.nextOffset;

  // 3. [0] EXPLICIT context wrapping SignedData
  const ctx0 = readElement(der, pos);
  if (ctx0.tag !== 0xa0) throw new Error("Expected [0] context wrapping SignedData");
  pos = ctx0.contentStart;

  // 4. SignedData SEQUENCE
  const sd = readSeq(der, pos);
  pos = sd.contentStart;
  const sdEnd = sd.nextOffset;

  // 5. Walk SignedData children
  while (pos < sdEnd) {
    const el = readElement(der, pos);

    if (el.tag === 0xa0) {
      // certificates [0] IMPLICIT — extract each SEQUENCE
      return extractSequencesFrom(der, el.contentStart, el.nextOffset);
    }

    pos = el.nextOffset;
  }

  return [];
}

/** Reads a SEQUENCE tag and returns its content range. */
function readSeq(
  buf: Uint8Array,
  offset: number
): { contentStart: number; nextOffset: number } {
  const el = readElement(buf, offset);
  if (el.tag !== 0x30) throw new Error(`Expected SEQUENCE (0x30) at offset ${offset}, got 0x${el.tag.toString(16)}`);
  return el;
}

/** Extracts all top-level SEQUENCE elements from a range as PEM strings. */
function extractSequencesFrom(buf: Uint8Array, start: number, end: number): string[] {
  const pems: string[] = [];
  let pos = start;

  while (pos < end) {
    const el = readElement(buf, pos);
    if (el.tag === 0x30) {
      // Full element bytes (tag + length + content)
      const certDer = buf.slice(pos, el.nextOffset);
      if (certDer.byteLength > MAX_PEM_BLOCK_CHARS) throw new Error(`Certificate exceeds the maximum of ${MAX_PEM_BLOCK_CHARS} bytes.`);
      pems.push(derToPem(certDer));
      if (pems.length > MAX_CERTIFICATES) throw new Error(`PKCS#7 file exceeds the maximum of ${MAX_CERTIFICATES} certificates.`);
    }
    pos = el.nextOffset;
  }

  return pems;
}

// ── DER element reader ────────────────────────────────────────────────────────

interface DerElement {
  tag: number;
  contentStart: number;
  contentLength: number;
  nextOffset: number;
}

function readElement(buf: Uint8Array, offset: number): DerElement {
  if (offset >= buf.length) {
    throw new Error(`Offset ${offset} out of bounds (len ${buf.length})`);
  }

  const tag = buf[offset];
  const { length, headerBytes } = readLength(buf, offset + 1);

  const contentStart = offset + 1 + headerBytes;
  const nextOffset = contentStart + length;

  if (nextOffset > buf.length) {
    throw new Error(`Element at ${offset} extends beyond buffer (${nextOffset} > ${buf.length})`);
  }

  return { tag, contentStart, contentLength: length, nextOffset };
}

function readLength(buf: Uint8Array, offset: number): { length: number; headerBytes: number } {
  if (offset >= buf.length) {
    throw new Error(`Length offset ${offset} out of bounds (len ${buf.length})`);
  }
  const first = buf[offset];

  if (first < 0x80) {
    return { length: first, headerBytes: 1 };
  }

  const numBytes = first & 0x7f;
  if (numBytes === 0 || numBytes > 4) {
    throw new Error(`Unsupported length encoding at offset ${offset}`);
  }

  let length = 0;
  for (let i = 0; i < numBytes; i++) {
    if (offset + 1 + i >= buf.length) {
      throw new Error(`Truncated length at offset ${offset}`);
    }
    length = (length << 8) | buf[offset + 1 + i];
  }

  return { length, headerBytes: 1 + numBytes };
}
