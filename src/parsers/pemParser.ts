import { MAX_PEM_BLOCK_CHARS, MAX_PEM_BLOCKS } from "./limits";

const PEM_SEP = "-".repeat(5);
const PEM_HEADER_RE = new RegExp(`^${PEM_SEP}BEGIN ([A-Z0-9 ]+)${PEM_SEP}$`);
const PEM_FOOTER_RE = new RegExp(`^${PEM_SEP}END ([A-Z0-9 ]+)${PEM_SEP}$`);

export interface PemBlock {
  type: string;
  base64: string;
  pem: string;
}

/** Certificate types we know how to display */
export type KnownPemType =
  | "CERTIFICATE"
  | "CERTIFICATE REQUEST"
  | "NEW CERTIFICATE REQUEST"
  | "PKCS7"
  | "X509 CRL"
  | "PUBLIC KEY";

/**
 * Splits a PEM file (potentially multi-block) into individual blocks.
 */
export function splitPemBlocks(pemContent: string): PemBlock[] {
  const blocks: PemBlock[] = [];
  const lines = pemContent.replace(/\r\n/g, "\n").split("\n");

  let inBlock = false;
  let blockType = "";
  let blockLines: string[] = [];

  for (const line of lines) {
    const trimmed = line.trim();
    const headerMatch = trimmed.match(PEM_HEADER_RE);
    const footerMatch = trimmed.match(PEM_FOOTER_RE);

    if (headerMatch && !inBlock) {
      inBlock = true;
      blockType = headerMatch[1];
      blockLines = [trimmed];
    } else if (footerMatch && inBlock) {
      blockLines.push(trimmed);
      const pem = blockLines.join("\n");
      if (pem.length > MAX_PEM_BLOCK_CHARS) {
        throw new Error(`PEM block exceeds the maximum of ${MAX_PEM_BLOCK_CHARS} characters.`);
      }
      const base64 = blockLines.slice(1, -1).join("").replace(/\s/g, "");
      blocks.push({ type: blockType, base64, pem });
      if (blocks.length > MAX_PEM_BLOCKS) {
        throw new Error(`PEM file exceeds the maximum of ${MAX_PEM_BLOCKS} blocks.`);
      }
      inBlock = false;
      blockType = "";
      blockLines = [];
    } else if (inBlock) {
      blockLines.push(trimmed);
      if (blockLines.join("\n").length > MAX_PEM_BLOCK_CHARS) {
        throw new Error(`PEM block exceeds the maximum of ${MAX_PEM_BLOCK_CHARS} characters.`);
      }
    }
  }

  return blocks;
}

/** Returns true if the content looks like a PEM file. */
export function isPemContent(content: string): boolean {
  return PEM_HEADER_RE.test(content.trim().split("\n")[0]?.trim() ?? "");
}

/**
 * Returns true if the buffer looks like a DER-encoded ASN.1 SEQUENCE.
 * DER files start with 0x30 (SEQUENCE tag).
 */
export function isDerBuffer(buffer: Uint8Array): boolean {
  return buffer.length > 1 && buffer[0] === 0x30;
}

/** Converts DER bytes to a PEM CERTIFICATE string. */
export function derToPem(derBytes: Uint8Array): string {
  const base64 = Buffer.from(derBytes).toString("base64");
  const lines = base64.match(/.{1,64}/g) ?? [];
  const tag = "CERTIFICATE";
  return `${PEM_SEP}BEGIN ${tag}${PEM_SEP}\n${lines.join("\n")}\n${PEM_SEP}END ${tag}${PEM_SEP}`;
}

/** Converts a base64 body to DER bytes. */
export function base64ToDer(base64: string): Uint8Array {
  return new Uint8Array(Buffer.from(base64, "base64"));
}

/**
 * Detects which format a file is in based on content + extension.
 * Returns the primary PEM block type or 'DER'.
 */
export function detectFormat(
  content: string | Uint8Array,
  _extension: string
): KnownPemType | "DER" | "UNKNOWN" {
  if (typeof content !== "string") {
    return isDerBuffer(content) ? "DER" : "UNKNOWN";
  }

  if (!isPemContent(content)) {
    // Binary with .cer/.der extension → try DER
    return "DER";
  }

  const blocks = splitPemBlocks(content);
  if (blocks.length === 0) return "UNKNOWN";

  const type = blocks[0].type as KnownPemType;
  return type;
}
