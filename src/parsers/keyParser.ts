import * as crypto from "crypto";
import * as forge from "node-forge";
import { splitPemBlocks } from "./pemParser";

export interface KeyInfo {
  kind: "public" | "private";
  algorithm: string;
  display: string;
  keySize?: number;
  curve?: string;
  publicExponent?: string;
  format: string;
  publicKeyPem?: string;
  spkiFingerprints?: {
    sha1: string;
    sha256: string;
  };
  encrypted?: boolean;
  note?: string;
}

export function isEncryptedPrivateKey(raw: Uint8Array): boolean {
  const text = Buffer.from(raw).toString("utf8");
  return /-----BEGIN ENCRYPTED PRIVATE KEY-----/.test(text) || /Proc-Type: 4,ENCRYPTED/.test(text);
}

export function parseKeyFile(raw: Uint8Array, filename: string): KeyInfo[] {
  const text = Buffer.from(raw).toString("utf8");
  const format = keyFileFormat(raw, filename, text);
  if (format === "PEM") {
    const keyBlocks = splitPemBlocks(text).filter(isKeyPemBlock);
    if (keyBlocks.length > 1) return keyBlocks.map(block => keyInfoFromPemBlock(block.pem));
  }
  if (isEncryptedPrivateKey(raw) || isEncryptedPkcs8Der(raw)) {
    return [{
      kind: "private",
      algorithm: "Encrypted private key",
      display: "Encrypted private key",
      format,
      encrypted: true,
      note: "CertView does not prompt for private key passwords or decrypt encrypted private keys.",
    }];
  }
  if (looksLikeJwk(text)) {
    return [keyInfoFromObject(crypto.createPublicKey({ key: JSON.parse(text), format: "jwk" }), "JWK")];
  }
  const isPrivate = /-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----/.test(text);
  const isPublic = /-----BEGIN (?:[A-Z ]+ )?PUBLIC KEY-----/.test(text);
  const key = isPrivate ? crypto.createPrivateKey(text) : isPublic ? crypto.createPublicKey(text) : parseDerKey(raw, filename);
  return [keyInfoFromObject(key, format)];
}

export function parseKeyPemBlocks(text: string): KeyInfo[] {
  return splitPemBlocks(text).filter(isKeyPemBlock).map(block => keyInfoFromPemBlock(block.pem, true));
}

function keyFileFormat(raw: Uint8Array, filename: string, text: string): string {
  if (filename.toLowerCase().endsWith(".jwk") || looksLikeJwk(text)) return "JWK";
  if (/-----BEGIN [^-]+-----/.test(text)) return "PEM";
  return "DER";
}

function isKeyPemBlock(block: { type: string }): boolean {
  return /(?:^| )PRIVATE KEY$/.test(block.type) || /(?:^| )PUBLIC KEY$/.test(block.type);
}

function keyInfoFromPemBlock(pem: string, tolerateErrors = false): KeyInfo {
  if (/-----BEGIN ENCRYPTED PRIVATE KEY-----/.test(pem) || /Proc-Type: 4,ENCRYPTED/.test(pem)) {
    return {
      kind: "private",
      algorithm: "Encrypted private key",
      display: "Encrypted private key",
      format: "PEM",
      encrypted: true,
      note: "CertView does not prompt for private key passwords or decrypt encrypted private keys.",
    };
  }
  const isPrivate = /-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----/.test(pem);
  try {
    const key = isPrivate ? crypto.createPrivateKey(pem) : crypto.createPublicKey(pem);
    return keyInfoFromObject(key, "PEM");
  } catch (error) {
    if (!tolerateErrors) throw error;
    return {
      kind: isPrivate ? "private" : "public",
      algorithm: `Unsupported ${isPrivate ? "private" : "public"} key`,
      display: `Unsupported ${isPrivate ? "private" : "public"} key`,
      format: "PEM",
      note: error instanceof Error ? error.message : String(error),
    };
  }
}

function isEncryptedPkcs8Der(raw: Uint8Array): boolean {
  try {
    const root = forge.asn1.fromDer(Buffer.from(raw).toString("binary"));
    if (!Array.isArray(root.value) || root.value.length < 2) return false;
    const algorithmIdentifier = root.value[0] as forge.asn1.Asn1;
    const encryptedData = root.value[1] as forge.asn1.Asn1;
    return root.type === forge.asn1.Type.SEQUENCE &&
      Array.isArray(algorithmIdentifier.value) &&
      algorithmIdentifier.type === forge.asn1.Type.SEQUENCE &&
      encryptedData.type === forge.asn1.Type.OCTETSTRING;
  } catch {
    return false;
  }
}

function keyInfoFromObject(key: crypto.KeyObject, format: string): KeyInfo {
  const details = key.asymmetricKeyDetails ?? {};
  const publicKeyPem = key.type === "private"
    ? crypto.createPublicKey(key).export({ type: "spki", format: "pem" }).toString()
    : key.export({ type: "spki", format: "pem" }).toString();
  const spkiDer = key.type === "private"
    ? crypto.createPublicKey(key).export({ type: "spki", format: "der" }) as Buffer
    : key.export({ type: "spki", format: "der" }) as Buffer;
  return {
    kind: key.type === "private" ? "private" : "public",
    algorithm: (key.asymmetricKeyType ?? "unknown").toUpperCase(),
    display: keyDisplay((key.asymmetricKeyType ?? "unknown").toUpperCase(), "modulusLength" in details ? details.modulusLength : undefined, "namedCurve" in details && typeof details.namedCurve === "string" ? friendlyCurveName(details.namedCurve) : undefined),
    keySize: "modulusLength" in details ? details.modulusLength : undefined,
    curve: "namedCurve" in details && typeof details.namedCurve === "string" ? friendlyCurveName(details.namedCurve) : undefined,
    publicExponent: "publicExponent" in details && details.publicExponent !== undefined ? details.publicExponent.toString() : undefined,
    format,
    publicKeyPem,
    spkiFingerprints: {
      sha1: fingerprint(spkiDer, "sha1"),
      sha256: fingerprint(spkiDer, "sha256"),
    },
  };
}

function keyDisplay(type: string, keySize?: number, curve?: string): string {
  if (keySize) return `${type}-${keySize}`;
  if (curve) return `${type}-${shortCurveName(curve)}`;
  return type;
}

function shortCurveName(curve: string): string {
  const match = curve.match(/P-\d+/);
  return match ? match[0] : curve.split("/")[0].trim();
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

function looksLikeJwk(text: string): boolean {
  try {
    const parsed = JSON.parse(text) as { kty?: string };
    return typeof parsed.kty === "string";
  } catch {
    return false;
  }
}

function parseDerKey(raw: Uint8Array, filename: string): crypto.KeyObject {
  const bytes = Buffer.from(raw);
  if (/\.key$/i.test(filename)) {
    try { return crypto.createPrivateKey({ key: bytes, format: "der", type: "pkcs8" }); } catch { /* try public */ }
  }
  try { return crypto.createPublicKey({ key: bytes, format: "der", type: "spki" }); } catch { /* try private */ }
  return crypto.createPrivateKey({ key: bytes, format: "der", type: "pkcs8" });
}
