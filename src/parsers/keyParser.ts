import * as crypto from "crypto";
import * as forge from "node-forge";

export interface KeyInfo {
  kind: "public" | "private";
  algorithm: string;
  keySize?: number;
  curve?: string;
  format: string;
  publicKeyPem?: string;
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
  if (isEncryptedPrivateKey(raw) || isEncryptedPkcs8Der(raw)) {
    return [{
      kind: "private",
      algorithm: "Encrypted private key",
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

function keyFileFormat(raw: Uint8Array, filename: string, text: string): string {
  if (filename.toLowerCase().endsWith(".jwk") || looksLikeJwk(text)) return "JWK";
  if (/-----BEGIN [^-]+-----/.test(text)) return "PEM";
  return "DER";
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
  return {
    kind: key.type === "private" ? "private" : "public",
    algorithm: (key.asymmetricKeyType ?? "unknown").toUpperCase(),
    keySize: "modulusLength" in details ? details.modulusLength : undefined,
    curve: "namedCurve" in details ? details.namedCurve : undefined,
    format,
    publicKeyPem,
  };
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
