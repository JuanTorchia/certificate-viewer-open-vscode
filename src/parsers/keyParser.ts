import * as crypto from "crypto";

export interface KeyInfo {
  kind: "public" | "private";
  algorithm: string;
  keySize?: number;
  curve?: string;
  format: string;
  publicKeyPem?: string;
}

export function parseKeyFile(raw: Uint8Array, filename: string): KeyInfo[] {
  const text = Buffer.from(raw).toString("utf8");
  if (/-----BEGIN ENCRYPTED PRIVATE KEY-----/.test(text) || /Proc-Type: 4,ENCRYPTED/.test(text)) {
    throw new Error("Encrypted private keys require a password and are not opened directly yet. Convert with OpenSSL or provide an unencrypted test key for inspection.");
  }
  if (looksLikeJwk(text)) {
    return [keyInfoFromObject(crypto.createPublicKey({ key: JSON.parse(text), format: "jwk" }), "JWK")];
  }
  const isPrivate = /-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----/.test(text);
  const isPublic = /-----BEGIN (?:[A-Z ]+ )?PUBLIC KEY-----/.test(text);
  const key = isPrivate ? crypto.createPrivateKey(text) : isPublic ? crypto.createPublicKey(text) : parseDerKey(raw, filename);
  return [keyInfoFromObject(key, filename.toLowerCase().endsWith(".der") ? "DER" : "PEM")];
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
