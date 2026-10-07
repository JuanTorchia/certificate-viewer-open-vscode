import * as forge from "node-forge";
import { parseCertificateFile } from "./certParser";
import { CertificateInfo } from "../models/certificate";
import { assertWithinInputLimit, MAX_CERTIFICATES, MAX_PKCS12_KDF_ITERATIONS } from "./limits";

const CMS_DATA_OID = "1.2.840.113549.1.7.1";
const PBES2_OID = "1.2.840.113549.1.5.13";
const PBKDF2_OID = "1.2.840.113549.1.5.12";
const PKCS12_PBE_OID_PREFIX = "1.2.840.113549.1.12.1.";

export class Pkcs12PasswordError extends Error {
  constructor() {
    super("PKCS#12: invalid password or failed MAC verification");
  }
}

class Pkcs12IterationLimitError extends Error {}

/**
 * Extracts certificates from a PKCS#12 / PFX binary buffer.
 * Throws Pkcs12PasswordError if the password is wrong or MAC verification fails.
 */
export function parsePkcs12(raw: Uint8Array, password: string): CertificateInfo[] {
  assertWithinInputLimit(raw.byteLength, "PKCS#12 file");
  let p12: forge.pkcs12.Pkcs12Pfx;
  try {
    const buf = forge.util.createBuffer(Buffer.from(raw).toString("binary"));
    const asn1 = forge.asn1.fromDer(buf);
    assertSafePkcs12Iterations(asn1);
    p12 = forge.pkcs12.pkcs12FromAsn1(asn1, false, password);
  } catch (e) {
    if (e instanceof Pkcs12IterationLimitError) {
      throw e;
    }
    const msg = e instanceof Error ? e.message : String(e);
    if (/mac|password|integrity|verify|invalid/i.test(msg)) {
      throw new Pkcs12PasswordError();
    }
    throw e;
  }

  const certs: CertificateInfo[] = [];
  for (const sc of p12.safeContents) {
    for (const bag of sc.safeBags) {
      if (bag.type !== forge.pki.oids.certBag || !bag.cert) {
        continue;
      }
      try {
        const pem = forge.pki.certificateToPem(bag.cert);
        certs.push(...parseCertificateFile(pem));
      } catch {
        // skip unreadable cert bags
      }
      if (certs.length > MAX_CERTIFICATES) {
        throw new Error(`PKCS#12 file exceeds the maximum of ${MAX_CERTIFICATES} certificates.`);
      }
    }
  }
  return certs;
}

function assertSafePkcs12Iterations(pfx: forge.asn1.Asn1): void {
  const pfxValues = asn1Children(pfx);
  const macDataValues = asn1Children(pfxValues?.[2]);
  const iterations = macDataValues?.[2];
  if (iterations?.type === forge.asn1.Type.INTEGER && typeof iterations.value === "string") {
    assertIterationLimit(iterations.value, "PKCS#12 MAC");
  }

  const authenticatedSafe = decodeDataContentInfo(pfxValues?.[1]);
  if (!authenticatedSafe) {
    return;
  }

  assertVisibleKdfIterationLimits(authenticatedSafe);
  for (const contentInfo of asn1Children(authenticatedSafe) ?? []) {
    const safeContents = decodeDataContentInfo(contentInfo);
    if (safeContents) {
      assertVisibleKdfIterationLimits(safeContents);
    }
  }
}

function asn1Children(node: forge.asn1.Asn1 | undefined): forge.asn1.Asn1[] | undefined {
  return node && Array.isArray(node.value) ? node.value as forge.asn1.Asn1[] : undefined;
}

function decodeDataContentInfo(contentInfo: forge.asn1.Asn1 | undefined): forge.asn1.Asn1 | undefined {
  const values = asn1Children(contentInfo);
  if (asn1Oid(values?.[0]) !== CMS_DATA_OID) {
    return undefined;
  }

  const wrappedContent = asn1Children(values?.[1])?.[0];
  if (wrappedContent?.type !== forge.asn1.Type.OCTETSTRING || typeof wrappedContent.value !== "string") {
    return undefined;
  }

  try {
    return forge.asn1.fromDer(forge.util.createBuffer(wrappedContent.value), false);
  } catch {
    return undefined;
  }
}

function assertVisibleKdfIterationLimits(root: forge.asn1.Asn1): void {
  const pending = [root];
  while (pending.length > 0) {
    const node = pending.pop()!;
    const values = asn1Children(node);
    if (!values) {
      continue;
    }

    const algorithmOid = asn1Oid(values[0]);
    if (algorithmOid === PBES2_OID) {
      const pbes2Parameters = asn1Children(values[1]);
      const kdf = asn1Children(pbes2Parameters?.[0]);
      if (asn1Oid(kdf?.[0]) === PBKDF2_OID) {
        const pbkdf2Parameters = asn1Children(kdf?.[1]);
        const iterations = pbkdf2Parameters?.[1];
        if (iterations?.type === forge.asn1.Type.INTEGER && typeof iterations.value === "string") {
          assertIterationLimit(iterations.value, "PKCS#12 PBES2");
        }
      }
    } else if (algorithmOid?.startsWith(PKCS12_PBE_OID_PREFIX)) {
      const pbeParameters = asn1Children(values[1]);
      const iterations = pbeParameters?.[1];
      if (iterations?.type === forge.asn1.Type.INTEGER && typeof iterations.value === "string") {
        assertIterationLimit(iterations.value, "PKCS#12 PBE");
      }
    }

    pending.push(...values);
  }
}

function asn1Oid(node: forge.asn1.Asn1 | undefined): string | undefined {
  if (node?.type !== forge.asn1.Type.OID || typeof node.value !== "string") {
    return undefined;
  }
  try {
    return forge.asn1.derToOid(node.value);
  } catch {
    return undefined;
  }
}

function assertIterationLimit(encoded: string, label: string): void {
  if (encoded.length === 0 || (encoded.charCodeAt(0) & 0x80) !== 0) {
    throw new Error(`${label} iteration count must be a positive integer.`);
  }

  let firstSignificantByte = 0;
  while (firstSignificantByte < encoded.length && encoded.charCodeAt(firstSignificantByte) === 0) {
    firstSignificantByte += 1;
  }
  if (firstSignificantByte === encoded.length) {
    throw new Error(`${label} iteration count must be a positive integer.`);
  }

  const significantBytes = encoded.length - firstSignificantByte;
  const maximumBytes = Math.ceil(Math.log2(MAX_PKCS12_KDF_ITERATIONS + 1) / 8);
  if (significantBytes > maximumBytes) {
    throwIterationLimitError(label);
  }

  let value = 0;
  for (let index = firstSignificantByte; index < encoded.length; index += 1) {
    value = value * 256 + encoded.charCodeAt(index);
  }
  if (value > MAX_PKCS12_KDF_ITERATIONS) {
    throwIterationLimitError(label);
  }
}

function throwIterationLimitError(label: string): never {
  throw new Pkcs12IterationLimitError(`${label} iteration count exceeds the maximum of ${MAX_PKCS12_KDF_ITERATIONS}.`);
}
