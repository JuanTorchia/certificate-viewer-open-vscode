import * as forge from "node-forge";
import { parseCertificateFile } from "./certParser";
import { CertificateInfo } from "../models/certificate";
import { assertWithinInputLimit, MAX_CERTIFICATES } from "./limits";

export class Pkcs12PasswordError extends Error {
  constructor() {
    super("PKCS#12: invalid password or failed MAC verification");
  }
}

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
    p12 = forge.pkcs12.pkcs12FromAsn1(asn1, false, password);
  } catch (e) {
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
