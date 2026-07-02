import * as crypto from "crypto";
import * as forge from "node-forge";
import {
  CertificateInfo,
  CertificateSubject,
  SubjectAlternativeName,
  CertificateExtension,
  ExtendedKeyUsageInfo,
} from "../models/certificate";
import { derToPem, splitPemBlocks } from "./pemParser";
import { assertWithinInputLimit, MAX_CERTIFICATES } from "./limits";
import { CT_LOG_NAMES } from "./ctLogs";
import { addChainFindings, safeCA, validateCertificate } from "./certLinter";

const EXTENDED_KEY_USAGE_OID: Record<string, string> = {
  "1.3.6.1.5.5.7.3.1": "TLS Web Server Authentication",
  "1.3.6.1.5.5.7.3.2": "TLS Web Client Authentication",
  "1.3.6.1.5.5.7.3.3": "Code Signing",
  "1.3.6.1.5.5.7.3.4": "Email Protection",
  "1.3.6.1.5.5.7.3.5": "IPsec End System",
  "1.3.6.1.5.5.7.3.6": "IPsec Tunnel",
  "1.3.6.1.5.5.7.3.7": "IPsec User",
  "1.3.6.1.5.5.7.3.8": "Time Stamping",
  "1.3.6.1.5.5.7.3.9": "OCSP Signing",
  "1.3.6.1.5.5.7.3.10": "DVCS",
  "1.3.6.1.5.5.7.3.11": "SBGP Certificate AA Service Authentication",
  "1.3.6.1.5.5.7.3.13": "EAP over PPP",
  "1.3.6.1.5.5.7.3.14": "EAP over LAN",
  "1.3.6.1.5.5.7.3.15": "SCVP Server",
  "1.3.6.1.5.5.7.3.16": "SCVP Client",
  "1.3.6.1.5.5.7.3.17": "IPsec IKE",
  "1.3.6.1.5.5.7.3.18": "CAPWAP AC",
  "1.3.6.1.5.5.7.3.19": "CAPWAP WTP",
  "1.3.6.1.5.5.7.3.20": "SIP Domain",
  "1.3.6.1.5.5.7.3.21": "SSH Client",
  "1.3.6.1.5.5.7.3.22": "SSH Server",
  "1.3.6.1.5.5.7.3.23": "SEND Router",
  "1.3.6.1.5.5.7.3.24": "SEND Proxied Router",
  "1.3.6.1.5.5.7.3.25": "SEND Owner",
  "1.3.6.1.5.5.7.3.26": "SEND Proxied Owner",
  "1.3.6.1.5.5.7.3.27": "CMC CA",
  "1.3.6.1.5.5.7.3.28": "CMC RA",
  "1.3.6.1.5.5.7.3.29": "CMC Archive",
  "1.3.6.1.5.5.7.3.36": "Document Signing",
  "1.3.6.1.5.2.3.4": "PKINIT Client Authentication",
  "1.3.6.1.5.2.3.5": "PKINIT KDC Authentication",
  "1.3.6.1.4.1.311.10.3.1": "Microsoft Trust List Signing",
  "1.3.6.1.4.1.311.10.3.2": "Microsoft Time Stamp Signing",
  "1.3.6.1.4.1.311.10.3.3": "Microsoft Server Gated Cryptography",
  "1.3.6.1.4.1.311.10.3.4": "Encrypting File System",
  "1.3.6.1.4.1.311.10.3.4.1": "File Recovery",
  "1.3.6.1.4.1.311.10.3.5": "Windows Hardware Driver Verification",
  "1.3.6.1.4.1.311.10.3.6": "Windows System Component Verification",
  "1.3.6.1.4.1.311.10.3.8": "Embedded Windows System Component Verification",
  "1.3.6.1.4.1.311.10.3.9": "Root List Signer",
  "1.3.6.1.4.1.311.10.3.10": "Qualified Subordination",
  "1.3.6.1.4.1.311.10.3.11": "Key Recovery",
  "1.3.6.1.4.1.311.10.3.12": "Document Signing",
  "1.3.6.1.4.1.311.10.3.13": "Lifetime Signing",
  "1.3.6.1.4.1.311.10.3.20": "Windows Kits Component",
  "1.3.6.1.4.1.311.20.2.2": "Smart Card Logon",
  "1.3.6.1.4.1.311.21.6": "Key Recovery Agent",
  "1.3.6.1.4.1.311.21.19": "Directory Service Email Replication",
  "2.5.29.37.0": "Any Extended Key Usage",
};

const FORGE_EXTENDED_KEY_USAGE: Record<string, string> = {
  serverAuth: "1.3.6.1.5.5.7.3.1",
  clientAuth: "1.3.6.1.5.5.7.3.2",
  codeSigning: "1.3.6.1.5.5.7.3.3",
  emailProtection: "1.3.6.1.5.5.7.3.4",
  ipsecEndSystem: "1.3.6.1.5.5.7.3.5",
  ipsecTunnel: "1.3.6.1.5.5.7.3.6",
  ipsecUser: "1.3.6.1.5.5.7.3.7",
  timeStamping: "1.3.6.1.5.5.7.3.8",
  ocspSigning: "1.3.6.1.5.5.7.3.9",
  anyExtendedKeyUsage: "2.5.29.37.0",
};

const SIGNATURE_ALGORITHM_OID: Record<string, string> = {
  "1.2.840.113549.1.1.5": "sha1WithRSAEncryption",
  "1.2.840.113549.1.1.11": "sha256WithRSAEncryption",
  "1.2.840.113549.1.1.12": "sha384WithRSAEncryption",
  "1.2.840.113549.1.1.13": "sha512WithRSAEncryption",
  "1.2.840.10045.4.3.2": "ecdsa-with-SHA256",
  "1.2.840.10045.4.3.3": "ecdsa-with-SHA384",
  "1.2.840.10045.4.3.4": "ecdsa-with-SHA512",
  "1.3.101.112": "Ed25519",
  "1.3.101.113": "Ed448",
  "2.16.840.1.101.3.4.3.17": "ML-DSA-44",
  "2.16.840.1.101.3.4.3.18": "ML-DSA-65",
  "2.16.840.1.101.3.4.3.19": "ML-DSA-87",
};

const TLS_FEATURES: Record<number, string> = {
  5: "status_request",
  17: "status_request_v2",
};

const CURVE_NAMES: Record<string, string> = {
  "1.2.840.10045.3.1.1": "secp192r1 / prime192v1 / P-192",
  "1.2.840.10045.3.1.2": "prime192v2",
  "1.2.840.10045.3.1.3": "prime192v3",
  "1.2.840.10045.3.1.4": "prime239v1",
  "1.2.840.10045.3.1.5": "prime239v2",
  "1.2.840.10045.3.1.6": "prime239v3",
  "1.2.840.10045.3.1.7": "secp256r1 / prime256v1 / P-256",
  "1.3.132.0.1": "sect163k1",
  "1.3.132.0.2": "sect163r1",
  "1.3.132.0.34": "secp384r1 / P-384",
  "1.3.132.0.35": "secp521r1 / P-521",
  "1.3.132.0.10": "secp256k1",
  "1.3.132.0.15": "sect163r2",
  "1.3.132.0.16": "sect283k1",
  "1.3.132.0.17": "sect283r1",
  "1.3.132.0.26": "sect233k1",
  "1.3.132.0.27": "sect233r1",
  "1.3.132.0.33": "secp224r1 / P-224",
  "1.3.132.0.36": "sect409k1",
  "1.3.132.0.37": "sect409r1",
  "1.3.132.0.38": "sect571k1",
  "1.3.132.0.39": "sect571r1",
  "1.3.36.3.3.2.8.1.1.1": "brainpoolP160r1",
  "1.3.36.3.3.2.8.1.1.2": "brainpoolP160t1",
  "1.3.36.3.3.2.8.1.1.3": "brainpoolP192r1",
  "1.3.36.3.3.2.8.1.1.4": "brainpoolP192t1",
  "1.3.36.3.3.2.8.1.1.5": "brainpoolP224r1",
  "1.3.36.3.3.2.8.1.1.6": "brainpoolP224t1",
  "1.3.36.3.3.2.8.1.1.7": "brainpoolP256r1",
  "1.3.36.3.3.2.8.1.1.8": "brainpoolP256t1",
  "1.3.36.3.3.2.8.1.1.9": "brainpoolP320r1",
  "1.3.36.3.3.2.8.1.1.10": "brainpoolP320t1",
  "1.3.36.3.3.2.8.1.1.11": "brainpoolP384r1",
  "1.3.36.3.3.2.8.1.1.12": "brainpoolP384t1",
  "1.3.36.3.3.2.8.1.1.13": "brainpoolP512r1",
  "1.3.36.3.3.2.8.1.1.14": "brainpoolP512t1",
  "1.3.101.110": "X25519",
  "1.3.101.111": "X448",
  "1.3.101.112": "Ed25519",
  "1.3.101.113": "Ed448",
  "1.2.156.10197.1.301": "SM2 / sm2p256v1",
};

const OID_NAMES: Record<string, string> = {
  ...CURVE_NAMES,
  "1.2.840.10045.2.1": "Elliptic Curve Public Key",
  "1.2.840.10045.3.1.7": "secp256r1 / prime256v1 / P-256",
  "1.3.132.0.34": "secp384r1 / P-384",
  "1.3.132.0.35": "secp521r1 / P-521",
  "1.3.132.0.10": "secp256k1",
  "1.3.101.110": "X25519",
  "1.3.101.111": "X448",
  "1.3.101.112": "Ed25519",
  "1.3.101.113": "Ed448",
  "1.2.840.113549.1.1.1": "RSA Encryption",
  "1.2.840.113549.1.1.10": "RSASSA-PSS",
  "1.2.840.113549.1.1.4": "md5WithRSAEncryption",
  "1.2.840.113549.1.1.5": "sha1WithRSAEncryption",
  "1.2.840.113549.1.1.11": "sha256WithRSAEncryption",
  "1.2.840.113549.1.1.12": "sha384WithRSAEncryption",
  "1.2.840.113549.1.1.13": "sha512WithRSAEncryption",
  "1.2.840.10045.4.1": "ecdsa-with-SHA1",
  "1.2.840.10045.4.3.1": "ecdsa-with-SHA224",
  "1.2.840.10045.4.3.2": "ecdsa-with-SHA256",
  "1.2.840.10045.4.3.3": "ecdsa-with-SHA384",
  "1.2.840.10045.4.3.4": "ecdsa-with-SHA512",
  "1.2.156.10197.1.501": "SM2-with-SM3",
  "2.5.4.3": "Common Name",
  "2.5.4.4": "Surname",
  "2.5.4.5": "Serial Number Attribute",
  "2.5.4.6": "Country Name",
  "2.5.4.7": "Locality Name",
  "2.5.4.8": "State or Province Name",
  "2.5.4.9": "Street Address",
  "2.5.4.10": "Organization Name",
  "2.5.4.11": "Organizational Unit Name",
  "2.5.4.12": "Title",
  "2.5.4.13": "Description",
  "2.5.4.15": "Business Category",
  "2.5.4.17": "Postal Code",
  "2.5.4.18": "Post Office Box",
  "2.5.4.20": "Telephone Number",
  "2.5.4.23": "Facsimile Telephone Number",
  "2.5.4.41": "Name",
  "2.5.4.42": "Given Name",
  "2.5.4.43": "Initials",
  "2.5.4.44": "Generation Qualifier",
  "2.5.4.46": "DN Qualifier",
  "2.5.4.65": "Pseudonym",
  "2.5.4.97": "Organization Identifier",
  "0.9.2342.19200300.100.1.25": "Domain Component",
  "0.9.2342.19200300.100.1.1": "User ID",
  "2.5.29.9": "Subject Directory Attributes",
  "2.5.29.14": "Subject Key Identifier",
  "2.5.29.15": "Key Usage",
  "2.5.29.16": "Private Key Usage Period",
  "2.5.29.17": "Subject Alternative Name",
  "2.5.29.18": "Issuer Alternative Name",
  "2.5.29.19": "Basic Constraints",
  "2.5.29.20": "CRL Number",
  "2.5.29.21": "CRL Reason",
  "2.5.29.23": "Hold Instruction Code",
  "2.5.29.24": "Invalidity Date",
  "2.5.29.27": "Delta CRL Indicator",
  "2.5.29.28": "Issuing Distribution Point",
  "2.5.29.30": "Name Constraints",
  "2.5.29.31": "CRL Distribution Points",
  "2.5.29.32": "Certificate Policies",
  "2.5.29.32.0": "Any Policy",
  "2.5.29.33": "Policy Mappings",
  "2.5.29.35": "Authority Key Identifier",
  "2.5.29.36": "Policy Constraints",
  "2.5.29.37": "Extended Key Usage",
  "2.5.29.54": "Inhibit Any Policy",
  "2.5.29.46": "Freshest CRL",
  "1.3.6.1.5.5.7.1.3": "Qualified Certificate Statements",
  "1.3.6.1.5.5.7.1.11": "Subject Information Access",
  "1.3.6.1.5.5.7.1.1": "Authority Information Access",
  "1.3.6.1.5.5.7.1.24": "TLS Feature",
  "1.3.6.1.4.1.11129.2.4.2": "Signed Certificate Timestamps",
  "1.3.6.1.4.1.11129.2.4.3": "CT Poison",
  "1.3.6.1.4.1.11129.2.4.4": "CT Precertificate Signer",
  "1.3.6.1.4.1.311.20.2": "Certificate Template Name",
  "1.3.6.1.4.1.311.21.7": "Certificate Template Information",
  "1.3.6.1.4.1.311.21.10": "Application Policies",
  "1.3.6.1.4.1.311.21.1": "CA Version",
  "1.3.6.1.4.1.311.21.2": "Previous CA Certificate Hash",
  "1.3.6.1.4.1.311.21.4": "Next CRL Publish",
  "1.3.6.1.4.1.311.21.14": "Published CRL Locations",
  "1.3.6.1.4.1.311.25.1": "Microsoft DS Object GUID",
  "1.2.840.113549.1.9.1": "PKCS #9 Email Address",
  "1.2.840.113549.1.9.2": "PKCS #9 Unstructured Name",
  "1.2.840.113549.1.9.3": "PKCS #9 Content Type",
  "1.2.840.113549.1.9.4": "PKCS #9 Message Digest",
  "1.2.840.113549.1.9.5": "PKCS #9 Signing Time",
  "1.2.840.113549.1.9.6": "PKCS #9 Countersignature",
  "1.2.840.113549.1.9.7": "PKCS #9 Challenge Attribute",
  "1.2.840.113549.1.9.8": "PKCS #9 Unstructured Address",
  "1.2.840.113549.1.9.9": "PKCS #9 Extended Certificate Attributes",
  "1.2.840.113549.1.9.14": "PKCS #9 Extension Request",
  "1.2.840.113549.1.9.15": "S/MIME Capabilities",
  "1.2.840.113549.1.9.16": "S/MIME Object Identifier Arc",
  "1.2.840.113549.1.9.16.2.12": "Signing Certificate",
  "1.2.840.113549.1.9.16.2.14": "Signature Time Stamp Token",
  "1.2.840.113549.1.9.16.2.47": "Signing Certificate V2",
  "1.2.840.113549.1.9.20": "PKCS #9 Friendly Name",
  "1.2.840.113549.1.9.21": "PKCS #9 Local Key ID",
  "1.2.840.113549.1.9.22.1": "x509Certificate",
  "1.2.840.113549.1.9.22.2": "sdsiCertificate",
  "1.2.840.113549.1.9.23.1": "x509CRL",
  "2.23.140.1.1": "CA/Browser Forum Domain Validated",
  "2.23.140.1.2": "CA/Browser Forum Validation Level",
  "2.23.140.1.2.1": "CA/Browser Forum Organization Validated",
  "2.23.140.1.2.2": "CA/Browser Forum Individual Validated",
  "2.23.140.1.2.3": "CA/Browser Forum Extended Validated",
  "2.23.140.1.2.2.7": "CA/Browser Forum S/MIME Sponsor Validated",
  "2.23.140.1.2.2.8": "CA/Browser Forum S/MIME Mailbox Validated",
  "2.23.140.1.2.2.9": "CA/Browser Forum S/MIME Organization Validated",
  "2.23.140.1.2.2.10": "CA/Browser Forum S/MIME Individual Validated",
  "2.23.140.1.31": "CA/Browser Forum Onion Domain Validated",
};

const FORGE_EXTENSION_OIDS: Record<string, string> = {
  subjectKeyIdentifier: "2.5.29.14",
  keyUsage: "2.5.29.15",
  subjectAltName: "2.5.29.17",
  issuerAltName: "2.5.29.18",
  basicConstraints: "2.5.29.19",
  cRLDistributionPoints: "2.5.29.31",
  certificatePolicies: "2.5.29.32",
  authorityKeyIdentifier: "2.5.29.35",
  extKeyUsage: "2.5.29.37",
  authorityInfoAccess: "1.3.6.1.5.5.7.1.1",
};

type ParsedExtension = forge.pki.Certificate["extensions"][number] & Record<string, unknown>;

/**
 * Parses a PEM or DER certificate file.
 * Handles multi-cert PEM chains (returns one entry per cert).
 */
export function parseCertificateFile(content: string | Uint8Array): CertificateInfo[] {
  let pems: string[];

  if (typeof content === "string") {
    assertWithinInputLimit(Buffer.byteLength(content, "utf8"), "Certificate file");
    const blocks = splitPemBlocks(content).filter(b => b.type === "CERTIFICATE");
    if (blocks.length === 0) {
      throw new Error("No CERTIFICATE blocks found in the file.");
    }
    pems = blocks.map(b => b.pem);
  } else {
    assertWithinInputLimit(content.byteLength, "Certificate file");
    pems = [derToPem(content)];
  }

  if (pems.length > MAX_CERTIFICATES) {
    throw new Error(`Certificate file exceeds the maximum of ${MAX_CERTIFICATES} certificates.`);
  }

  const certs = pems.map((pem, idx) => {
    try {
      return parseSinglePem(pem);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      throw new Error(`Certificate #${idx + 1}: ${msg}`);
    }
  });
  addChainFindings(certs);
  return certs;
}

function parseSinglePem(pem: string): CertificateInfo {
  const x509 = new crypto.X509Certificate(pem);
  const forgeCert = tryParseForgeCertificate(pem);
  const parsedExtensions = forgeCert?.extensions as ParsedExtension[] | undefined ?? parseAsn1Extensions(pem);

  const subject = forgeCert ? parseForgeName(forgeCert.subject.attributes, x509.subject) : parseX509Name(x509.subject);
  const issuer = forgeCert ? parseForgeName(forgeCert.issuer.attributes, x509.issuer) : parseX509Name(x509.issuer);

  // keyUsage is string[] in Node.js ≥15.6
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const x509any = x509 as any;
  const keyUsage = parseKeyUsage(parsedExtensions) ?? normalizeKeyUsage(x509any.keyUsage);
  const extendedKeyUsage = parseExtendedKeyUsage(parsedExtensions, x509any.extendedKeyUsage ?? []);
  const extendedKeyUsageDetails = extendedKeyUsage.map(extendedKeyUsageInfo);
  const publicKeyInfo = getPublicKeyInfo(x509.publicKey);
  const extensions = buildExtensions(x509, parsedExtensions);
  const basicConstraints = parseBasicConstraints(parsedExtensions);
  const nameConstraints = extensionValue(parsedExtensions, "2.5.29.30");
  const signatureAlgorithm = getSignatureAlgorithm(x509, pem);
  const findings = validateCertificate({
    x509,
    subject,
    keyUsage,
    extendedKeyUsage,
    extensions,
    basicConstraints,
    publicKeyAlgorithm: publicKeyInfo.algorithm,
    publicKeySize: publicKeyInfo.keySize,
    signatureAlgorithm,
  });

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
    subjectAltNames: parseForgeAltNames(parsedExtensions, "2.5.29.17") ?? parseSubjectAltNames(x509.subjectAltName ?? ""),
    keyUsage,
    extendedKeyUsage,
    extendedKeyUsageDetails,
    extensions,
    basicConstraints,
    nameConstraints,
    signatureAlgorithm,
    publicKeyAlgorithm: publicKeyInfo.algorithm,
    publicKeyDisplay: publicKeyInfo.display,
    publicKeySize: publicKeyInfo.keySize,
    publicKeyCurve: publicKeyInfo.curve,
    publicKeyExponent: publicKeyInfo.exponent,
    publicKeyPem: x509.publicKey.export({ type: "spki", format: "pem" }).toString(),
    fingerprints: {
      sha1: x509.fingerprint.toUpperCase(),
      sha256: x509.fingerprint256.toUpperCase(),
    },
    isSelfSigned: x509.subject === x509.issuer,
    isCA: basicConstraints?.ca ?? safeCA(x509),
    findings,
  };
}

function tryParseForgeCertificate(pem: string): forge.pki.Certificate | undefined {
  try {
    return forge.pki.certificateFromPem(pem);
  } catch {
    return undefined;
  }
}

// Node.js ≥18 returns string[], ≤17 returned a comma-separated string.
// Handle both to be safe.
function normalizeKeyUsage(raw: string[] | string | undefined): string[] {
  if (!raw) return [];
  if (Array.isArray(raw)) return raw;
  return raw.split(/,\s*/).map(s => s.trim()).filter(Boolean);
}

function parseExtendedKeyUsage(extensions: ParsedExtension[], nodeEkus: string[]): string[] {
  const ext = extensions.find(e => e.id === "2.5.29.37" || e.name === "extKeyUsage") as Record<string, unknown> | undefined;
  if (ext) {
    const names = Object.entries(ext)
      .filter(([key, value]) => value === true && !["critical"].includes(key))
      .map(([key]) => key);
    if (names.length) return names;
  }
  return nodeEkus;
}

function extendedKeyUsageInfo(key: string): ExtendedKeyUsageInfo {
  const oid = FORGE_EXTENDED_KEY_USAGE[key] ?? (EXTENDED_KEY_USAGE_OID[key] ? key : undefined);
  return { key, oid, name: oid ? EXTENDED_KEY_USAGE_OID[oid] : undefined };
}

export function parseX509Name(nameStr: string): CertificateSubject {
  const result: CertificateSubject = {};
  if (!nameStr) return result;

  const parts = splitX509Name(nameStr);

  for (const part of parts) {
    const eq = part.indexOf("=");
    if (eq < 0) continue;
    const key = part.slice(0, eq).trim().toUpperCase();
    const value = unescapeX509Value(part.slice(eq + 1).trim());

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

function splitX509Name(nameStr: string): string[] {
  const parts: string[] = [];
  let current = "";
  let escaped = false;
  for (const ch of nameStr.replace(/\r?\n/g, "\n")) {
    if (escaped) {
      current += "\\" + ch;
      escaped = false;
      continue;
    }
    if (ch === "\\") {
      escaped = true;
      continue;
    }
    if (ch === "\n" || ch === ",") {
      if (current.trim()) parts.push(current.trim());
      current = "";
      continue;
    }
    current += ch;
  }
  if (escaped) current += "\\";
  if (current.trim()) parts.push(current.trim());
  return parts;
}

function unescapeX509Value(value: string): string {
  return value.replace(/\\([,=+<>#;"\\])/g, "$1");
}

function parseForgeName(attributes: forge.pki.CertificateField[], fallback: string): CertificateSubject {
  if (!attributes.length) return parseX509Name(fallback);
  const result: CertificateSubject = {};
  for (const attr of attributes) {
    const oid = attr.type;
    const value = String(attr.value);
    switch (oid) {
      case "2.5.4.3": result.commonName = value; break;
      case "2.5.4.10": (result.organization ??= []).push(value); break;
      case "2.5.4.11": (result.organizationalUnit ??= []).push(value); break;
      case "2.5.4.6": (result.country ??= []).push(value); break;
      case "2.5.4.8": (result.state ??= []).push(value); break;
      case "2.5.4.7": (result.locality ??= []).push(value); break;
      case "1.2.840.113549.1.9.1": (result.emailAddress ??= []).push(value); break;
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

function parseForgeAltNames(extensions: ParsedExtension[], oid: string): SubjectAlternativeName[] | undefined {
  const ext = extensions.find(e => e.id === oid) as Record<string, unknown> | undefined;
  const altNames = ext?.altNames as Array<{ type?: number; value?: unknown; ip?: string }> | undefined;
  if (!altNames) return undefined;
  const results: SubjectAlternativeName[] = altNames.map(name => {
    switch (name.type) {
      case 1: return { type: "email", value: String(name.value ?? "") };
      case 2: return { type: "dns", value: String(name.value ?? "") };
      case 6: return { type: "uri", value: String(name.value ?? "") };
      case 7: return { type: "ip", value: name.ip ?? binaryToIp(String(name.value ?? "")) };
      case 0: return { type: "otherName", value: formatOtherName(name.value) };
      default: return { type: "unknown", value: formatGeneralName(name) };
    }
  });
  return results.filter(name => name.value);
}

function formatGeneralName(name: { type?: number; value?: unknown; ip?: string }): string {
  switch (name.type) {
    case 1: return `email:${String(name.value ?? "")}`;
    case 2: return `DNS:${String(name.value ?? "")}`;
    case 6: return `URI:${String(name.value ?? "")}`;
    case 7: return `IP:${name.ip ?? binaryToIp(String(name.value ?? ""))}`;
    case 0: return `otherName:${formatOtherName(name.value)}`;
    default: return `type ${name.type ?? "unknown"}:${String(name.value ?? "")}`;
  }
}

function formatOtherName(value: unknown): string {
  if (!Array.isArray(value) || value.length < 2) return String(value ?? "");
  const oidNode = value[0] as forge.asn1.Asn1;
  const valueNode = value[1] as forge.asn1.Asn1;
  const oid = typeof oidNode.value === "string" ? forge.asn1.derToOid(oidNode.value) : "unknown";
  const inner = Array.isArray(valueNode.value) ? valueNode.value[0] as forge.asn1.Asn1 : undefined;
  return `${oid}:${inner ? asn1ScalarValue(inner) : ""}`;
}

function binaryToIp(value: string): string {
  const bytes = Buffer.from(value, "binary");
  if (bytes.length === 4) return Array.from(bytes).join(".");
  if (bytes.length === 16) {
    const groups: string[] = [];
    for (let i = 0; i < bytes.length; i += 2) groups.push(bytes.readUInt16BE(i).toString(16));
    return groups.join(":").replace(/(^|:)0(:0)+(:|$)/, "::");
  }
  return bytes.toString("hex").toUpperCase();
}

function getPublicKeyInfo(key: crypto.KeyObject): { algorithm: string; display: string; keySize?: number; curve?: string; exponent?: string } {
  try {
    const type = (key.asymmetricKeyType ?? "unknown").toUpperCase();
    const details = key.asymmetricKeyDetails ?? {};
    const keySize = "modulusLength" in details ? (details.modulusLength as number) : undefined;
    const curve = "namedCurve" in details && typeof details.namedCurve === "string" ? friendlyCurveName(details.namedCurve) : undefined;
    const exponent = "publicExponent" in details && details.publicExponent !== undefined ? details.publicExponent.toString() : undefined;
    return { algorithm: type, display: publicKeyDisplay(type, keySize, curve), keySize, curve, exponent };
  } catch {
    return { algorithm: "unknown", display: "unknown" };
  }
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

function friendlyCurveName(curve: string): string {
  const normalized = curve.toLowerCase();
  if (normalized === "prime256v1" || normalized === "secp256r1") return "secp256r1 / prime256v1 / P-256";
  if (normalized === "secp384r1") return "secp384r1 / P-384";
  if (normalized === "secp521r1") return "secp521r1 / P-521";
  return CURVE_NAMES[curve] ?? curve;
}

function getSignatureAlgorithm(x509: crypto.X509Certificate, pem: string): string {
  const nodeAlgorithm = (x509 as { signatureAlgorithm?: string }).signatureAlgorithm;
  if (nodeAlgorithm) return nodeAlgorithm;
  try {
    const der = Buffer.from(pem.replace(/-----[^-]+-----/g, "").replace(/\s/g, ""), "base64").toString("binary");
    const cert = forge.asn1.fromDer(der);
    const values = Array.isArray(cert.value) ? cert.value as forge.asn1.Asn1[] : [];
    const algSeq = values[1];
    const oidNode = Array.isArray(algSeq?.value) ? algSeq.value[0] as forge.asn1.Asn1 : undefined;
    if (typeof oidNode?.value === "string") {
      const oidValue = forge.asn1.derToOid(oidNode.value);
      return SIGNATURE_ALGORITHM_OID[oidValue] ?? oidValue;
    }
  } catch {
    // fall through
  }
  return "Unknown";
}


function buildExtensions(x509: crypto.X509Certificate, parsedExtensions: ParsedExtension[]): CertificateExtension[] {
  const exts = parsedExtensions.map(ext => {
    const anyExt = ext as Record<string, unknown>;
    const oid = String(anyExt.id ?? extensionOidByName(ext.name) ?? "unknown");
    return {
      oid,
      name: OID_NAMES[oid] ?? ext.name ?? oid,
      critical: Boolean(ext.critical),
      value: describeExtension(ext),
    };
  });

  if (x509.subjectAltName && !exts.some(e => e.oid === "2.5.29.17")) {
    exts.push({ oid: "2.5.29.17", name: "Subject Alternative Name", critical: false, value: x509.subjectAltName });
  }

  const ku = normalizeKeyUsage(x509.keyUsage);
  if (ku.length && !exts.some(e => e.oid === "2.5.29.15")) {
    exts.push({ oid: "2.5.29.15", name: "Key Usage", critical: true, value: ku.join(", ") });
  }

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const eku: string[] = (x509 as any).extendedKeyUsage ?? [];
  if (eku.length && !exts.some(e => e.oid === "2.5.29.37")) {
    exts.push({ oid: "2.5.29.37", name: "Extended Key Usage", critical: false, value: eku.join(", ") });
  }

  if (x509.infoAccess && !exts.some(e => e.oid === "1.3.6.1.5.5.7.1.1")) {
    exts.push({ oid: "1.3.6.1.5.5.7.1.1", name: "Authority Information Access", critical: false, value: x509.infoAccess });
  }

  return exts;
}

function extensionOidByName(name?: string): string | undefined {
  if (name && FORGE_EXTENSION_OIDS[name]) return FORGE_EXTENSION_OIDS[name];
  return Object.entries(OID_NAMES).find(([, n]) => n === name)?.[0];
}

function describeExtension(ext: forge.pki.Certificate["extensions"][number]): string {
  const anyExt = ext as Record<string, unknown>;
  const oid = String(anyExt.id ?? extensionOidByName(ext.name) ?? "");
  if (oid === "2.5.29.19") {
    return `CA: ${Boolean(anyExt.cA)}${typeof anyExt.pathLenConstraint === "number" ? `, pathLen: ${anyExt.pathLenConstraint}` : ""}`;
  }
  if (oid === "2.5.29.15") {
    return Object.entries(anyExt).filter(([k, v]) => v === true && k !== "critical").map(([k]) => k).join(", ");
  }
  if (oid === "2.5.29.37") {
    return Object.entries(anyExt).filter(([k, v]) => v === true && k !== "critical").map(([k]) => {
      const info = extendedKeyUsageInfo(k);
      return info.name ? `${info.key} (${info.name})` : info.key;
    }).join(", ");
  }
  if (oid === "2.5.29.17" || oid === "2.5.29.18") {
    const altNames = anyExt.altNames as Array<{ type?: number; value?: string; ip?: string }> | undefined;
    return altNames?.map(formatGeneralName).join(", ") ?? "";
  }
  if (oid === "2.5.29.14") {
    return typeof anyExt.subjectKeyIdentifier === "string" ? anyExt.subjectKeyIdentifier.toUpperCase() : describeKeyIdentifier(ext.value);
  }
  if (oid === "2.5.29.35") {
    return describeAuthorityKeyIdentifier(ext.value);
  }
  if (oid === "2.5.29.30") {
    return describeNameConstraints(ext.value);
  }
  if (oid === "2.5.29.31") {
    return describeUris(ext.value, "URI");
  }
  if (oid === "1.3.6.1.5.5.7.1.1") {
    return describeAuthorityInfoAccess(ext.value);
  }
  if (oid === "2.5.29.32") {
    return describeCertificatePolicies(ext.value);
  }
  if (oid === "1.3.6.1.5.5.7.1.24") {
    return describeTlsFeatures(ext.value);
  }
  if (oid === "1.3.6.1.4.1.11129.2.4.2") {
    return describeSignedCertificateTimestamps(ext.value);
  }
  if (ext.value) return describeDerValue(ext.value);
  return JSON.stringify(anyExt, (_key, value) => typeof value === "string" && value.length > 256 ? `${value.slice(0, 256)}…` : value);
}

function describeKeyIdentifier(value: string): string {
  const root = fromDer(value);
  if (!root || typeof root.value !== "string") return hex(value);
  return Buffer.from(root.value, "binary").toString("hex").toUpperCase().match(/.{2}/g)?.join(":") ?? hex(value);
}

function describeAuthorityKeyIdentifier(value: string): string {
  const root = fromDer(value);
  if (!root || !Array.isArray(root.value)) return hex(value);
  const parts: string[] = [];
  for (const node of root.value as forge.asn1.Asn1[]) {
    if (node.tagClass === forge.asn1.Class.CONTEXT_SPECIFIC && node.type === 0 && typeof node.value === "string") {
      parts.push(`keyid:${Buffer.from(node.value, "binary").toString("hex").toUpperCase().match(/.{2}/g)?.join(":") ?? ""}`);
    }
  }
  return parts.length ? parts.join(", ") : hex(value);
}

function fromDer(value: string): forge.asn1.Asn1 | undefined {
  try {
    return forge.asn1.fromDer(forge.util.createBuffer(value));
  } catch {
    return undefined;
  }
}

function describeNameConstraints(value: string): string {
  const root = fromDer(value);
  if (!root || !Array.isArray(root.value)) return hex(value);
  const parts: string[] = [];
  for (const section of root.value as forge.asn1.Asn1[]) {
    if (!Array.isArray(section.value)) continue;
    const label = section.type === 0 ? "permitted" : section.type === 1 ? "excluded" : `context ${section.type}`;
    for (const subtree of section.value as forge.asn1.Asn1[]) {
      const base = Array.isArray(subtree.value) ? subtree.value[0] as forge.asn1.Asn1 : subtree;
      parts.push(`${label}:${formatGeneralNameNode(base)}`);
    }
  }
  return parts.length ? parts.join(", ") : hex(value);
}

function describeUris(value: string, prefix: string): string {
  const root = fromDer(value);
  if (!root) return hex(value);
  const uris: string[] = [];
  visitAsn1(root, node => {
    if (node.tagClass === forge.asn1.Class.CONTEXT_SPECIFIC && node.type === 6 && typeof node.value === "string") {
      uris.push(`${prefix}:${node.value}`);
    }
  });
  return uris.length ? uris.join(", ") : hex(value);
}

function describeAuthorityInfoAccess(value: string): string {
  const root = fromDer(value);
  if (!root || !Array.isArray(root.value)) return hex(value);
  const items: string[] = [];
  for (const desc of root.value as forge.asn1.Asn1[]) {
    if (!Array.isArray(desc.value) || desc.value.length < 2) continue;
    const oidNode = desc.value[0] as forge.asn1.Asn1;
    const location = desc.value[1] as forge.asn1.Asn1;
    const oid = typeof oidNode.value === "string" ? forge.asn1.derToOid(oidNode.value) : "unknown";
    const method = oid === "1.3.6.1.5.5.7.48.1" ? "OCSP" : oid === "1.3.6.1.5.5.7.48.2" ? "caIssuers" : oid;
    items.push(`${method}:${formatGeneralNameNode(location)}`);
  }
  return items.length ? items.join(", ") : hex(value);
}

function describeCertificatePolicies(value: string): string {
  const root = fromDer(value);
  if (!root || !Array.isArray(root.value)) return hex(value);
  const policies: string[] = [];
  for (const policyInfo of root.value as forge.asn1.Asn1[]) {
    const oidNode = Array.isArray(policyInfo.value) ? policyInfo.value[0] as forge.asn1.Asn1 : undefined;
    if (oidNode && typeof oidNode.value === "string") {
      const oid = forge.asn1.derToOid(oidNode.value);
      policies.push(OID_NAMES[oid] ? `${OID_NAMES[oid]} (${oid})` : oid);
    }
  }
  return policies.length ? policies.join(", ") : hex(value);
}

function describeSignedCertificateTimestamps(value: string): string {
  try {
    const bytes = unwrapOctetString(Buffer.from(value, "binary"));
    if (bytes.length < 2) return hex(value);
    const listLength = bytes.readUInt16BE(0);
    if (bytes.length !== 2 + listLength) return hex(value);
    let offset = 2;
    const end = 2 + listLength;
    const scts: string[] = [];
    let index = 1;
    while (offset < end) {
      if (offset + 2 > end) return hex(value);
      const sctLength = bytes.readUInt16BE(offset);
      offset += 2;
      if (sctLength <= 0 || offset + sctLength > end) return hex(value);
      const sct = bytes.subarray(offset, offset + sctLength);
      offset += sctLength;
      scts.push(describeSingleSct(sct, index++));
    }
    return scts.length ? scts.join("; ") : hex(value);
  } catch {
    return hex(value);
  }
}

function describeSingleSct(sct: Buffer, index: number): string {
  if (sct.length < 43) return `SCT ${index}: malformed (${sct.length} bytes)`;
  const version = sct[0] === 0 ? "v1" : `version ${sct[0]}`;
  const logId = sct.subarray(1, 33).toString("hex").toUpperCase().match(/.{2}/g)?.join(":") ?? "";
  const logName = CT_LOG_NAMES[logId] ?? "unknown log";
  const timestamp = timestampToIso(sct.readBigUInt64BE(33));
  if (!timestamp) return `SCT ${index}: malformed timestamp`;
  const extensionsLengthOffset = 41;
  const extensionsLength = sct.readUInt16BE(extensionsLengthOffset);
  const sigOffset = extensionsLengthOffset + 2 + extensionsLength;
  if (sigOffset + 4 > sct.length) return `SCT ${index}: malformed extensions`;
  const signatureLength = sct.readUInt16BE(sigOffset + 2);
  if (sigOffset + 4 + signatureLength !== sct.length) return `SCT ${index}: malformed signature`;
  const sigAlg = signatureSchemeName(sct[sigOffset], sct[sigOffset + 1]);
  return `SCT ${index}: ${version}, log ${logName}, logID ${logId}, timestamp ${timestamp}, ${sigAlg}`;
}

function unwrapOctetString(bytes: Buffer): Buffer {
  if (bytes.length < 2 || bytes[0] !== 0x04) return bytes;
  const length = derLength(bytes, 1);
  if (!length || length.offset + length.length !== bytes.length) return bytes;
  return bytes.subarray(length.offset);
}

function derLength(bytes: Buffer, offset: number): { length: number; offset: number } | undefined {
  const first = bytes[offset];
  if (first === undefined) return undefined;
  if (first < 0x80) return { length: first, offset: offset + 1 };
  const octets = first & 0x7f;
  if (octets === 0 || octets > 4 || offset + 1 + octets > bytes.length) return undefined;
  let length = 0;
  for (let i = 0; i < octets; i++) length = (length << 8) + bytes[offset + 1 + i];
  return { length, offset: offset + 1 + octets };
}

function timestampToIso(timestamp: bigint): string | undefined {
  if (timestamp > BigInt(Number.MAX_SAFE_INTEGER)) return undefined;
  const millis = Number(timestamp);
  if (millis > 8640000000000000) return undefined;
  try {
    return new Date(millis).toISOString();
  } catch {
    return undefined;
  }
}

function signatureSchemeName(hash: number, signature: number): string {
  const hashes: Record<number, string> = { 0: "none", 1: "MD5", 2: "SHA-1", 3: "SHA-224", 4: "SHA-256", 5: "SHA-384", 6: "SHA-512" };
  const signatures: Record<number, string> = { 0: "anonymous", 1: "RSA", 2: "DSA", 3: "ECDSA" };
  return `${hashes[hash] ?? `hash ${hash}`} with ${signatures[signature] ?? `signature ${signature}`}`;
}

function describeTlsFeatures(value: string): string {
  const root = fromDer(value);
  if (!root || !Array.isArray(root.value)) return hex(value);
  const features = (root.value as forge.asn1.Asn1[]).map(node => {
    const number = typeof node.value === "string" ? Buffer.from(node.value, "binary").reduce((acc, byte) => (acc << 8) + byte, 0) : -1;
    return TLS_FEATURES[number] ?? String(number);
  });
  return features.join(", ");
}

function describeDerValue(value: string): string {
  const root = fromDer(value);
  if (!root) return hex(value);
  const scalar = asn1ScalarValue(root);
  return scalar || hex(value);
}

function formatGeneralNameNode(node: forge.asn1.Asn1): string {
  if (node.tagClass === forge.asn1.Class.CONTEXT_SPECIFIC) {
    if (node.type === 1) return `email:${String(node.value)}`;
    if (node.type === 2) return `DNS:${String(node.value)}`;
    if (node.type === 6) return `URI:${String(node.value)}`;
    if (node.type === 7 && typeof node.value === "string") return `IP:${formatIpConstraint(node.value)}`;
  }
  return asn1ScalarValue(node) || `tag ${node.type}`;
}

function formatIpConstraint(value: string): string {
  const bytes = Buffer.from(value, "binary");
  if (bytes.length === 8) return `${Array.from(bytes.subarray(0, 4)).join(".")}/${Array.from(bytes.subarray(4)).join(".")}`;
  if (bytes.length === 32) return `${binaryToIp(bytes.subarray(0, 16).toString("binary"))}/${binaryToIp(bytes.subarray(16).toString("binary"))}`;
  return binaryToIp(value);
}

function asn1ScalarValue(node: forge.asn1.Asn1): string {
  if (typeof node.value !== "string") return "";
  if (node.type === forge.asn1.Type.OID) return namedOid(forge.asn1.derToOid(node.value));
  if (node.type === forge.asn1.Type.UTF8 || node.type === forge.asn1.Type.PRINTABLESTRING || node.type === forge.asn1.Type.IA5STRING) return node.value;
  return hex(node.value);
}

function namedOid(oid: string): string {
  return OID_NAMES[oid] ? `${OID_NAMES[oid]} (${oid})` : oid;
}

function visitAsn1(node: forge.asn1.Asn1, visitor: (node: forge.asn1.Asn1) => void): void {
  visitor(node);
  if (Array.isArray(node.value)) {
    for (const child of node.value as forge.asn1.Asn1[]) visitAsn1(child, visitor);
  }
}

function hex(value: string): string {
  return `DER:${Buffer.from(value, "binary").toString("hex").toUpperCase()}`;
}

function parseAsn1Extensions(pem: string): ParsedExtension[] {
  try {
    const der = Buffer.from(pem.replace(/-----[^-]+-----/g, "").replace(/\s/g, ""), "base64").toString("binary");
    const cert = forge.asn1.fromDer(der);
    const tbs = Array.isArray(cert.value) ? cert.value[0] as forge.asn1.Asn1 : undefined;
    if (!tbs || !Array.isArray(tbs.value)) return [];
    const extensionsWrapper = (tbs.value as forge.asn1.Asn1[]).find(node => node.tagClass === forge.asn1.Class.CONTEXT_SPECIFIC && node.type === 3);
    const extensionsSeq = Array.isArray(extensionsWrapper?.value) ? extensionsWrapper.value[0] as forge.asn1.Asn1 : undefined;
    if (!extensionsSeq || !Array.isArray(extensionsSeq.value)) return [];
    return (extensionsSeq.value as forge.asn1.Asn1[]).map(parseAsn1Extension).filter((ext): ext is ParsedExtension => Boolean(ext));
  } catch {
    return [];
  }
}

function parseAsn1Extension(node: forge.asn1.Asn1): ParsedExtension | undefined {
  if (!Array.isArray(node.value) || node.value.length < 2) return undefined;
  const values = node.value as forge.asn1.Asn1[];
  const idNode = values[0];
  if (typeof idNode.value !== "string") return undefined;
  const id = forge.asn1.derToOid(idNode.value);
  let critical = false;
  let valueNode = values[1];
  if (valueNode.type === forge.asn1.Type.BOOLEAN) {
    critical = valueNode.value !== "\x00";
    valueNode = values[2];
  }
  if (!valueNode || typeof valueNode.value !== "string") return undefined;
  const ext: ParsedExtension = { id, name: extensionNameByOid(id) ?? OID_NAMES[id] ?? id, critical, value: valueNode.value } as ParsedExtension;
  enrichParsedExtension(ext);
  return ext;
}

function extensionNameByOid(id: string): string | undefined {
  return Object.entries(FORGE_EXTENSION_OIDS).find(([, oidValue]) => oidValue === id)?.[0];
}

function enrichParsedExtension(ext: ParsedExtension): void {
  const inner = typeof ext.value === "string" ? fromDer(ext.value) : undefined;
  if (!inner) return;
  if (ext.id === "2.5.29.19") enrichBasicConstraints(ext, inner);
  if (ext.id === "2.5.29.15") enrichKeyUsage(ext, inner);
  if (ext.id === "2.5.29.37") enrichExtendedKeyUsage(ext, inner);
  if (ext.id === "2.5.29.17" || ext.id === "2.5.29.18") enrichAltNames(ext, inner);
}

function enrichBasicConstraints(ext: ParsedExtension, inner: forge.asn1.Asn1): void {
  ext.name = "basicConstraints";
  if (!Array.isArray(inner.value)) return;
  for (const node of inner.value as forge.asn1.Asn1[]) {
    if (node.type === forge.asn1.Type.BOOLEAN) ext.cA = node.value !== "\x00";
    if (node.type === forge.asn1.Type.INTEGER && typeof node.value === "string") ext.pathLenConstraint = Buffer.from(node.value, "binary").readUIntBE(0, node.value.length);
  }
}

function enrichKeyUsage(ext: ParsedExtension, inner: forge.asn1.Asn1): void {
  ext.name = "keyUsage";
  if (typeof inner.value !== "string" || inner.value.length < 2) return;
  const bytes = Buffer.from(inner.value, "binary").subarray(1);
  const flags: Array<[string, number]> = [
    ["digitalSignature", 0], ["nonRepudiation", 1], ["keyEncipherment", 2], ["dataEncipherment", 3],
    ["keyAgreement", 4], ["keyCertSign", 5], ["cRLSign", 6], ["encipherOnly", 7], ["decipherOnly", 8],
  ];
  for (const [name, bit] of flags) {
    const byte = bytes[Math.floor(bit / 8)] ?? 0;
    ext[name] = Boolean(byte & (0x80 >> (bit % 8)));
  }
}

function enrichExtendedKeyUsage(ext: ParsedExtension, inner: forge.asn1.Asn1): void {
  ext.name = "extKeyUsage";
  if (!Array.isArray(inner.value)) return;
  for (const node of inner.value as forge.asn1.Asn1[]) {
    if (node.type === forge.asn1.Type.OID && typeof node.value === "string") {
      ext[forge.asn1.derToOid(node.value)] = true;
    }
  }
}

function enrichAltNames(ext: ParsedExtension, inner: forge.asn1.Asn1): void {
  ext.name = ext.id === "2.5.29.17" ? "subjectAltName" : "issuerAltName";
  if (!Array.isArray(inner.value)) return;
  ext.altNames = (inner.value as forge.asn1.Asn1[]).map(node => {
    const value = typeof node.value === "string" ? node.value : undefined;
    if (node.type === 7 && value) return { type: node.type, value, ip: binaryToIp(value) };
    return { type: node.type, value };
  });
}

function parseKeyUsage(extensions: ParsedExtension[]): string[] | undefined {
  const ext = extensions.find(e => e.id === "2.5.29.15" || e.name === "keyUsage") as Record<string, unknown> | undefined;
  if (!ext) return undefined;
  const names = ["digitalSignature", "nonRepudiation", "keyEncipherment", "dataEncipherment", "keyAgreement", "keyCertSign", "cRLSign", "encipherOnly", "decipherOnly"];
  return names.filter(name => ext[name] === true);
}

function parseBasicConstraints(extensions: ParsedExtension[]): { ca: boolean; pathLenConstraint?: number } | undefined {
  const ext = extensions.find(e => e.id === "2.5.29.19" || e.name === "basicConstraints") as Record<string, unknown> | undefined;
  if (!ext) return undefined;
  const result: { ca: boolean; pathLenConstraint?: number } = { ca: Boolean(ext.cA) };
  if (typeof ext.pathLenConstraint === "number") result.pathLenConstraint = ext.pathLenConstraint;
  return result;
}

function extensionValue(extensions: ParsedExtension[], oid: string): string | undefined {
  const ext = extensions.find(e => e.id === oid);
  return ext ? describeExtension(ext) : undefined;
}

function formatSerial(serial: string): string {
  // Node returns hex string, format as colon-separated pairs
  return (serial.length % 2 === 0 ? serial : "0" + serial)
    .match(/.{1,2}/g)!
    .join(":")
    .toUpperCase();
}
