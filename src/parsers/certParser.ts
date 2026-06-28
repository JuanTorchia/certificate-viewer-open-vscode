import * as crypto from "crypto";
import * as forge from "node-forge";
import {
  CertificateInfo,
  CertificateSubject,
  SubjectAlternativeName,
  CertificateExtension,
  CertificateFinding,
} from "../models/certificate";
import { derToPem, splitPemBlocks } from "./pemParser";
import { assertWithinInputLimit, MAX_CERTIFICATES } from "./limits";

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
  "1.3.6.1.5.5.7.3.13": "EAP over PPP",
  "1.3.6.1.5.5.7.3.14": "EAP over LAN",
  "1.3.6.1.5.5.7.3.17": "IPsec IKE",
  "1.3.6.1.5.5.7.3.21": "SSH Client",
  "1.3.6.1.5.5.7.3.22": "SSH Server",
  "1.3.6.1.5.5.7.3.36": "Document Signing",
  "1.3.6.1.4.1.311.10.3.4": "Encrypting File System",
  "1.3.6.1.4.1.311.10.3.12": "Document Signing",
  "1.3.6.1.4.1.311.20.2.2": "Smart Card Logon",
  "1.3.6.1.4.1.311.21.19": "Directory Service Email Replication",
  "2.5.29.37.0": "Any Extended Key Usage",
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

const OID_NAMES: Record<string, string> = {
  "2.5.4.3": "Common Name",
  "2.5.4.5": "Serial Number Attribute",
  "2.5.4.6": "Country Name",
  "2.5.4.7": "Locality Name",
  "2.5.4.8": "State or Province Name",
  "2.5.4.10": "Organization Name",
  "2.5.4.11": "Organizational Unit Name",
  "2.5.4.15": "Business Category",
  "2.5.4.17": "Postal Code",
  "2.5.4.97": "Organization Identifier",
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
  "1.2.840.113549.1.9.1": "Email Address",
  "1.2.840.113549.1.9.15": "S/MIME Capabilities",
  "1.2.840.113549.1.9.16.2.47": "Signing Certificate V2",
  "2.23.140.1.1": "CA/Browser Forum Domain Validated",
  "2.23.140.1.2.1": "CA/Browser Forum Organization Validated",
  "2.23.140.1.2.2": "CA/Browser Forum Individual Validated",
  "2.23.140.1.2.3": "CA/Browser Forum Extended Validated",
  "2.23.140.1.2.2.7": "CA/Browser Forum S/MIME Sponsor Validated",
  "2.23.140.1.2.2.8": "CA/Browser Forum S/MIME Mailbox Validated",
  "2.23.140.1.2.2.9": "CA/Browser Forum S/MIME Organization Validated",
  "2.23.140.1.2.2.10": "CA/Browser Forum S/MIME Individual Validated",
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
  const { algorithm, keySize } = getPublicKeyInfo(x509.publicKey);
  const extensions = buildExtensions(x509, parsedExtensions);
  const basicConstraints = parseBasicConstraints(parsedExtensions);
  const nameConstraints = extensionValue(parsedExtensions, "2.5.29.30");
  const signatureAlgorithm = getSignatureAlgorithm(x509, pem);
  const findings = validateCertificate(x509, subject, keyUsage, extendedKeyUsage, extensions, basicConstraints, algorithm, keySize, signatureAlgorithm);

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
    extensions,
    basicConstraints,
    nameConstraints,
    signatureAlgorithm,
    publicKeyAlgorithm: algorithm,
    publicKeySize: keySize,
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
      .map(([key]) => EXTENDED_KEY_USAGE_OID[key] ?? key);
    if (names.length) return names;
  }
  return nodeEkus.map(oid => EXTENDED_KEY_USAGE_OID[oid] ?? OID_NAMES[oid] ?? oid);
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

function getPublicKeyInfo(key: crypto.KeyObject): { algorithm: string; keySize?: number } {
  try {
    const type = (key.asymmetricKeyType ?? "unknown").toUpperCase();
    const details = key.asymmetricKeyDetails ?? {};
    const keySize = "modulusLength" in details ? (details.modulusLength as number) : undefined;
    const curve = "namedCurve" in details ? ` (${details.namedCurve})` : "";
    return { algorithm: type + curve, keySize };
  } catch {
    return { algorithm: "unknown" };
  }
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
  if (ext.name === "basicConstraints") {
    return `CA: ${Boolean(anyExt.cA)}${typeof anyExt.pathLenConstraint === "number" ? `, pathLen: ${anyExt.pathLenConstraint}` : ""}`;
  }
  if (ext.name === "keyUsage") {
    return Object.entries(anyExt).filter(([k, v]) => v === true && k !== "critical").map(([k]) => k).join(", ");
  }
  if (ext.name === "extKeyUsage") {
    return Object.entries(anyExt).filter(([k, v]) => v === true && k !== "critical").map(([k]) => EXTENDED_KEY_USAGE_OID[k] ?? k).join(", ");
  }
  if (ext.name === "subjectAltName" || ext.name === "issuerAltName") {
    const altNames = anyExt.altNames as Array<{ type?: number; value?: string; ip?: string }> | undefined;
    return altNames?.map(formatGeneralName).join(", ") ?? "";
  }
  if (ext.name === "subjectKeyIdentifier" && typeof anyExt.subjectKeyIdentifier === "string") {
    return anyExt.subjectKeyIdentifier.toUpperCase();
  }
  if (ext.name === "nameConstraints") {
    return describeNameConstraints(ext.value);
  }
  if (ext.name === "cRLDistributionPoints") {
    return describeUris(ext.value, "URI");
  }
  if (ext.name === "authorityInfoAccess") {
    return describeAuthorityInfoAccess(ext.value);
  }
  if (ext.name === "certificatePolicies") {
    return describeCertificatePolicies(ext.value);
  }
  if (String(anyExt.id) === "1.3.6.1.5.5.7.1.24") {
    return describeTlsFeatures(ext.value);
  }
  if (String(anyExt.id) === "1.3.6.1.4.1.11129.2.4.2") {
    return describeSignedCertificateTimestamps(ext.value);
  }
  if (ext.value) return describeDerValue(ext.value);
  return JSON.stringify(anyExt, (_key, value) => typeof value === "string" && value.length > 256 ? `${value.slice(0, 256)}…` : value);
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
    const bytes = Buffer.from(value, "binary");
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
  const timestamp = timestampToIso(sct.readBigUInt64BE(33));
  if (!timestamp) return `SCT ${index}: malformed timestamp`;
  const extensionsLengthOffset = 41;
  const extensionsLength = sct.readUInt16BE(extensionsLengthOffset);
  const sigOffset = extensionsLengthOffset + 2 + extensionsLength;
  if (sigOffset + 4 > sct.length) return `SCT ${index}: malformed extensions`;
  const signatureLength = sct.readUInt16BE(sigOffset + 2);
  if (sigOffset + 4 + signatureLength !== sct.length) return `SCT ${index}: malformed signature`;
  const sigAlg = signatureSchemeName(sct[sigOffset], sct[sigOffset + 1]);
  return `SCT ${index}: ${version}, logID ${logId}, timestamp ${timestamp}, ${sigAlg}`;
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
  if (node.type === forge.asn1.Type.OID) return forge.asn1.derToOid(node.value);
  if (node.type === forge.asn1.Type.UTF8 || node.type === forge.asn1.Type.PRINTABLESTRING || node.type === forge.asn1.Type.IA5STRING) return node.value;
  return hex(node.value);
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
  const ext: ParsedExtension = { id, name: OID_NAMES[id] ?? extensionNameByOid(id), critical, value: valueNode.value } as ParsedExtension;
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

function validateCertificate(
  x509: crypto.X509Certificate,
  subject: CertificateSubject,
  keyUsage: string[],
  extendedKeyUsage: string[],
  extensions: CertificateExtension[],
  basicConstraints: { ca: boolean; pathLenConstraint?: number } | undefined,
  publicKeyAlgorithm: string,
  publicKeySize: number | undefined,
  signatureAlgorithm: string
): CertificateFinding[] {
  const findings: CertificateFinding[] = [];
  const now = Date.now();
  const serialBytes = Buffer.from(x509.serialNumber.length % 2 ? `0${x509.serialNumber}` : x509.serialNumber, "hex");
  const subjectEmpty = Object.values(subject).every(value => value === undefined || (Array.isArray(value) && value.length === 0));
  const sanExtension = extensionByOid(extensions, "2.5.29.17");
  const basicConstraintsExtension = extensionByOid(extensions, "2.5.29.19");
  const nameConstraintsExtension = extensionByOid(extensions, "2.5.29.30");
  const aiaExtension = extensionByOid(extensions, "1.3.6.1.5.5.7.1.1");
  const crlDistributionPointsExtension = extensionByOid(extensions, "2.5.29.31");
  const freshestCrlExtension = extensionByOid(extensions, "2.5.29.46");
  const duplicateOids = duplicateExtensionOids(extensions);

  if (!x509.serialNumber || serialBytes.length === 0) findings.push({ severity: "error", message: "Certificate serial number is empty.", rfc: "RFC 5280 §4.1.2.2" });
  if (serialBytes.length > 20) findings.push({ severity: "warning", message: `Certificate serial number is ${serialBytes.length} octets; conforming CAs must not use serial numbers longer than 20 octets.`, rfc: "RFC 5280 §4.1.2.2" });
  if (new Date(x509.validTo).getTime() < now) findings.push({ severity: "error", message: "Certificate is expired.", rfc: "RFC 5280 §4.1.2.5" });
  if (new Date(x509.validFrom).getTime() > now) findings.push({ severity: "error", message: "Certificate is not yet valid.", rfc: "RFC 5280 §4.1.2.5" });
  if (new Date(x509.validFrom).getTime() > new Date(x509.validTo).getTime()) findings.push({ severity: "error", message: "Certificate notBefore is after notAfter.", rfc: "RFC 5280 §4.1.2.5" });
  if (!subject.commonName && !x509.subjectAltName) findings.push({ severity: "warning", message: "Certificate has neither subject CN nor SAN.", rfc: "RFC 5280 §4.1.2.6, §4.2.1.6" });
  if (subjectEmpty && !sanExtension) findings.push({ severity: "error", message: "Certificate subject is empty but subjectAltName is absent.", rfc: "RFC 5280 §4.1.2.6, §4.2.1.6" });
  if (subjectEmpty && sanExtension && !sanExtension.critical) findings.push({ severity: "error", message: "subjectAltName must be critical when the subject distinguished name is empty.", rfc: "RFC 5280 §4.2.1.6" });
  if (!subjectEmpty && sanExtension?.critical) findings.push({ severity: "warning", message: "subjectAltName should be noncritical when the subject distinguished name is present.", rfc: "RFC 5280 §4.2.1.6" });
  if (safeCA(x509) && !basicConstraints?.ca) findings.push({ severity: "error", message: "Certificate is treated as a CA but Basic Constraints CA=true was not decoded.", rfc: "RFC 5280 §4.2.1.9" });
  if (basicConstraints?.ca && !basicConstraintsExtension?.critical) findings.push({ severity: "warning", message: "CA Basic Constraints should be marked critical.", rfc: "RFC 5280 §4.2.1.9" });
  if (basicConstraints && !basicConstraints.ca && basicConstraints.pathLenConstraint !== undefined) findings.push({ severity: "error", message: "Basic Constraints pathLenConstraint is present while CA=false.", rfc: "RFC 5280 §4.2.1.9" });
  if (basicConstraints?.pathLenConstraint !== undefined && !keyUsage.includes("keyCertSign")) findings.push({ severity: "warning", message: "Basic Constraints pathLenConstraint is present but keyCertSign is not asserted.", rfc: "RFC 5280 §4.2.1.9" });
  if (basicConstraints?.ca && !keyUsage.includes("keyCertSign")) findings.push({ severity: "warning", message: "CA certificate lacks keyCertSign key usage.", rfc: "RFC 5280 §4.2.1.3, §4.2.1.9" });
  if (!basicConstraints?.ca && keyUsage.includes("keyCertSign")) findings.push({ severity: "warning", message: "End-entity certificate includes keyCertSign.", rfc: "RFC 5280 §4.2.1.3" });
  if (keyUsage.includes("encipherOnly") && !keyUsage.includes("keyAgreement")) findings.push({ severity: "error", message: "encipherOnly is meaningful only when keyAgreement is asserted.", rfc: "RFC 5280 §4.2.1.3" });
  if (keyUsage.includes("decipherOnly") && !keyUsage.includes("keyAgreement")) findings.push({ severity: "error", message: "decipherOnly is meaningful only when keyAgreement is asserted.", rfc: "RFC 5280 §4.2.1.3" });
  if (extendedKeyUsage.includes("Any Extended Key Usage") && extendedKeyUsage.length > 1) findings.push({ severity: "warning", message: "anyExtendedKeyUsage appears with specific extended key usages.", rfc: "RFC 5280 §4.2.1.12" });
  if (nameConstraintsExtension && !nameConstraintsExtension.critical) findings.push({ severity: "error", message: "Name Constraints must be marked critical.", rfc: "RFC 5280 §4.2.1.10" });
  if (nameConstraintsExtension && !basicConstraints?.ca) findings.push({ severity: "warning", message: "Name Constraints is present on a certificate that is not marked as a CA.", rfc: "RFC 5280 §4.2.1.10" });
  if (aiaExtension?.critical) findings.push({ severity: "error", message: "Authority Information Access must be noncritical.", rfc: "RFC 5280 §4.2.2.1" });
  if (crlDistributionPointsExtension?.critical) findings.push({ severity: "warning", message: "CRL Distribution Points should be noncritical.", rfc: "RFC 5280 §4.2.1.13" });
  if (freshestCrlExtension?.critical) findings.push({ severity: "error", message: "Freshest CRL must be noncritical.", rfc: "RFC 5280 §4.2.1.15" });
  if (hasServerAuth(extendedKeyUsage) && !x509.subjectAltName) findings.push({ severity: "warning", message: "TLS server certificate should include DNS/IP subjectAltName.", rfc: "RFC 6125 §6.4.4" });
  if (/MD5|SHA1|SHA-1/i.test(signatureAlgorithm)) findings.push({ severity: "warning", message: `Weak signature algorithm: ${signatureAlgorithm}.`, rfc: "RFC 5280 §4.1.1.2" });
  if (publicKeyAlgorithm.startsWith("RSA") && publicKeySize !== undefined && publicKeySize < 2048) findings.push({ severity: "warning", message: `RSA public key is ${publicKeySize} bits; 2048 bits or larger is recommended.`, rfc: "NIST SP 800-131A" });
  for (const oid of duplicateOids) {
    findings.push({ severity: "error", message: `Duplicate extension OID ${oid}.`, rfc: "RFC 5280 §4.2" });
  }
  for (const ext of extensions) {
    if (ext.oid === "unknown") findings.push({ severity: "info", message: `Unrecognized extension: ${ext.name}.`, rfc: "RFC 5280 §4.2" });
    if (ext.critical && ext.name === ext.oid) findings.push({ severity: "warning", message: `Critical extension ${ext.oid} is not decoded by name; relying parties must understand it.`, rfc: "RFC 5280 §4.2" });
  }
  return findings;
}

function hasServerAuth(extendedKeyUsage: string[]): boolean {
  return extendedKeyUsage.includes("serverAuth") || extendedKeyUsage.includes("TLS Web Server Authentication");
}

function extensionByOid(extensions: CertificateExtension[], oid: string): CertificateExtension | undefined {
  return extensions.find(ext => ext.oid === oid);
}

function duplicateExtensionOids(extensions: CertificateExtension[]): string[] {
  const counts = new Map<string, number>();
  for (const ext of extensions) counts.set(ext.oid, (counts.get(ext.oid) ?? 0) + 1);
  return Array.from(counts.entries()).filter(([oid, count]) => oid !== "unknown" && count > 1).map(([oid]) => oid);
}

function addChainFindings(certs: CertificateInfo[]): void {
  if (certs.length < 2) return;
  for (let i = 0; i < certs.length - 1; i++) {
    const child = certs[i];
    const issuer = certs[i + 1];
    if (!samePrincipal(child.issuer, issuer.subject)) {
      child.findings.push({ severity: "warning", message: "Next certificate subject does not match this certificate issuer.", rfc: "RFC 5280 §6" });
    }
    if (!issuer.isCA) {
      child.findings.push({ severity: "error", message: "Issuer certificate is not marked as a CA.", rfc: "RFC 5280 §4.2.1.9, §6" });
    }
    if (!issuer.keyUsage.includes("keyCertSign")) {
      child.findings.push({ severity: "warning", message: "Issuer certificate lacks keyCertSign key usage.", rfc: "RFC 5280 §4.2.1.3, §6" });
    }
    if (child.validity.notBefore < issuer.validity.notBefore || child.validity.notAfter > issuer.validity.notAfter) {
      child.findings.push({ severity: "warning", message: "Certificate validity is not fully nested within issuer validity.", rfc: "RFC 5280 §6" });
    }
  }
  for (let i = 1; i < certs.length; i++) {
    const issuer = certs[i];
    const pathLenConstraint = issuer.basicConstraints?.pathLenConstraint;
    if (pathLenConstraint === undefined) continue;
    const subordinateCaCount = certs.slice(0, i).filter(cert => cert.isCA).length;
    if (subordinateCaCount > pathLenConstraint) {
      issuer.findings.push({ severity: "error", message: `Path length constraint ${pathLenConstraint} is exceeded by ${subordinateCaCount} subordinate CA certificate(s).`, rfc: "RFC 5280 §4.2.1.9, §6" });
    }
  }
}

function samePrincipal(a: CertificateSubject, b: CertificateSubject): boolean {
  return JSON.stringify(normalizeSubject(a)) === JSON.stringify(normalizeSubject(b));
}

function normalizeSubject(subject: CertificateSubject): Record<string, string | string[]> {
  return {
    commonName: subject.commonName ?? "",
    organization: subject.organization ?? [],
    organizationalUnit: subject.organizationalUnit ?? [],
    country: subject.country ?? [],
    state: subject.state ?? [],
    locality: subject.locality ?? [],
    emailAddress: subject.emailAddress ?? [],
  };
}

function safeCA(x509: crypto.X509Certificate): boolean {
  try { return x509.ca; } catch { return false; }
}

function formatSerial(serial: string): string {
  // Node returns hex string, format as colon-separated pairs
  return (serial.length % 2 === 0 ? serial : "0" + serial)
    .match(/.{1,2}/g)!
    .join(":")
    .toUpperCase();
}
