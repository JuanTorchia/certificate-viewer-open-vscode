import * as crypto from "crypto";
import { CertificateExtension, CertificateFinding, CertificateInfo, CertificateSubject } from "../models/certificate";

export interface CertificateLintInput {
  x509: crypto.X509Certificate;
  subject: CertificateSubject;
  keyUsage: string[];
  extendedKeyUsage: string[];
  extensions: CertificateExtension[];
  basicConstraints?: { ca: boolean; pathLenConstraint?: number };
  publicKeyAlgorithm: string;
  publicKeySize?: number;
  signatureAlgorithm: string;
}

export function validateCertificate(input: CertificateLintInput): CertificateFinding[] {
  const findings: CertificateFinding[] = [];
  const now = Date.now();
  const serialBytes = Buffer.from(input.x509.serialNumber.length % 2 ? `0${input.x509.serialNumber}` : input.x509.serialNumber, "hex");
  const subjectEmpty = Object.values(input.subject).every(value => value === undefined || (Array.isArray(value) && value.length === 0));
  const sanExtension = extensionByOid(input.extensions, "2.5.29.17");
  const basicConstraintsExtension = extensionByOid(input.extensions, "2.5.29.19");
  const nameConstraintsExtension = extensionByOid(input.extensions, "2.5.29.30");
  const aiaExtension = extensionByOid(input.extensions, "1.3.6.1.5.5.7.1.1");
  const crlDistributionPointsExtension = extensionByOid(input.extensions, "2.5.29.31");
  const freshestCrlExtension = extensionByOid(input.extensions, "2.5.29.46");

  if (!input.x509.serialNumber || serialBytes.length === 0) findings.push({ severity: "error", message: "Certificate serial number is empty.", rfc: "RFC 5280 §4.1.2.2" });
  if (serialBytes.length > 20) findings.push({ severity: "warning", message: `Certificate serial number is ${serialBytes.length} octets; conforming CAs must not use serial numbers longer than 20 octets.`, rfc: "RFC 5280 §4.1.2.2" });
  if (new Date(input.x509.validTo).getTime() < now) findings.push({ severity: "error", message: "Certificate is expired.", rfc: "RFC 5280 §4.1.2.5" });
  if (new Date(input.x509.validFrom).getTime() > now) findings.push({ severity: "error", message: "Certificate is not yet valid.", rfc: "RFC 5280 §4.1.2.5" });
  if (new Date(input.x509.validFrom).getTime() > new Date(input.x509.validTo).getTime()) findings.push({ severity: "error", message: "Certificate notBefore is after notAfter.", rfc: "RFC 5280 §4.1.2.5" });
  if (!input.subject.commonName && !input.x509.subjectAltName) findings.push({ severity: "warning", message: "Certificate has neither subject CN nor SAN.", rfc: "RFC 5280 §4.1.2.6, §4.2.1.6" });
  if (subjectEmpty && !sanExtension) findings.push({ severity: "error", message: "Certificate subject is empty but subjectAltName is absent.", rfc: "RFC 5280 §4.1.2.6, §4.2.1.6" });
  if (subjectEmpty && sanExtension && !sanExtension.critical) findings.push({ severity: "error", message: "subjectAltName must be critical when the subject distinguished name is empty.", rfc: "RFC 5280 §4.2.1.6" });
  if (!subjectEmpty && sanExtension?.critical) findings.push({ severity: "warning", message: "subjectAltName should be noncritical when the subject distinguished name is present.", rfc: "RFC 5280 §4.2.1.6" });
  if (safeCA(input.x509) && !input.basicConstraints?.ca) findings.push({ severity: "error", message: "Certificate is treated as a CA but Basic Constraints CA=true was not decoded.", rfc: "RFC 5280 §4.2.1.9" });
  if (input.basicConstraints?.ca && !basicConstraintsExtension?.critical) findings.push({ severity: "warning", message: "CA Basic Constraints should be marked critical.", rfc: "RFC 5280 §4.2.1.9" });
  if (input.basicConstraints && !input.basicConstraints.ca && input.basicConstraints.pathLenConstraint !== undefined) findings.push({ severity: "error", message: "Basic Constraints pathLenConstraint is present while CA=false.", rfc: "RFC 5280 §4.2.1.9" });
  if (input.basicConstraints?.pathLenConstraint !== undefined && !input.keyUsage.includes("keyCertSign")) findings.push({ severity: "warning", message: "Basic Constraints pathLenConstraint is present but keyCertSign is not asserted.", rfc: "RFC 5280 §4.2.1.9" });
  if (input.basicConstraints?.ca && !input.keyUsage.includes("keyCertSign")) findings.push({ severity: "warning", message: "CA certificate lacks keyCertSign key usage.", rfc: "RFC 5280 §4.2.1.3, §4.2.1.9" });
  if (!input.basicConstraints?.ca && input.keyUsage.includes("keyCertSign")) findings.push({ severity: "warning", message: "End-entity certificate includes keyCertSign.", rfc: "RFC 5280 §4.2.1.3" });
  if (input.keyUsage.includes("encipherOnly") && !input.keyUsage.includes("keyAgreement")) findings.push({ severity: "error", message: "encipherOnly is meaningful only when keyAgreement is asserted.", rfc: "RFC 5280 §4.2.1.3" });
  if (input.keyUsage.includes("decipherOnly") && !input.keyUsage.includes("keyAgreement")) findings.push({ severity: "error", message: "decipherOnly is meaningful only when keyAgreement is asserted.", rfc: "RFC 5280 §4.2.1.3" });
  if (input.extendedKeyUsage.includes("Any Extended Key Usage") && input.extendedKeyUsage.length > 1) findings.push({ severity: "warning", message: "anyExtendedKeyUsage appears with specific extended key usages.", rfc: "RFC 5280 §4.2.1.12" });
  if (nameConstraintsExtension && !nameConstraintsExtension.critical) findings.push({ severity: "error", message: "Name Constraints must be marked critical.", rfc: "RFC 5280 §4.2.1.10" });
  if (nameConstraintsExtension && !input.basicConstraints?.ca) findings.push({ severity: "warning", message: "Name Constraints is present on a certificate that is not marked as a CA.", rfc: "RFC 5280 §4.2.1.10" });
  if (aiaExtension?.critical) findings.push({ severity: "error", message: "Authority Information Access must be noncritical.", rfc: "RFC 5280 §4.2.2.1" });
  if (crlDistributionPointsExtension?.critical) findings.push({ severity: "warning", message: "CRL Distribution Points should be noncritical.", rfc: "RFC 5280 §4.2.1.13" });
  if (freshestCrlExtension?.critical) findings.push({ severity: "error", message: "Freshest CRL must be noncritical.", rfc: "RFC 5280 §4.2.1.15" });
  if (hasServerAuth(input.extendedKeyUsage) && !input.x509.subjectAltName) findings.push({ severity: "warning", message: "TLS server certificate should include DNS/IP subjectAltName.", rfc: "RFC 6125 §6.4.4" });
  if (/MD5|SHA1|SHA-1/i.test(input.signatureAlgorithm)) findings.push({ severity: "warning", message: `Weak signature algorithm: ${input.signatureAlgorithm}.`, rfc: "RFC 5280 §4.1.1.2" });
  if (input.publicKeyAlgorithm.startsWith("RSA") && input.publicKeySize !== undefined && input.publicKeySize < 2048) findings.push({ severity: "warning", message: `RSA public key is ${input.publicKeySize} bits; 2048 bits or larger is recommended.`, rfc: "NIST SP 800-131A" });
  for (const oid of duplicateExtensionOids(input.extensions)) findings.push({ severity: "error", message: `Duplicate extension OID ${oid}.`, rfc: "RFC 5280 §4.2" });
  for (const ext of input.extensions) {
    if (ext.oid === "unknown") findings.push({ severity: "info", message: `Unrecognized extension: ${ext.name}.`, rfc: "RFC 5280 §4.2" });
    if (ext.critical && ext.name === ext.oid) findings.push({ severity: "warning", message: `Critical extension ${ext.oid} is not decoded by name; relying parties must understand it.`, rfc: "RFC 5280 §4.2" });
  }
  return findings;
}

export function addChainFindings(certs: CertificateInfo[]): void {
  if (certs.length < 2) return;
  for (let i = 0; i < certs.length - 1; i++) {
    const child = certs[i];
    const issuer = certs[i + 1];
    if (!samePrincipal(child.issuer, issuer.subject)) child.findings.push({ severity: "warning", message: "Next certificate subject does not match this certificate issuer.", rfc: "RFC 5280 §6" });
    if (!issuer.isCA) child.findings.push({ severity: "error", message: "Issuer certificate is not marked as a CA.", rfc: "RFC 5280 §4.2.1.9, §6" });
    if (!issuer.keyUsage.includes("keyCertSign")) child.findings.push({ severity: "warning", message: "Issuer certificate lacks keyCertSign key usage.", rfc: "RFC 5280 §4.2.1.3, §6" });
    if (child.validity.notBefore < issuer.validity.notBefore || child.validity.notAfter > issuer.validity.notAfter) child.findings.push({ severity: "warning", message: "Certificate validity is not fully nested within issuer validity.", rfc: "RFC 5280 §6" });
  }
  for (let i = 1; i < certs.length; i++) {
    const issuer = certs[i];
    const pathLenConstraint = issuer.basicConstraints?.pathLenConstraint;
    if (pathLenConstraint === undefined) continue;
    const subordinateCaCount = certs.slice(0, i).filter(cert => cert.isCA).length;
    if (subordinateCaCount > pathLenConstraint) issuer.findings.push({ severity: "error", message: `Path length constraint ${pathLenConstraint} is exceeded by ${subordinateCaCount} subordinate CA certificate(s).`, rfc: "RFC 5280 §4.2.1.9, §6" });
  }
}

export function safeCA(x509: crypto.X509Certificate): boolean {
  try { return x509.ca; } catch { return false; }
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
