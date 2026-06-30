export interface CertificateSubject {
  commonName?: string;
  organization?: string[];
  organizationalUnit?: string[];
  country?: string[];
  state?: string[];
  locality?: string[];
  emailAddress?: string[];
}

export interface CertificateValidity {
  notBefore: Date;
  notAfter: Date;
}

export interface SubjectAlternativeName {
  type: "dns" | "ip" | "email" | "uri" | "otherName" | "unknown";
  value: string;
}

export interface CertificateExtension {
  oid: string;
  name: string;
  critical: boolean;
  value: string;
}

export type CertificateFindingSeverity = "error" | "warning" | "info";

export interface CertificateFinding {
  severity: CertificateFindingSeverity;
  message: string;
  rfc?: string;
}

export interface CertificateInfo {
  /** Raw PEM string */
  pem: string;
  version: number;
  serialNumber: string;
  subject: CertificateSubject;
  issuer: CertificateSubject;
  validity: CertificateValidity;
  subjectAltNames: SubjectAlternativeName[];
  keyUsage: string[];
  extendedKeyUsage: string[];
  extensions: CertificateExtension[];
  basicConstraints?: {
    ca: boolean;
    pathLenConstraint?: number;
  };
  nameConstraints?: string;
  signatureAlgorithm: string;
  publicKeyAlgorithm: string;
  publicKeySize?: number;
  publicKeyCurve?: string;
  publicKeyExponent?: string;
  publicKeyPem?: string;
  fingerprints: {
    sha1: string;
    sha256: string;
  };
  isSelfSigned: boolean;
  isCA: boolean;
  findings: CertificateFinding[];
}

export type CertificateStatus = "valid" | "expiring-soon" | "expired" | "not-yet-valid";

export function getCertificateStatus(
  cert: CertificateInfo,
  warningDays: number = 30
): CertificateStatus {
  const now = new Date();
  if (now < cert.validity.notBefore) return "not-yet-valid";
  if (now > cert.validity.notAfter) return "expired";
  const daysUntilExpiry = Math.floor(
    (cert.validity.notAfter.getTime() - now.getTime()) / (1000 * 60 * 60 * 24)
  );
  if (daysUntilExpiry <= warningDays) return "expiring-soon";
  return "valid";
}

export function getDaysUntilExpiry(cert: CertificateInfo): number {
  return Math.floor(
    (cert.validity.notAfter.getTime() - Date.now()) / (1000 * 60 * 60 * 24)
  );
}
