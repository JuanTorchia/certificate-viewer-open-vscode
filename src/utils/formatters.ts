import { CertificateSubject } from "../models/certificate";

/**
 * Formats a Date to a human-readable string.
 */
export function formatDate(date: Date): string {
  return date.toLocaleString("en-US", {
    year: "numeric",
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    timeZoneName: "short",
  });
}

/**
 * Returns "X days" / "X hours" remaining or overdue.
 */
export function formatRelativeExpiry(date: Date): string {
  const diffMs = date.getTime() - Date.now();
  const absDays = Math.abs(Math.floor(diffMs / (1000 * 60 * 60 * 24)));
  const expired = diffMs < 0;

  if (absDays === 0) return expired ? "Expired today" : "Expires today";
  if (absDays === 1) return expired ? "Expired 1 day ago" : "Expires in 1 day";
  return expired ? `Expired ${absDays} days ago` : `Expires in ${absDays} days`;
}

/**
 * Converts a CertificateSubject to a display string like "CN=foo, O=bar".
 */
export function subjectToString(subject: CertificateSubject): string {
  const parts: string[] = [];
  if (subject.commonName) parts.push(`CN=${subject.commonName}`);
  if (subject.organization?.length) parts.push(`O=${subject.organization.join(", ")}`);
  if (subject.organizationalUnit?.length) parts.push(`OU=${subject.organizationalUnit.join(", ")}`);
  if (subject.country?.length) parts.push(`C=${subject.country.join(", ")}`);
  if (subject.state?.length) parts.push(`ST=${subject.state.join(", ")}`);
  if (subject.locality?.length) parts.push(`L=${subject.locality.join(", ")}`);
  return parts.join(", ");
}

/**
 * Returns a short display name for a certificate (CN or O or serial).
 */
export function getCertDisplayName(subject: CertificateSubject, serialNumber: string): string {
  return subject.commonName ?? subject.organization?.[0] ?? `Serial: ${serialNumber.slice(0, 12)}...`;
}
