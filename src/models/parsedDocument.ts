import { CertificateInfo } from "./certificate";

export interface CertificateDocument {
  type: "certificates";
  items: CertificateInfo[];
}

export interface CrlDocument {
  type: "crl";
  issuer: string;
  thisUpdate: string;
  nextUpdate: string;
  revokedCount: number;
  rawPem: string;
}

export interface ErrorDocument {
  type: "error";
  message: string;
  detail?: string;
}

export type ParsedDocument =
  | CertificateDocument
  | CrlDocument
  | ErrorDocument;
