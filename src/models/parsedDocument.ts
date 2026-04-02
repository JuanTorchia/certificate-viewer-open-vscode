import { CertificateInfo } from "./certificate";
import { CsrInfo } from "../parsers/csrParser";

export type ParsedDocumentType = "certificates" | "csr" | "crl" | "pkcs12" | "error";

export interface CertificateDocument {
  type: "certificates";
  items: CertificateInfo[];
}

export interface CsrDocument {
  type: "csr";
  items: CsrInfo[];
}

export interface CrlDocument {
  type: "crl";
  issuer: string;
  thisUpdate: string;
  nextUpdate: string;
  revokedCount: number;
  rawPem: string;
}

export interface Pkcs12Document {
  type: "pkcs12";
  items: CertificateInfo[];
}

export interface ErrorDocument {
  type: "error";
  message: string;
  detail?: string;
}

export type ParsedDocument =
  | CertificateDocument
  | CsrDocument
  | CrlDocument
  | Pkcs12Document
  | ErrorDocument;
