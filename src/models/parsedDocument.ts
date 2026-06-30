import { CertificateInfo } from "./certificate";
import { CsrInfo } from "../parsers/csrParser";
import { KeyInfo } from "../parsers/keyParser";

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
  signatureAlgorithm?: string;
  crlNumber?: string;
  authorityKeyIdentifier?: string;
  fingerprints?: {
    sha1: string;
    sha256: string;
  };
  rawPem: string;
}

export interface ErrorDocument {
  type: "error";
  message: string;
  detail?: string;
}

export interface KeyDocument {
  type: "keys";
  items: KeyInfo[];
}

export interface BundleDocument {
  type: "bundle";
  certificates: CertificateInfo[];
  keys: KeyInfo[];
}

export type ParsedDocument =
  | CertificateDocument
  | BundleDocument
  | CsrDocument
  | CrlDocument
  | KeyDocument
  | ErrorDocument;
