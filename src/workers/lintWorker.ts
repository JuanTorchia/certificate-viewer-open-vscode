import * as path from "path";
import { parentPort } from "worker_threads";
import { ParsedDocument } from "../models/parsedDocument";
import { MAX_CERTIFICATES } from "../parsers/limits";
import { parseCertificateFile } from "../parsers/certParser";
import { parseDocument } from "../parsers/documentParser";

interface ParseRequest {
  id: number;
  kind: "parse";
  filename: string;
  raw: Uint8Array;
}

interface CertificateRequest {
  id: number;
  kind: "certificates";
  filename: string;
  pems: string[];
}

type LintRequest = ParseRequest | CertificateRequest;

if (!parentPort) throw new Error("Lint worker must run inside a worker thread.");

parentPort.on("message", (request: LintRequest) => {
  let document: ParsedDocument;
  try {
    if (request.kind === "parse") {
      document = parseDocument(Buffer.from(request.raw), request.filename);
    } else {
      if (request.pems.length > MAX_CERTIFICATES) throw new Error(`PKCS#12 file exceeds the maximum of ${MAX_CERTIFICATES} certificates.`);
      const items = request.pems.flatMap(pem => {
        try { return parseCertificateFile(pem); } catch { return []; }
      });
      document = { type: "certificates", items };
    }
  } catch (error) {
    document = {
      type: "error",
      message: `Failed to parse ${path.basename(request.filename)}`,
      detail: error instanceof Error ? error.message : String(error),
    };
  }
  parentPort?.postMessage({ id: request.id, document });
});
