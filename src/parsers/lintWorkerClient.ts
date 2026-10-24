import { Worker } from "worker_threads";
import { ParsedDocument } from "../models/parsedDocument";

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
type LintRequestPayload = Omit<ParseRequest, "id"> | Omit<CertificateRequest, "id">;

interface LintResponse {
  id: number;
  document: ParsedDocument;
}

interface PendingRequest {
  resolve(document: ParsedDocument): void;
  reject(error: Error): void;
}

export class LintWorkerClient {
  private worker?: Worker;
  private nextId = 0;
  private disposed = false;
  private readonly pending = new Map<number, PendingRequest>();

  constructor(private readonly workerPath: string) {
    this.startWorker();
  }

  parse(raw: Uint8Array, filename: string): Promise<ParsedDocument> {
    return this.send({ kind: "parse", raw, filename });
  }

  parseCertificates(pems: string[], filename: string): Promise<ParsedDocument> {
    return this.send({ kind: "certificates", pems, filename });
  }

  private send(request: LintRequestPayload): Promise<ParsedDocument> {
    if (this.disposed) return Promise.reject(new Error("Lint worker client is disposed."));
    const worker = this.worker ?? this.startWorker();
    const id = ++this.nextId;
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      try {
        const message = request.kind === "parse" ? { ...request, raw: Uint8Array.from(request.raw) } : request;
        worker.postMessage({ id, ...message } satisfies LintRequest);
      } catch (error) {
        this.pending.delete(id);
        reject(error instanceof Error ? error : new Error(String(error)));
      }
    });
  }

  dispose(): void {
    if (this.disposed) return;
    this.disposed = true;
    const worker = this.worker;
    this.worker = undefined;
    this.rejectPending(new Error("Lint worker client disposed."));
    void worker?.terminate();
  }

  private startWorker(): Worker {
    const worker = new Worker(this.workerPath);
    this.worker = worker;
    worker.on("message", (response: LintResponse) => {
      const request = this.pending.get(response.id);
      if (!request) return;
      this.pending.delete(response.id);
      request.resolve(response.document);
    });
    worker.once("error", error => this.failWorker(worker, error));
    worker.once("exit", code => {
      if (this.worker === worker && !this.disposed) this.failWorker(worker, new Error(`Lint worker exited with code ${code}.`));
    });
    return worker;
  }

  private failWorker(worker: Worker, error: Error): void {
    if (this.worker !== worker) return;
    this.worker = undefined;
    this.rejectPending(error);
  }

  private rejectPending(error: Error): void {
    for (const request of this.pending.values()) request.reject(error);
    this.pending.clear();
  }
}
