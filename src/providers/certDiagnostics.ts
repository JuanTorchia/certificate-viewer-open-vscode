import * as path from "path";
import * as vscode from "vscode";
import { CertificateFinding, CertificateFindingSeverity } from "../models/certificate";
import { ParsedDocument } from "../models/parsedDocument";
import { parseDocument } from "../parsers/documentParser";

const SUPPORTED_EXTENSIONS = new Set([
  ".pem", ".cer", ".crt", ".der", ".crl", ".p7b", ".p7c", ".p7", ".csr", ".p12", ".pfx", ".key", ".pub", ".jwk",
]);
const LIVE_DIAGNOSTICS_MAX_BYTES = 1024 * 1024;
const DIAGNOSTIC_DEBOUNCE_MS = 500;

export class CertDiagnosticsProvider implements vscode.Disposable {
  private readonly collection = vscode.languages.createDiagnosticCollection("certview");
  private readonly disposables: vscode.Disposable[] = [];
  private readonly timers = new Map<string, NodeJS.Timeout>();

  constructor() {
    this.disposables.push(
      this.collection,
      vscode.workspace.onDidOpenTextDocument(doc => { void this.updateTextDocument(doc); }),
      vscode.workspace.onDidSaveTextDocument(doc => { void this.updateTextDocument(doc); }),
      vscode.workspace.onDidChangeTextDocument(event => this.scheduleTextDocumentUpdate(event.document)),
      vscode.workspace.onDidCloseTextDocument(doc => {
        this.clearTimer(doc.uri);
        this.collection.delete(doc.uri);
      })
    );

    for (const doc of vscode.workspace.textDocuments) {
      void this.updateTextDocument(doc);
    }
  }

  async updateUri(uri: vscode.Uri): Promise<void> {
    if (!isSupportedUri(uri)) return;
    try {
      const raw = await vscode.workspace.fs.readFile(uri);
      this.setDiagnostics(uri, parseDocument(raw, uri.fsPath));
    } catch (error) {
      this.collection.set(uri, [diagnosticFromError(error)]);
    }
  }

  dispose(): void {
    for (const timer of this.timers.values()) clearTimeout(timer);
    this.timers.clear();
    for (const disposable of this.disposables) disposable.dispose();
  }

  setParsedDiagnostics(uri: vscode.Uri, parsed: ParsedDocument): void {
    if (!isSupportedUri(uri)) return;
    this.setDiagnostics(uri, parsed);
  }

  private scheduleTextDocumentUpdate(doc: vscode.TextDocument): void {
    if (!isSupportedUri(doc.uri) || doc.isUntitled) return;
    const key = doc.uri.toString();
    this.clearTimer(doc.uri);
    const version = doc.version;
    const timer = setTimeout(() => {
      this.timers.delete(key);
      if (doc.version !== version) return;
      void this.updateTextDocument(doc, version);
    }, DIAGNOSTIC_DEBOUNCE_MS);
    this.timers.set(key, timer);
  }

  private async updateTextDocument(doc: vscode.TextDocument, version?: number): Promise<void> {
    if (!isSupportedUri(doc.uri)) return;
    if (doc.isUntitled) return;
    try {
      if (version !== undefined && doc.version !== version) return;
      const text = doc.getText();
      if (Buffer.byteLength(text, "utf8") > LIVE_DIAGNOSTICS_MAX_BYTES) {
        const diagnostic = new vscode.Diagnostic(new vscode.Range(0, 0, 0, 1), "CertView live diagnostics skipped for files larger than 1 MiB; open the certificate viewer to parse with full limits.", vscode.DiagnosticSeverity.Information);
        diagnostic.source = "CertView";
        this.collection.set(doc.uri, [diagnostic]);
        return;
      }
      const raw = Buffer.from(text, "utf8");
      if (version !== undefined && doc.version !== version) return;
      this.setDiagnostics(doc.uri, parseDocument(raw, doc.uri.fsPath));
    } catch (error) {
      this.collection.set(doc.uri, [diagnosticFromError(error)]);
    }
  }

  private clearTimer(uri: vscode.Uri): void {
    const key = uri.toString();
    const existing = this.timers.get(key);
    if (existing) clearTimeout(existing);
    this.timers.delete(key);
  }

  private setDiagnostics(uri: vscode.Uri, parsed: ParsedDocument): void {
    if (parsed.type === "certificates" || parsed.type === "bundle") {
      const certs = parsed.type === "certificates" ? parsed.items : parsed.certificates;
      this.collection.set(uri, certs.flatMap((cert, certIndex) =>
        cert.findings.map(finding => diagnosticFromFinding(finding, certIndex, cert.subject.commonName ?? cert.serialNumber))
      ));
      return;
    }

    if (parsed.type === "error") {
      this.collection.set(uri, [new vscode.Diagnostic(new vscode.Range(0, 0, 0, 1), parsed.detail ?? parsed.message, vscode.DiagnosticSeverity.Error)]);
      return;
    }

    this.collection.delete(uri);
  }
}

function isSupportedUri(uri: vscode.Uri): boolean {
  return uri.scheme === "file" && SUPPORTED_EXTENSIONS.has(path.extname(uri.fsPath).toLowerCase());
}

function diagnosticFromFinding(finding: CertificateFinding, certIndex: number, label: string): vscode.Diagnostic {
  const diagnostic = new vscode.Diagnostic(
    new vscode.Range(0, 0, 0, 1),
    `Certificate ${certIndex + 1} (${label}): ${finding.message}${finding.rfc ? ` (${finding.rfc})` : ""}`,
    diagnosticSeverity(finding.severity)
  );
  diagnostic.source = "CertView";
  diagnostic.code = finding.rfc;
  return diagnostic;
}

function diagnosticFromError(error: unknown): vscode.Diagnostic {
  const diagnostic = new vscode.Diagnostic(
    new vscode.Range(0, 0, 0, 1),
    error instanceof Error ? error.message : String(error),
    vscode.DiagnosticSeverity.Error
  );
  diagnostic.source = "CertView";
  return diagnostic;
}

function diagnosticSeverity(severity: CertificateFindingSeverity): vscode.DiagnosticSeverity {
  switch (severity) {
    case "error": return vscode.DiagnosticSeverity.Error;
    case "warning": return vscode.DiagnosticSeverity.Warning;
    case "info": return vscode.DiagnosticSeverity.Information;
  }
}
