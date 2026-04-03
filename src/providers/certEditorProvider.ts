import * as vscode from "vscode";
import * as path from "path";
import { parseCertificateFile } from "../parsers/certParser";
import { parseCsrFile } from "../parsers/csrParser";
import { extractCertsFromPkcs7 } from "../parsers/pkcs7Parser";
import { splitPemBlocks, isPemContent, isDerBuffer, detectFormat } from "../parsers/pemParser";
import { ParsedDocument } from "../models/parsedDocument";
import { buildWebviewHtml } from "../views/certWebview";

export class CertEditorProvider implements vscode.CustomReadonlyEditorProvider {
  public static readonly viewType = "certview.certEditor";

  constructor(private readonly context: vscode.ExtensionContext) {}

  public static register(context: vscode.ExtensionContext): vscode.Disposable {
    return vscode.window.registerCustomEditorProvider(
      CertEditorProvider.viewType,
      new CertEditorProvider(context),
      {
        webviewOptions: { retainContextWhenHidden: true },
        supportsMultipleEditorsPerDocument: false,
      }
    );
  }

  async openCustomDocument(
    uri: vscode.Uri,
    _openContext: vscode.CustomDocumentOpenContext,
    _token: vscode.CancellationToken
  ): Promise<vscode.CustomDocument> {
    return { uri, dispose: () => {} };
  }

  async resolveCustomEditor(
    document: vscode.CustomDocument,
    webviewPanel: vscode.WebviewPanel,
    _token: vscode.CancellationToken
  ): Promise<void> {
    webviewPanel.webview.options = { enableScripts: true };

    const config = vscode.workspace.getConfiguration("certview");
    const warningDays: number = config.get("warningDaysBeforeExpiry", 30);

    const parsed = await this.parseFile(document.uri);
    webviewPanel.webview.html = buildWebviewHtml(
      webviewPanel.webview,
      this.context.extensionUri,
      parsed,
      warningDays
    );

    webviewPanel.webview.onDidReceiveMessage(async (msg: { command: string; data?: string }) => {
      switch (msg.command) {
        case "copyText":
          if (msg.data) {
            await vscode.env.clipboard.writeText(msg.data);
            vscode.window.showInformationMessage("Copied to clipboard.");
          }
          break;
        case "openRaw":
          await vscode.commands.executeCommand("vscode.openWith", document.uri, "default");
          break;
      }
    });
  }

  private async parseFile(uri: vscode.Uri): Promise<ParsedDocument> {
    const raw = await vscode.workspace.fs.readFile(uri);
    const ext = path.extname(uri.fsPath).toLowerCase();

    try {
      // Text-based formats
      if (ext !== ".der" && !isDerBuffer(raw)) {
        const text = Buffer.from(raw).toString("utf-8");

        if (!isPemContent(text)) {
          // Some .cer files are actually DER despite the extension
          return this.parseDer(raw);
        }

        const format = detectFormat(text, ext);

        if (format === "CERTIFICATE REQUEST" || format === "NEW CERTIFICATE REQUEST") {
          return { type: "csr", items: parseCsrFile(text) };
        }

        if (format === "PKCS7") {
          return this.parsePkcs7Pem(text);
        }

        if (format === "X509 CRL") {
          return this.parseCrlPem(text);
        }

        // Default: CERTIFICATE (or try anyway)
        return { type: "certificates", items: parseCertificateFile(text) };
      }

      // Binary DER — could be a plain cert or a DER-encoded PKCS#7
      if (ext === ".p7b" || ext === ".p7c" || ext === ".p7") {
        return this.parsePkcs7Der(raw);
      }
      return this.parseDer(raw);

    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      const stack = err instanceof Error ? err.stack ?? "" : "";
      return {
        type: "error",
        message: `Failed to parse ${path.basename(uri.fsPath)}`,
        detail: message + (stack ? `\n\n${stack.split("\n").slice(0, 5).join("\n")}` : ""),
      };
    }
  }

  private parseDer(raw: Uint8Array): ParsedDocument {
    // DER could be a certificate, CRL, CSR — try certificate first
    try {
      return { type: "certificates", items: parseCertificateFile(raw) };
    } catch {
      return { type: "error", message: "Unable to parse DER file.", detail: "Not a recognized ASN.1 structure (certificate, CRL, or CSR)." };
    }
  }

  private parsePkcs7Pem(text: string): ParsedDocument {
    const pems = extractCertsFromPkcs7(text);

    if (pems.length === 0) {
      return {
        type: "error",
        message: "PKCS#7 container: no certificates found",
        detail: "The PKCS#7 structure did not contain any embedded X.509 certificates.",
      };
    }

    const items = parseCertificateFile(pems.join("\n"));
    return { type: "certificates", items };
  }

  private parsePkcs7Der(raw: Uint8Array): ParsedDocument {
    const pems = extractCertsFromPkcs7(raw);

    if (pems.length === 0) {
      return {
        type: "error",
        message: "PKCS#7 DER: no certificates found",
        detail: "Could not extract certificates from the DER-encoded PKCS#7 structure.",
      };
    }

    const items = parseCertificateFile(pems.join("\n"));
    return { type: "certificates", items };
  }

  private parseCrlPem(text: string): ParsedDocument {
    // Parse basic CRL info from the PEM
    const blocks = splitPemBlocks(text).filter(b => b.type === "X509 CRL");
    if (blocks.length === 0) {
      throw new Error("No X509 CRL block found.");
    }

    // Minimal DER inspection for issuer, thisUpdate, nextUpdate
    const der = Buffer.from(blocks[0].base64, "base64");
    return {
      type: "crl",
      issuer: extractCrlIssuer(der),
      thisUpdate: "See raw file",
      nextUpdate: "See raw file",
      revokedCount: -1,
      rawPem: blocks[0].pem,
    };
  }

}

// Minimal CRL issuer extraction — finds first readable string after the outer SEQUENCE
function extractCrlIssuer(der: Buffer): string {
  try {
    const hex = der.toString("hex");
    // Look for PrintableString or UTF8String patterns that look like DN values
    const cnMatch = hex.match(/(?:0c|13)([0-9a-f]{2})((?:[0-9a-f]{2})+)/);
    if (cnMatch) {
      const len = parseInt(cnMatch[1], 16);
      const valueHex = cnMatch[2].slice(0, len * 2);
      return Buffer.from(valueHex, "hex").toString("utf8");
    }
  } catch { /* ignore */ }
  return "Unknown";
}
