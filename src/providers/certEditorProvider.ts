import * as path from "path";
import * as vscode from "vscode";
import { ParsedDocument } from "../models/parsedDocument";
import { parseDocument } from "../parsers/documentParser";
import { parsePkcs12, Pkcs12PasswordError } from "../parsers/pkcs12Parser";
import { buildWebviewHtml } from "../views/certWebview";
import { MAX_INPUT_BYTES } from "../parsers/limits";
import { CertDiagnosticsProvider } from "./certDiagnostics";

export class CertEditorProvider implements vscode.CustomReadonlyEditorProvider {
  public static readonly viewType = "certview.certEditor";

  constructor(private readonly context: vscode.ExtensionContext, private readonly diagnosticsProvider?: CertDiagnosticsProvider) {}

  public static register(context: vscode.ExtensionContext, diagnosticsProvider?: CertDiagnosticsProvider): vscode.Disposable {
    return vscode.window.registerCustomEditorProvider(
      CertEditorProvider.viewType,
      new CertEditorProvider(context, diagnosticsProvider),
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
    return { uri, dispose: (): void => {} };
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
    this.diagnosticsProvider?.setParsedDiagnostics(document.uri, parsed);
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
    const stat = await vscode.workspace.fs.stat(uri);
    if (stat.size > MAX_INPUT_BYTES) {
      return {
        type: "error",
        message: `Refusing to parse ${path.basename(uri.fsPath)}`,
        detail: `File is ${stat.size} bytes; CertView limit is ${MAX_INPUT_BYTES} bytes to protect the VS Code extension host from unbounded parsing.`,
      };
    }
    const raw = await vscode.workspace.fs.readFile(uri);
    const ext = path.extname(uri.fsPath).toLowerCase();

    if (ext === ".p12" || ext === ".pfx") {
      return this.parsePkcs12File(raw, uri.fsPath);
    }

    return parseDocument(raw, uri.fsPath);
  }

  private async parsePkcs12File(raw: Uint8Array, fsPath: string): Promise<ParsedDocument> {
    // Try empty password first (covers unprotected and empty-password P12s)
    try {
      const items = parsePkcs12(raw, "");
      return { type: "certificates", items };
    } catch (e) {
      if (!(e instanceof Pkcs12PasswordError)) {
        return this.pkcs12ErrorDoc(fsPath, e);
      }
    }

    // Prompt user for password
    const password = await vscode.window.showInputBox({
      prompt: `Password for ${path.basename(fsPath)}`,
      placeHolder: "Enter P12/PFX password",
      password: true,
      ignoreFocusOut: true,
    });

    if (password === undefined) {
      return { type: "error", message: "P12/PFX password required", detail: "No password was provided." };
    }

    try {
      const items = parsePkcs12(raw, password);
      return { type: "certificates", items };
    } catch (e) {
      if (e instanceof Pkcs12PasswordError) {
        return { type: "error", message: "Invalid P12/PFX password", detail: "The password is incorrect or the file is corrupt." };
      }
      return this.pkcs12ErrorDoc(fsPath, e);
    }
  }

  private pkcs12ErrorDoc(fsPath: string, e: unknown): ParsedDocument {
    const message = e instanceof Error ? e.message : String(e);
    return {
      type: "error",
      message: `Failed to parse ${path.basename(fsPath)}`,
      detail: message,
    };
  }

}
