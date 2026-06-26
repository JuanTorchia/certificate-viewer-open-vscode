import * as path from "path";
import * as vscode from "vscode";
import { ParsedDocument } from "../models/parsedDocument";
import { parseDocument } from "../parsers/documentParser";
import { parsePkcs12, Pkcs12PasswordError } from "../parsers/pkcs12Parser";
import { buildWebviewHtml } from "../views/certWebview";
import { MAX_INPUT_BYTES } from "../parsers/limits";
import { EncryptedPrivateKeyPasswordError, isEncryptedPrivateKey, parseKeyFile } from "../parsers/keyParser";

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

    if (isEncryptedPrivateKey(raw)) {
      return this.parseEncryptedKeyFile(raw, uri.fsPath);
    }

    return parseDocument(raw, uri.fsPath);
  }

  private async parseEncryptedKeyFile(raw: Uint8Array, fsPath: string): Promise<ParsedDocument> {
    const password = await vscode.window.showInputBox({
      prompt: `Password for ${path.basename(fsPath)}`,
      placeHolder: "Enter private key password",
      password: true,
      ignoreFocusOut: true,
    });

    if (password === undefined) {
      return { type: "error", message: "Private key password required", detail: "No password was provided." };
    }

    try {
      return { type: "keys", items: parseKeyFile(raw, fsPath, password) };
    } catch (e) {
      if (e instanceof EncryptedPrivateKeyPasswordError) {
        return { type: "error", message: "Private key password required", detail: "No password was provided." };
      }
      const message = e instanceof Error ? e.message : String(e);
      return { type: "error", message: "Invalid private key password", detail: message };
    }
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
    const stack = e instanceof Error ? e.stack ?? "" : "";
    return {
      type: "error",
      message: `Failed to parse ${path.basename(fsPath)}`,
      detail: message + (stack ? `\n\n${stack.split("\n").slice(0, 5).join("\n")}` : ""),
    };
  }

}
