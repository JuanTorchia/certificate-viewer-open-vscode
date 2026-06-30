import * as vscode from "vscode";
import * as path from "path";
import { CertificateInfo, getCertificateStatus, getDaysUntilExpiry } from "../models/certificate";
import { getCertDisplayName } from "../utils/formatters";
import { KeyInfo } from "../parsers/keyParser";
import { parseDocument } from "../parsers/documentParser";
import { MAX_INPUT_BYTES } from "../parsers/limits";

type TreeItemType = "file" | "cert" | "key" | "field";

export class CertTreeItem extends vscode.TreeItem {
  constructor(
    public readonly label: string,
    public readonly collapsibleState: vscode.TreeItemCollapsibleState,
    public readonly itemType: TreeItemType,
    public readonly resourceUri?: vscode.Uri,
    public readonly certInfo?: CertificateInfo,
    public readonly keyInfo?: KeyInfo,
    public readonly command?: vscode.Command
  ) {
    super(label, collapsibleState);
    this.contextValue = itemType;
  }
}

/**
 * Provides the "Certificates" tree view in the Explorer sidebar.
 * Shows supported certificate and key files in the workspace with parsed details.
 */
export class CertTreeProvider implements vscode.TreeDataProvider<CertTreeItem> {
  private _onDidChangeTreeData = new vscode.EventEmitter<CertTreeItem | undefined | void>();
  readonly onDidChangeTreeData = this._onDidChangeTreeData.event;

  private fileWatcher: vscode.FileSystemWatcher | undefined;

  constructor() {
    this.registerFileWatcher();
  }

  private registerFileWatcher(): void {
    this.fileWatcher = vscode.workspace.createFileSystemWatcher(
      "**/*.{pem,cer,crt,der,p7b,p7c,p7,crl,csr,p12,pfx,key,pub,jwk}"
    );
    this.fileWatcher.onDidCreate(() => this.refresh());
    this.fileWatcher.onDidDelete(() => this.refresh());
    this.fileWatcher.onDidChange(() => this.refresh());
  }

  refresh(): void {
    this._onDidChangeTreeData.fire();
  }

  dispose(): void {
    this.fileWatcher?.dispose();
    this._onDidChangeTreeData.dispose();
  }

  getTreeItem(element: CertTreeItem): vscode.TreeItem {
    return element;
  }

  async getChildren(element?: CertTreeItem): Promise<CertTreeItem[]> {
    if (!element) {
      return this.getCertFiles();
    }

    if (element.itemType === "file" && element.resourceUri) {
      return this.getCertsFromFile(element.resourceUri);
    }

    if (element.itemType === "cert" && element.certInfo) {
      return this.getCertFields(element.certInfo);
    }

    if (element.itemType === "key" && element.keyInfo) {
      return this.getKeyFields(element.keyInfo);
    }

    return [];
  }

  private async getCertFiles(): Promise<CertTreeItem[]> {
    const uris = await vscode.workspace.findFiles(
      "**/*.{pem,cer,crt,der,p7b,p7c,p7,crl,csr,p12,pfx,key,pub,jwk}",
      "**/node_modules/**"
    );

    return uris
      .sort((a, b) => a.fsPath.localeCompare(b.fsPath))
      .map(uri => {
        const item = new CertTreeItem(
          path.basename(uri.fsPath),
          vscode.TreeItemCollapsibleState.Collapsed,
          "file",
          uri,
          undefined,
          undefined,
          {
            command: "vscode.openWith",
            title: "Open Certificate",
            arguments: [uri, "certview.certEditor"],
          }
        );
        item.tooltip = uri.fsPath;
        item.iconPath = new vscode.ThemeIcon("file");
        return item;
      });
  }

  private async getCertsFromFile(uri: vscode.Uri): Promise<CertTreeItem[]> {
    try {
      const ext = path.extname(uri.fsPath).toLowerCase();
      if (ext === ".p12" || ext === ".pfx") {
        const item = new CertTreeItem("PKCS#12 keystore - open file to inspect", vscode.TreeItemCollapsibleState.None, "field");
        item.iconPath = new vscode.ThemeIcon("key");
        item.tooltip = "PKCS#12 files may require a password prompt, so CertView parses them in the editor view.";
        return [item];
      }

      const stat = await vscode.workspace.fs.stat(uri);
      if (stat.size > MAX_INPUT_BYTES) {
        const item = new CertTreeItem("File too large to parse", vscode.TreeItemCollapsibleState.None, "field");
        item.iconPath = new vscode.ThemeIcon("warning");
        item.tooltip = `CertView limit is ${MAX_INPUT_BYTES} bytes.`;
        return [item];
      }
      const raw = await vscode.workspace.fs.readFile(uri);
      const parsed = parseDocument(raw, uri.fsPath);

      if (parsed.type === "crl") {
        const item = new CertTreeItem("Revocation List", vscode.TreeItemCollapsibleState.None, "field");
        item.iconPath = new vscode.ThemeIcon("info");
        return [item];
      }

      if (parsed.type === "csr") {
        const item = new CertTreeItem("Certificate Signing Request", vscode.TreeItemCollapsibleState.None, "field");
        item.iconPath = new vscode.ThemeIcon("info");
        return [item];
      }

      if (parsed.type === "keys") {
        return this.keyItems(parsed.items);
      }

      if (parsed.type === "bundle") {
        return [
          ...parsed.certificates.map((cert, idx) => this.certItem(cert, parsed.certificates.length, idx)),
          ...this.keyItems(parsed.keys),
        ];
      }

      if (parsed.type === "error") {
        throw new Error(parsed.detail ?? parsed.message);
      }

      return parsed.items.map((cert, idx) => this.certItem(cert, parsed.items.length, idx));
    } catch {
      const errItem = new CertTreeItem(
        "Failed to parse file",
        vscode.TreeItemCollapsibleState.None,
        "field"
      );
      errItem.iconPath = new vscode.ThemeIcon("error");
      return [errItem];
    }
  }

  private keyItems(keys: KeyInfo[]): CertTreeItem[] {
    return keys.map((key, idx) => {
          const item = new CertTreeItem(
            keys.length > 1 ? `[${idx + 1}] ${key.algorithm} ${key.kind} key` : `${key.algorithm} ${key.kind} key`,
            vscode.TreeItemCollapsibleState.Collapsed,
            "key",
            undefined,
            undefined,
            key
          );
          item.description = key.format;
          item.iconPath = new vscode.ThemeIcon(key.kind === "private" ? "key" : "symbol-key");
          item.tooltip = `${key.algorithm} ${key.kind} key (${key.format})`;
          return item;
        });
  }

  private certItem(cert: CertificateInfo, total: number, idx: number): CertTreeItem {
    const displayName = getCertDisplayName(cert.subject, cert.serialNumber);
    const status = getCertificateStatus(cert);
    const item = new CertTreeItem(
      total > 1 ? `[${idx + 1}] ${displayName}` : displayName,
      vscode.TreeItemCollapsibleState.Collapsed,
      "cert",
      undefined,
      cert,
      undefined
    );
    item.description = this.getStatusDescription(cert);
    item.iconPath = this.getStatusIcon(status);
    item.tooltip = this.buildCertTooltip(cert);
    return item;
  }

  private getCertFields(cert: CertificateInfo): CertTreeItem[] {
    const fields: Array<[string, string]> = [
      ["Subject", cert.subject.commonName ?? "-"],
      ["Issuer", cert.issuer.commonName ?? "-"],
      ["Valid From", cert.validity.notBefore.toLocaleDateString()],
      ["Valid To", cert.validity.notAfter.toLocaleDateString()],
      ["Serial", cert.serialNumber.slice(0, 20) + "..."],
      ["SHA-256", cert.fingerprints.sha256.slice(0, 24) + "..."],
      ["Curve", cert.publicKeyCurve ?? "-"],
      ["Public Exponent", cert.publicKeyExponent ?? "-"],
    ];

    return fields.map(([key, value]) => {
      const item = new CertTreeItem(
        `${key}: ${value}`,
        vscode.TreeItemCollapsibleState.None,
        "field"
      );
      item.iconPath = new vscode.ThemeIcon("symbol-field");
      return item;
    });
  }

  private getKeyFields(key: KeyInfo): CertTreeItem[] {
    const fields: Array<[string, string | undefined]> = [
      ["Kind", key.kind],
      ["Algorithm", key.algorithm],
      ["Format", key.format],
      ["Size", key.keySize ? `${key.keySize} bit` : undefined],
      ["Curve", key.curve],
      ["Public Exponent", key.publicExponent],
      ["Encrypted", key.encrypted ? "Yes" : undefined],
      ["SPKI SHA-256", key.spkiFingerprints ? `${key.spkiFingerprints.sha256.slice(0, 24)}...` : undefined],
    ];

    return fields.filter(([, value]) => value).map(([name, value]) => {
      const item = new CertTreeItem(`${name}: ${value}`, vscode.TreeItemCollapsibleState.None, "field");
      item.iconPath = new vscode.ThemeIcon("symbol-field");
      return item;
    });
  }

  private getStatusDescription(cert: CertificateInfo): string {
    const days = getDaysUntilExpiry(cert);
    if (days < 0) return `Expired ${Math.abs(days)}d ago`;
    if (days <= 30) return `Expires in ${days}d`;
    return cert.validity.notAfter.toLocaleDateString();
  }

  private getStatusIcon(status: ReturnType<typeof getCertificateStatus>): vscode.ThemeIcon {
    switch (status) {
      case "valid": return new vscode.ThemeIcon("pass", new vscode.ThemeColor("testing.iconPassed"));
      case "expiring-soon": return new vscode.ThemeIcon("warning", new vscode.ThemeColor("list.warningForeground"));
      case "expired": return new vscode.ThemeIcon("error", new vscode.ThemeColor("testing.iconFailed"));
      case "not-yet-valid": return new vscode.ThemeIcon("clock");
    }
  }

  private buildCertTooltip(cert: CertificateInfo): vscode.MarkdownString {
    const md = new vscode.MarkdownString();
    md.appendMarkdown(`**${cert.subject.commonName ?? "Unknown"}**\n\n`);
    md.appendMarkdown(`- Issuer: ${cert.issuer.commonName ?? "-"}\n`);
    md.appendMarkdown(`- Valid: ${cert.validity.notBefore.toLocaleDateString()} → ${cert.validity.notAfter.toLocaleDateString()}\n`);
    md.appendMarkdown(`- SHA-256: \`${cert.fingerprints.sha256}\`\n`);
    return md;
  }
}
