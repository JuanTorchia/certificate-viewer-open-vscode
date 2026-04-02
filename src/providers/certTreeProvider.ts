import * as vscode from "vscode";
import * as path from "path";
import { parseCertificateFile } from "../parsers/certParser";
import { isPemContent, isDerBuffer } from "../parsers/pemParser";
import { CertificateInfo, getCertificateStatus, getDaysUntilExpiry } from "../models/certificate";
import { getCertDisplayName } from "../utils/formatters";

type TreeItemType = "file" | "cert" | "field";

export class CertTreeItem extends vscode.TreeItem {
  constructor(
    public readonly label: string,
    public readonly collapsibleState: vscode.TreeItemCollapsibleState,
    public readonly itemType: TreeItemType,
    public readonly resourceUri?: vscode.Uri,
    public readonly certInfo?: CertificateInfo,
    public readonly command?: vscode.Command
  ) {
    super(label, collapsibleState);
    this.contextValue = itemType;
  }
}

/**
 * Provides the "Certificates" tree view in the Explorer sidebar.
 * Shows all .pem/.cer/.crt/.der files in the workspace with parsed cert details.
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
      "**/*.{pem,cer,crt,der,p7b,p7c,p7,pfx,p12,csr,req,crl}"
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

    return [];
  }

  private async getCertFiles(): Promise<CertTreeItem[]> {
    const uris = await vscode.workspace.findFiles(
      "**/*.{pem,cer,crt,der,p7b,p7c,p7,pfx,p12,csr,req,crl}",
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
      const raw = await vscode.workspace.fs.readFile(uri);
      const ext = path.extname(uri.fsPath).toLowerCase();

      // Skip formats that don't expose cert info directly in the tree
      if ([".pfx", ".p12", ".csr", ".req", ".crl"].includes(ext)) {
        const label = ext === ".csr" || ext === ".req" ? "Certificate Request"
          : ext === ".crl" ? "Revocation List"
          : "PKCS#12 (password required)";
        const item = new CertTreeItem(label, vscode.TreeItemCollapsibleState.None, "field");
        item.iconPath = new vscode.ThemeIcon("info");
        return [item];
      }

      const text = Buffer.from(raw).toString("utf-8");
      const content = isPemContent(text) ? text : (isDerBuffer(raw) ? raw : text);
      const certs = parseCertificateFile(content);

      return certs.map((cert, idx) => {
        const displayName = getCertDisplayName(cert.subject, cert.serialNumber);
        const status = getCertificateStatus(cert);
        const item = new CertTreeItem(
          certs.length > 1 ? `[${idx + 1}] ${displayName}` : displayName,
          vscode.TreeItemCollapsibleState.Collapsed,
          "cert",
          undefined,
          cert
        );
        item.description = this.getStatusDescription(cert);
        item.iconPath = this.getStatusIcon(status);
        item.tooltip = this.buildCertTooltip(cert);
        return item;
      });
    } catch {
      const errItem = new CertTreeItem(
        "Failed to parse certificate",
        vscode.TreeItemCollapsibleState.None,
        "field"
      );
      errItem.iconPath = new vscode.ThemeIcon("error");
      return [errItem];
    }
  }

  private getCertFields(cert: CertificateInfo): CertTreeItem[] {
    const fields: Array<[string, string]> = [
      ["Subject", cert.subject.commonName ?? "-"],
      ["Issuer", cert.issuer.commonName ?? "-"],
      ["Valid From", cert.validity.notBefore.toLocaleDateString()],
      ["Valid To", cert.validity.notAfter.toLocaleDateString()],
      ["Serial", cert.serialNumber.slice(0, 20) + "..."],
      ["SHA-256", cert.fingerprints.sha256.slice(0, 24) + "..."],
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
