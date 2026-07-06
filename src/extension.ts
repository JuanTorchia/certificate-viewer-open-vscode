import * as vscode from "vscode";
import { CertEditorProvider } from "./providers/certEditorProvider";
import { CertTreeProvider } from "./providers/certTreeProvider";
import { CertDiagnosticsProvider } from "./providers/certDiagnostics";
import { ParsedDocumentCache, ParsedDocumentStat } from "./parsers/parsedDocumentCache";

export function activate(context: vscode.ExtensionContext): void {
  const parsedDocumentCache = new ParsedDocumentCache({
    stat: async (uriString: string): Promise<ParsedDocumentStat> => {
      const stat = await vscode.workspace.fs.stat(vscode.Uri.parse(uriString));
      return { size: stat.size, mtime: stat.mtime };
    },
    readFile: async (uriString: string): Promise<Uint8Array> => vscode.workspace.fs.readFile(vscode.Uri.parse(uriString)),
  });
  context.subscriptions.push({ dispose: () => parsedDocumentCache.clear() });

  const diagnosticsProvider = new CertDiagnosticsProvider(parsedDocumentCache);
  context.subscriptions.push(diagnosticsProvider);

  // Register the custom editor for certificate files
  context.subscriptions.push(CertEditorProvider.register(context, diagnosticsProvider, parsedDocumentCache));

  // Register the sidebar tree view
  const treeProvider = new CertTreeProvider(parsedDocumentCache);
  const treeView = vscode.window.createTreeView("certview.certExplorer", {
    treeDataProvider: treeProvider,
    showCollapseAll: true,
  });
  context.subscriptions.push(treeView, treeProvider);

  // Command: Refresh tree
  context.subscriptions.push(
    vscode.commands.registerCommand("certview.refreshTree", () => {
      treeProvider.refresh();
    })
  );

  // Command: Open certificate with custom editor
  context.subscriptions.push(
    vscode.commands.registerCommand("certview.openCertificate", (uri?: vscode.Uri) => {
      const target = uri ?? vscode.window.activeTextEditor?.document.uri;
      if (!target) {
        vscode.window.showWarningMessage("CertView: No certificate file selected.");
        return;
      }
      return vscode.commands.executeCommand("vscode.openWith", target, CertEditorProvider.viewTypeForUri(target));
    })
  );
}

export function deactivate(): void {
  // Nothing to clean up — subscriptions handle disposal
}
