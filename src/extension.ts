import * as vscode from "vscode";
import { CertEditorProvider } from "./providers/certEditorProvider";
import { CertTreeProvider } from "./providers/certTreeProvider";

export function activate(context: vscode.ExtensionContext): void {
  // Register the custom editor for certificate files
  context.subscriptions.push(CertEditorProvider.register(context));

  // Register the sidebar tree view
  const treeProvider = new CertTreeProvider();
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
      vscode.commands.executeCommand("vscode.openWith", target, CertEditorProvider.viewType);
    })
  );

  // Command: Copy fingerprint (can be triggered programmatically)
  context.subscriptions.push(
    vscode.commands.registerCommand("certview.copyFingerprint", async (fingerprint: string) => {
      await vscode.env.clipboard.writeText(fingerprint);
      vscode.window.showInformationMessage("Fingerprint copied to clipboard.");
    })
  );
}

export function deactivate(): void {
  // Nothing to clean up — subscriptions handle disposal
}
