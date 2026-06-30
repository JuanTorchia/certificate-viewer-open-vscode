import * as assert from "assert";
import * as path from "path";
import * as vscode from "vscode";

const FIXTURES = path.resolve(__dirname, "../fixtures/certs");
const uri = (f: string): vscode.Uri => vscode.Uri.file(path.join(FIXTURES, f));
const exec = (cmd: string, ...args: unknown[]): Promise<unknown> =>
  Promise.resolve(vscode.commands.executeCommand(cmd, ...args));

suite("CertEditorProvider — registration", () => {
  test("extension activates successfully", async () => {
    const ext = vscode.extensions.getExtension("gmm.certview");
    assert.ok(ext, "Extension not found — check publisher.name in package.json");
    await ext!.activate();
    assert.ok(ext!.isActive);
  });

  test("certview.certEditor viewType is registered", async () => {
    await assert.doesNotReject(exec("vscode.openWith", uri("self-signed.pem"), "certview.certEditor"));
    await exec("workbench.action.closeAllEditors");
  });
});

suite("CertEditorProvider — command: certview.openCertificate", () => {
  test("command is registered", async () => {
    const cmds = await vscode.commands.getCommands(true);
    assert.ok(cmds.includes("certview.openCertificate"), "certview.openCertificate not found");
  });

  test("opens a PEM file without throwing", async () => {
    await assert.doesNotReject(exec("certview.openCertificate", uri("self-signed.pem")));
    await exec("workbench.action.closeAllEditors");
  });

  test("opens a DER file without throwing", async () => {
    await assert.doesNotReject(exec("certview.openCertificate", uri("self-signed.der")));
    await exec("workbench.action.closeAllEditors");
  });

  test("opens a PKCS7 file without throwing", async () => {
    await assert.doesNotReject(exec("certview.openCertificate", uri("bundle.p7b")));
    await exec("workbench.action.closeAllEditors");
  });

  test("opens a CRL file without throwing", async () => {
    await assert.doesNotReject(exec("certview.openCertificate", uri("test.crl")));
    await exec("workbench.action.closeAllEditors");
  });

  test("shows warning when called with no URI and no active editor", async () => {
    await exec("workbench.action.closeAllEditors");
    await assert.doesNotReject(exec("certview.openCertificate"));
  });
});

suite("CertEditorProvider — file format coverage", () => {
  const formats: Array<[string, string]> = [
    ["self-signed.pem", "PEM certificate"],
    ["chain.pem",       "PEM chain (2 certs)"],
    ["expired.pem",     "expired certificate"],
    ["ec-key.pem",      "EC key certificate"],
    ["self-signed.der", "DER certificate"],
    ["bundle.p7b",      "PKCS7 bundle"],
    ["test.crl",        "CRL file"],
  ];

  for (const [file, label] of formats) {
    test(`opens ${label} (${file}) without error`, async () => {
      await assert.doesNotReject(exec("certview.openCertificate", uri(file)));
      await new Promise(r => setTimeout(r, 200));
      await exec("workbench.action.closeAllEditors");
    });
  }
});

suite("CertView diagnostics", () => {
  test("expired certificate publishes a VS Code diagnostic", async () => {
    const target = uri("expired.pem");
    await assert.doesNotReject(exec("certview.openCertificate", target));
    await new Promise(r => setTimeout(r, 500));
    const diagnostics = vscode.languages.getDiagnostics(target);
    assert.ok(
      diagnostics.some(d => d.source === "CertView" && /expired/i.test(d.message)),
      `Expected CertView expired diagnostic, got: ${diagnostics.map(d => d.message).join(" | ")}`
    );
    await exec("workbench.action.closeAllEditors");
  });
});
