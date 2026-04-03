/**
 * "Open behavior" tests — simulate exactly what a user does:
 * double-click a cert file and verify it opens in the certificate viewer,
 * NOT as plain text.
 *
 * These tests would have caught the priority:"option" bug automatically.
 */
import * as assert from "assert";
import * as fs from "fs";
import * as path from "path";
import * as vscode from "vscode";
import { parseCertificateFile } from "../../parsers/certParser";
import { buildWebviewHtml } from "../../views/certWebview";

const FIXTURES = path.resolve(__dirname, "../fixtures/certs");
const uri = (f: string) => vscode.Uri.file(path.join(FIXTURES, f));
const wait = (ms: number) => new Promise<void>(r => setTimeout(r, ms));

async function openAsUser(file: string): Promise<void> {
  await vscode.commands.executeCommand("vscode.open", uri(file));
  await wait(600);
}

function isOpenAsText(file: string): boolean {
  return vscode.window.visibleTextEditors.some(e =>
    e.document.uri.fsPath === uri(file).fsPath
  );
}

suite("Open behavior — user double-click simulation", () => {
  teardown(async () => {
    await vscode.commands.executeCommand("workbench.action.closeAllEditors");
    await wait(200);
  });

  test(".pem opens as certificate viewer, NOT as text", async () => {
    await openAsUser("self-signed.pem");
    assert.ok(
      !isOpenAsText("self-signed.pem"),
      ".pem opened in a text editor — priority should be 'default', not 'option'"
    );
  });

  test(".der opens as certificate viewer, NOT as text", async () => {
    await openAsUser("self-signed.der");
    assert.ok(
      !isOpenAsText("self-signed.der"),
      ".der opened in a text editor — check customEditors selector"
    );
  });

  test(".p7b opens as certificate viewer, NOT as text", async () => {
    await openAsUser("bundle.p7b");
    assert.ok(
      !isOpenAsText("bundle.p7b"),
      ".p7b opened in a text editor — check customEditors selector includes p7b"
    );
  });

  test(".crl opens as certificate viewer, NOT as text", async () => {
    await openAsUser("test.crl");
    assert.ok(
      !isOpenAsText("test.crl"),
      ".crl opened in a text editor"
    );
  });
});

suite("Open behavior — webview payload is not an error", () => {
  teardown(async () => {
    await vscode.commands.executeCommand("workbench.action.closeAllEditors");
    await wait(200);
  });

  async function assertOpensAsCertView(file: string, label: string): Promise<void> {
    await openAsUser(file);
    const openedAsText = isOpenAsText(file);
    assert.ok(
      !openedAsText,
      `${label} (${file}) opened as plain text instead of the certificate viewer`
    );
  }

  test("PEM certificate renders as viewer (not code)", async () => {
    await assertOpensAsCertView("self-signed.pem", "PEM");
  });

  test("Expired certificate renders as viewer (not code)", async () => {
    await assertOpensAsCertView("expired.pem", "Expired PEM");
  });

  test("Chain PEM renders as viewer (not code)", async () => {
    await assertOpensAsCertView("chain.pem", "Chain PEM");
  });

  test("DER certificate renders as viewer (not code)", async () => {
    await assertOpensAsCertView("self-signed.der", "DER");
  });

  test("PKCS7 bundle renders as viewer (not code)", async () => {
    await assertOpensAsCertView("bundle.p7b", "PKCS7");
  });

  test("CRL renders as viewer (not code)", async () => {
    await assertOpensAsCertView("test.crl", "CRL");
  });
});

suite("Open behavior — webview HTML payload content", () => {
  const fixturesDir = FIXTURES;

  function parsePayload(html: string): Record<string, unknown> {
    const match = html.match(/data-payload="([^"]+)"/);
    assert.ok(match, "data-payload attribute not found in HTML");
    return JSON.parse(match[1].replace(/&quot;/g, '"').replace(/&amp;/g, "&"));
  }

  function fakeWebview(): vscode.Webview {
    return {
      options: {},
      asWebviewUri: (u: vscode.Uri) => u,
      cspSource: "",
    } as unknown as vscode.Webview;
  }

  test("self-signed.pem payload contains CN", () => {
    const pem = fs.readFileSync(path.join(fixturesDir, "self-signed.pem"), "utf-8");
    const doc = { type: "certificates" as const, items: parseCertificateFile(pem) };
    const html = buildWebviewHtml(fakeWebview(), vscode.Uri.file("/"), doc, 30);
    const payload = parsePayload(html) as { type: string; certs: Array<{ subject: { commonName: string } }> };

    assert.strictEqual(payload.type, "certificates");
    assert.ok(Array.isArray(payload.certs));
    assert.ok(payload.certs.length >= 1);
    assert.strictEqual(payload.certs[0].subject.commonName, "self-signed.example.com");
  });

  test("expired.pem payload has status 'expired'", () => {
    const pem = fs.readFileSync(path.join(fixturesDir, "expired.pem"), "utf-8");
    const doc = { type: "certificates" as const, items: parseCertificateFile(pem) };
    const html = buildWebviewHtml(fakeWebview(), vscode.Uri.file("/"), doc, 30);
    const payload = parsePayload(html) as { certs: Array<{ status: string }> };

    assert.strictEqual(payload.certs[0].status, "expired");
  });

  test("chain.pem payload contains 2 certs", () => {
    const pem = fs.readFileSync(path.join(fixturesDir, "chain.pem"), "utf-8");
    const doc = { type: "certificates" as const, items: parseCertificateFile(pem) };
    const html = buildWebviewHtml(fakeWebview(), vscode.Uri.file("/"), doc, 30);
    const payload = parsePayload(html) as { certs: unknown[] };

    assert.strictEqual(payload.certs.length, 2);
  });

  test("corrupt file payload is type 'error', not a crash", () => {
    const doc = { type: "error" as const, message: "Failed to parse", detail: "bad bytes" };
    const html = buildWebviewHtml(fakeWebview(), vscode.Uri.file("/"), doc, 30);
    const payload = parsePayload(html) as { type: string; message: string };

    assert.strictEqual(payload.type, "error");
    assert.ok(payload.message.length > 0);
  });
});
