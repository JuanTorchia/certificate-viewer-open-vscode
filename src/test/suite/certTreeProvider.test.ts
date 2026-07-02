import * as assert from "assert";
import * as path from "path";
import * as vscode from "vscode";
import { CertTreeProvider, CertTreeItem } from "../../providers/certTreeProvider";

const FIXTURES = path.resolve(__dirname, "../fixtures/certs");
const CERT_FIXTURES = {
  "self-signed.pem": path.join(FIXTURES, "self-signed.pem"),
  "chain.pem": path.join(FIXTURES, "chain.pem"),
  "expired.pem": path.join(FIXTURES, "expired.pem"),
  "expiring-soon.pem": path.join(FIXTURES, "expiring-soon.pem"),
  "self-signed.der": path.join(FIXTURES, "self-signed.der"),
  "bundle.p7b": path.join(FIXTURES, "bundle.p7b"),
  "test.crl": path.join(FIXTURES, "test.crl"),
} as const;
const uri = (f: keyof typeof CERT_FIXTURES): vscode.Uri => vscode.Uri.file(CERT_FIXTURES[f]);
const MISSING_CERT = path.join(FIXTURES, "missing.pem");

suite("CertTreeProvider — tree view registration", () => {
  test("certview.certExplorer view is registered", async () => {
    const cmds = await vscode.commands.getCommands(true);
    assert.ok(cmds.includes("certview.refreshTree"), "certview.refreshTree not found");
  });
});

suite("CertTreeProvider — getChildren (root level)", () => {
  let provider: CertTreeProvider;

  setup(() => {
    provider = new CertTreeProvider();
  });

  teardown(() => {
    provider.dispose();
  });

  test("returns CertTreeItem array", async () => {
    const items = await provider.getChildren();
    assert.ok(Array.isArray(items));
  });

  test("getTreeItem returns the same element", () => {
    const item = new CertTreeItem(
      "test",
      vscode.TreeItemCollapsibleState.None,
      "field"
    );
    assert.strictEqual(provider.getTreeItem(item), item);
  });

  test("returns empty array for unknown element type", async () => {
    const item = new CertTreeItem(
      "unknown",
      vscode.TreeItemCollapsibleState.None,
      "field"
    );
    const children = await provider.getChildren(item);
    assert.deepStrictEqual(children, []);
  });
});

suite("CertTreeProvider — getCertsFromFile", () => {
  let provider: CertTreeProvider;

  setup(() => {
    provider = new CertTreeProvider();
  });

  teardown(() => {
    provider.dispose();
  });

  async function getFileItem(file: keyof typeof CERT_FIXTURES): Promise<CertTreeItem> {
    return new CertTreeItem(
      file,
      vscode.TreeItemCollapsibleState.Collapsed,
      "file",
      uri(file)
    );
  }

  test("self-signed.pem — returns 1 cert item", async () => {
    const fileItem = await getFileItem("self-signed.pem");
    const children = await provider.getChildren(fileItem);
    assert.strictEqual(children.length, 1);
    assert.strictEqual(children[0].itemType, "cert");
    assert.strictEqual(children[0].label?.toString(), "self-signed.example.com");
  });

  test("chain.pem — returns 2 cert items", async () => {
    const fileItem = await getFileItem("chain.pem");
    const children = await provider.getChildren(fileItem);
    assert.strictEqual(children.length, 2);
    assert.ok(children.every(c => c.itemType === "cert"));
  });

  test("expired.pem — returns cert item (expired)", async () => {
    const fileItem = await getFileItem("expired.pem");
    const children = await provider.getChildren(fileItem);
    assert.strictEqual(children.length, 1);
    assert.ok(children[0].description?.toString().includes("Expired"));
  });

  test("expiring-soon.pem — returns a status description", async () => {
    const fileItem = await getFileItem("expiring-soon.pem");
    const children = await provider.getChildren(fileItem);
    assert.strictEqual(children.length, 1);
    assert.ok(children[0].description?.toString());
  });

  test("self-signed.der — returns 1 cert item", async () => {
    const fileItem = await getFileItem("self-signed.der");
    const children = await provider.getChildren(fileItem);
    assert.strictEqual(children.length, 1);
    assert.strictEqual(children[0].itemType, "cert");
  });

  test("bundle.p7b — returns 2 cert items", async () => {
    const fileItem = await getFileItem("bundle.p7b");
    const children = await provider.getChildren(fileItem);
    assert.strictEqual(children.length, 2);
    assert.ok(children.every(c => c.itemType === "cert"));
  });

  test("test.crl — returns info item (not a cert)", async () => {
    const fileItem = await getFileItem("test.crl");
    const children = await provider.getChildren(fileItem);
    assert.strictEqual(children.length, 1);
    assert.ok(children[0].label?.toString().includes("Revocation List"));
  });

  test("PKCS#12 files return an informational item instead of a parse error", async () => {
    const fileItem = new CertTreeItem(
      "keystore.p12",
      vscode.TreeItemCollapsibleState.Collapsed,
      "file",
      vscode.Uri.file(path.resolve(process.cwd(), "testcerts", "keystore.p12"))
    );
    const children = await provider.getChildren(fileItem);
    assert.strictEqual(children.length, 1);
    assert.ok(children[0].label?.toString().includes("PKCS#12"));
    assert.ok(!children[0].label?.toString().toLowerCase().includes("failed"));
  });

  test("non-existent file — returns error item", async () => {
    const fileItem = new CertTreeItem(
      "missing.pem",
      vscode.TreeItemCollapsibleState.Collapsed,
      "file",
      vscode.Uri.file(MISSING_CERT)
    );
    const children = await provider.getChildren(fileItem);
    assert.strictEqual(children.length, 1);
    assert.ok(children[0].label?.toString().toLowerCase().includes("failed"));
  });
});

suite("CertTreeProvider — getCertFields", () => {
  let provider: CertTreeProvider;

  setup(() => {
    provider = new CertTreeProvider();
  });

  teardown(() => {
    provider.dispose();
  });

  test("cert item expands to field items", async () => {
    const fileItem = new CertTreeItem(
      "self-signed.pem",
      vscode.TreeItemCollapsibleState.Collapsed,
      "file",
      uri("self-signed.pem")
    );
    const certs = await provider.getChildren(fileItem);
    assert.ok(certs.length >= 1);

    const fields = await provider.getChildren(certs[0]);
    assert.ok(fields.length > 0);
    assert.ok(fields.every(f => f.itemType === "field"));
  });

  test("field items include Subject, Issuer, Valid From, Valid To", async () => {
    const fileItem = new CertTreeItem(
      "self-signed.pem",
      vscode.TreeItemCollapsibleState.Collapsed,
      "file",
      uri("self-signed.pem")
    );
    const certs = await provider.getChildren(fileItem);
    const fields = await provider.getChildren(certs[0]);
    const labels = fields.map(f => f.label?.toString() ?? "");

    assert.ok(labels.some(l => l.startsWith("Subject:")));
    assert.ok(labels.some(l => l.startsWith("Issuer:")));
    assert.ok(labels.some(l => l.startsWith("Valid From:")));
    assert.ok(labels.some(l => l.startsWith("Valid To:")));
    assert.ok(labels.some(l => l.startsWith("Serial:")));
    assert.ok(labels.some(l => l.startsWith("SHA-256:")));
  });
});

suite("CertTreeProvider — refresh", () => {
  test("refresh fires onDidChangeTreeData event", done => {
    const provider = new CertTreeProvider();
    const sub = provider.onDidChangeTreeData(() => {
      sub.dispose();
      provider.dispose();
      done();
    });
    provider.refresh();
  });
});
