import * as assert from "assert";
import * as fs from "fs";
import * as path from "path";
import * as vm from "vm";

const WEBVIEW_SCRIPT = path.resolve(__dirname, "../../../media/webview.js");
const CERT_EDITOR_PROVIDER = path.resolve(__dirname, "../../providers/certEditorProvider.js");

suite("webview rendering safety", () => {
  test("routes HTML writes through the reviewed helper", () => {
    const source = fs.readFileSync(WEBVIEW_SCRIPT, "utf8");
    assert.strictEqual(source.match(/\.innerHTML\s*=/g)?.length ?? 0, 0);
  });

  test("does not retain hidden webview contexts", () => {
    const source = fs.readFileSync(CERT_EDITOR_PROVIDER, "utf8");
    assert.ok(!source.includes("retainContextWhenHidden"));
  });

  test("renders hostile certificate fields as text", () => {
    const html = renderWebview({
      type: "certificates",
      warningDays: 30,
      certs: [{
        displayName: "\"><img src=x onerror=alert(1)>",
        version: 3,
        serial: "01",
        subject: {
          commonName: "<script>alert('subject')</script>",
          org: ["Org </span><img src=x>"],
        },
        issuer: {
          commonName: "<svg onload=alert('issuer')>",
        },
        notBefore: "2026-01-01",
        notAfter: "2027-01-01",
        relExpiry: "Expires later",
        status: "valid",
        sans: [{ type: "dns", value: "example.com\"><img src=x>" }],
        keyUsage: ["digitalSignature"],
        extKeyUsage: [],
        sha1: "aa",
        sha256: "bb",
        pubKey: "RSA",
        pubKeyDisplay: "RSA-2048",
        sigAlg: "sha256WithRSAEncryption",
        selfSigned: false,
        isCA: false,
        extensions: [{
          oid: "1.2.3.4",
          name: "Hostile Extension",
          critical: false,
          value: "</span><script>alert('extension')</script>",
        }],
        findings: [{
          severity: "warning",
          message: "<img src=x onerror=alert('finding')>",
          rfc: "RFC 5280",
        }],
        lintReport: "<script>alert('lint')</script>",
      }],
    });

    assertNoRawHostileMarkup(html);
    assert.ok(html.includes("&lt;script&gt;alert('subject')&lt;/script&gt;"));
    assert.ok(html.includes("&lt;svg onload=alert('issuer')&gt;"));
    assert.ok(html.includes("&lt;/span&gt;&lt;script&gt;alert('extension')&lt;/script&gt;"));
  });

  test("renders hostile error detail as text", () => {
    const html = renderWebview({
      type: "error",
      message: "Parse failed <img src=x>",
      detail: "</pre><script>alert('detail')</script>",
    });

    assertNoRawHostileMarkup(html);
    assert.ok(html.includes("&lt;/pre&gt;&lt;script&gt;alert('detail')&lt;/script&gt;"));
  });

  test("renders hostile key notes as text", () => {
    const html = renderWebview({
      type: "keys",
      keys: [{
        kind: "private",
        algorithm: "RSA",
        display: "RSA-2048",
        format: "PEM",
        encrypted: true,
        note: "<img src=x onerror=alert('key-note')>",
        publicKeyPem: "-----BEGIN PUBLIC KEY-----\n<script>alert('key')</script>\n-----END PUBLIC KEY-----",
      }],
    });

    assertNoRawHostileMarkup(html);
    assert.ok(html.includes("&lt;img src=x onerror=alert('key-note')&gt;"));
    assert.ok(html.includes("&lt;script&gt;alert('key')&lt;/script&gt;"));
  });

  test("restores the selected certificate tab from webview state", () => {
    const payload = certificateTabsPayload();
    const firstRun = runWebview(payload);

    firstRun.elements.get("app")!.clickTab("1");

    assert.deepStrictEqual(firstRun.state, { activeCertificateTab: 1 });

    const restoredRun = runWebview(payload, firstRun.state);
    const html = restoredRun.elements.get("app")!.innerHTML;

    assert.ok(html.includes('<button class="tab" data-i="0">Leaf</button>'), html);
    assert.ok(html.includes('<button class="tab active" data-i="1">Intermediate</button>'), html);
    assert.ok(html.includes('<div class="panel active" data-p="1">'), html);
  });
});

function renderWebview(payload: unknown): string {
  const result = runWebview(payload);
  return Array.from(result.elements.values()).map(element => element.innerHTML).join("\n");
}

function runWebview(payload: unknown, initialState: Record<string, unknown> = {}): {
  elements: Map<string, FakeElement>;
  state: Record<string, unknown>;
} {
  const elements = new Map<string, FakeElement>();
  elements.set("__cv", new FakeElement(JSON.stringify(payload)));
  elements.set("app", new FakeElement());

  const document = {
    getElementById(id: string): FakeElement {
      if (!elements.has(id)) elements.set(id, new FakeElement());
      return elements.get(id)!;
    },
    createRange(): { createContextualFragment(html: string): { html: string } } {
      return {
        createContextualFragment: (html: string): { html: string } => ({ html }),
      };
    },
  };

  const state = { ...initialState };
  const context = {
    acquireVsCodeApi: (): {
      getState(): Record<string, unknown>;
      postMessage(): void;
      setState(nextState: Record<string, unknown>): void;
    } => ({
      getState: (): Record<string, unknown> => ({ ...state }),
      postMessage: (): void => {},
      setState: (nextState: Record<string, unknown>): void => {
        for (const key of Object.keys(state)) delete state[key];
        Object.assign(state, nextState);
      },
    }),
    document,
  };

  vm.runInNewContext(fs.readFileSync(WEBVIEW_SCRIPT, "utf8"), context);
  return { elements, state };
}

function assertNoRawHostileMarkup(html: string): void {
  assert.ok(!html.includes("<script"), html);
  assert.ok(!html.includes("</script"), html);
  assert.ok(!html.includes("<img"), html);
  assert.ok(!html.includes("<svg"), html);
}

class FakeElement {
  innerHTML = "";
  readonly dataset: Record<string, string> = {};
  private clickListener?: (event: { target: FakeClickable }) => void;

  constructor(private readonly payload?: string) {}

  getAttribute(name: string): string | null {
    return name === "data-payload" ? this.payload ?? null : null;
  }

  addEventListener(eventName: string, listener: (event: { target: FakeClickable }) => void): void {
    if (eventName === "click") this.clickListener = listener;
  }

  contains(): boolean {
    return true;
  }

  clickTab(index: string): void {
    this.clickListener?.({ target: new FakeClickable("tab", { i: index }) });
  }

  replaceChildren(fragment: { html?: string }): void {
    this.innerHTML = fragment.html ?? "";
    delete this.dataset.actionsWired;
  }
}

class FakeClickable {
  constructor(
    private readonly className: string,
    readonly dataset: Record<string, string> = {}
  ) {}

  closest(selector: string): FakeClickable | null {
    if (selector === ".tab" && this.className === "tab") return this;
    return null;
  }
}

function certificateTabsPayload(): unknown {
  const baseCertificate = {
    version: 3,
    serial: "01",
    subject: { commonName: "example.test" },
    issuer: { commonName: "Example CA" },
    notBefore: "2026-01-01",
    notAfter: "2027-01-01",
    relExpiry: "Expires later",
    status: "valid",
    sans: [],
    keyUsage: [],
    extKeyUsage: [],
    sha1: "aa",
    sha256: "bb",
    pubKey: "RSA",
    pubKeyDisplay: "RSA-2048",
    sigAlg: "sha256WithRSAEncryption",
    selfSigned: false,
    isCA: false,
    extensions: [],
    findings: [],
  };

  return {
    type: "certificates",
    warningDays: 30,
    certs: [
      { ...baseCertificate, displayName: "Leaf" },
      { ...baseCertificate, displayName: "Intermediate", serial: "02" },
    ],
  };
}
