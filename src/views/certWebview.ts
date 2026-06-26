import * as vscode from "vscode";
import { ParsedDocument } from "../models/parsedDocument";
import { CertificateInfo, getCertificateStatus } from "../models/certificate";
import { CsrInfo } from "../parsers/csrParser";
import { formatDate, formatRelativeExpiry, getCertDisplayName } from "../utils/formatters";

export function buildWebviewHtml(
  webview: vscode.Webview,
  extensionUri: vscode.Uri,
  doc: ParsedDocument,
  warningDays: number
): string {
  const scriptUri = webview.asWebviewUri(
    vscode.Uri.joinPath(extensionUri, "media", "webview.js")
  );
  const nonce = getNonce();
  const payload = buildPayload(doc, warningDays);

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta http-equiv="Content-Security-Policy"
    content="default-src 'none'; style-src 'nonce-${nonce}'; script-src 'nonce-${nonce}';">
  <meta name="viewport" content="width=device-width,initial-scale=1.0">
  <title>CertView</title>
  <style nonce="${nonce}">
    *{box-sizing:border-box;margin:0;padding:0}
    body{font-family:var(--vscode-font-family);font-size:var(--vscode-font-size);
         color:var(--vscode-foreground);background:var(--vscode-editor-background);padding:16px}
    .tabs{display:flex;gap:4px;border-bottom:1px solid var(--vscode-panel-border);margin-bottom:12px;padding-bottom:4px}
    .tab{background:none;border:none;color:var(--vscode-foreground);cursor:pointer;padding:4px 12px;
         border-radius:4px 4px 0 0;opacity:.6;font-size:var(--vscode-font-size)}
    .tab.active{opacity:1;background:var(--vscode-tab-activeBackground);
                border-bottom:2px solid var(--vscode-focusBorder)}
    .panel{display:none}.panel.active{display:block}
    .banner{padding:8px 12px;border-radius:6px;margin-bottom:12px;font-weight:600}
    .banner.ok  {background:rgba(0,200,100,.15);color:#4ec994}
    .banner.warn{background:rgba(255,180,0,.15);color:#e5a500}
    .banner.err {background:rgba(220,50,50,.15);color:#f14c4c}
    .banner.info{background:rgba(100,150,255,.15);color:#82b1ff}
    details{border:1px solid var(--vscode-panel-border);border-radius:6px;margin-bottom:8px;overflow:hidden}
    summary{padding:8px 12px;background:var(--vscode-sideBarSectionHeader-background);
            cursor:pointer;font-weight:600;font-size:.85em;text-transform:uppercase;letter-spacing:.04em;
            list-style:none}
    summary::-webkit-details-marker{display:none}
    details[open] summary{border-bottom:1px solid var(--vscode-panel-border)}
    .section-body{padding:4px 0}
    .row{display:grid;grid-template-columns:160px 1fr;gap:4px;padding:4px 12px;
         border-bottom:1px solid var(--vscode-panel-border)}
    .row:last-child{border-bottom:none}
    .lbl{color:var(--vscode-descriptionForeground);font-size:.9em;align-self:start;padding-top:1px}
    .val{font-family:var(--vscode-editor-font-family,monospace);word-break:break-all;white-space:pre-wrap}
    .mono{font-family:var(--vscode-editor-font-family,monospace)}
    .tags{display:flex;flex-wrap:wrap;gap:4px}
    .tag{padding:2px 8px;border-radius:12px;background:var(--vscode-badge-background);
         color:var(--vscode-badge-foreground);font-size:.8em}
    .copy-btn{margin-left:8px;padding:1px 6px;background:none;cursor:pointer;
              border:1px solid var(--vscode-panel-border);border-radius:4px;
              color:var(--vscode-foreground);font-size:.78em}
    .copy-btn:hover{background:var(--vscode-button-secondaryHoverBackground)}
    .link-btn{margin-top:8px;background:none;border:none;
              color:var(--vscode-textLink-foreground);cursor:pointer;
              text-decoration:underline;font-size:.85em}
    .badge-type{display:inline-block;padding:3px 10px;border-radius:12px;
                background:var(--vscode-badge-background);color:var(--vscode-badge-foreground);
                font-size:.78em;font-weight:700;letter-spacing:.05em;margin-bottom:12px}
    .error-card{padding:16px;border:1px solid rgba(220,50,50,.4);border-radius:6px;
                background:rgba(220,50,50,.08)}
    .error-title{font-weight:700;color:#f14c4c;margin-bottom:8px}
    .error-detail{font-family:var(--vscode-editor-font-family,monospace);font-size:.85em;
                  white-space:pre-wrap;word-break:break-all;
                  color:var(--vscode-descriptionForeground)}
  </style>
</head>
<body>
  <div id="__cv" data-payload="${escapeAttr(JSON.stringify(payload))}" style="display:none"></div>
  <div id="app"></div>
  <script nonce="${nonce}" src="${scriptUri}"></script>
</body>
</html>`;
}

// ── Payload builders ──────────────────────────────────────────────────────────

function buildPayload(doc: ParsedDocument, warningDays: number): unknown {
  switch (doc.type) {
    case "certificates":
      return { type: "certificates", certs: doc.items.map(c => serializeCert(c, warningDays)), warningDays };
    case "csr":
      return { type: "csr", csrs: doc.items.map(serializeCsr) };
    case "crl":
      return { type: "crl", crl: { issuer: doc.issuer, thisUpdate: doc.thisUpdate, nextUpdate: doc.nextUpdate, revokedCount: doc.revokedCount } };
    case "keys":
      return { type: "keys", keys: doc.items };
    case "error":
      return { type: "error", message: doc.message, detail: doc.detail ?? "" };
  }
}

function serializeCsr(csr: CsrInfo): Record<string, unknown> {
  return {
    displayName: csr.subject.commonName ?? "Certificate Request",
    subject: {
      commonName: csr.subject.commonName,
      org: csr.subject.organization,
      ou: csr.subject.organizationalUnit,
      country: csr.subject.country,
      state: csr.subject.state,
      locality: csr.subject.locality,
      email: csr.subject.emailAddress,
    },
    pubKey: csr.publicKeyAlgorithm,
    keySize: csr.publicKeySize,
    sigAlg: csr.signatureAlgorithm,
    sans: csr.subjectAltNames,
  };
}

function serializeCert(cert: CertificateInfo, warningDays: number): Record<string, unknown> {
  const status = getCertificateStatus(cert, warningDays);
  return {
    displayName: getCertDisplayName(cert.subject, cert.serialNumber),
    version: cert.version,
    serial: cert.serialNumber,
    subject: {
      commonName: cert.subject.commonName,
      org: cert.subject.organization,
      ou: cert.subject.organizationalUnit,
      country: cert.subject.country,
      state: cert.subject.state,
      locality: cert.subject.locality,
      email: cert.subject.emailAddress,
    },
    issuer: {
      commonName: cert.issuer.commonName,
      org: cert.issuer.organization,
      ou: cert.issuer.organizationalUnit,
      country: cert.issuer.country,
      state: cert.issuer.state,
      locality: cert.issuer.locality,
      email: cert.issuer.emailAddress,
    },
    notBefore: formatDate(cert.validity.notBefore),
    notAfter: formatDate(cert.validity.notAfter),
    relExpiry: formatRelativeExpiry(cert.validity.notAfter),
    status,
    sans: cert.subjectAltNames,
    keyUsage: cert.keyUsage,
    extKeyUsage: cert.extendedKeyUsage,
    sha1: cert.fingerprints.sha1,
    sha256: cert.fingerprints.sha256,
    pubKey: cert.publicKeyAlgorithm,
    keySize: cert.publicKeySize,
    sigAlg: cert.signatureAlgorithm,
    selfSigned: cert.isSelfSigned,
    isCA: cert.isCA,
    basicConstraints: cert.basicConstraints,
    nameConstraints: cert.nameConstraints,
    extensions: cert.extensions,
    publicKeyPem: cert.publicKeyPem,
    findings: cert.findings,
    lintReport: JSON.stringify({ subject: cert.subject.commonName, serial: cert.serialNumber, findings: cert.findings }, null, 2),
  };
}


function getNonce(): string {
  let t = "";
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  for (let i = 0; i < 32; i++) { t += chars[Math.floor(Math.random() * chars.length)]; }
  return t;
}

function escapeAttr(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/"/g, "&quot;");
}
