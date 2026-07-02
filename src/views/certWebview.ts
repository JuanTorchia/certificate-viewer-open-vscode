import * as vscode from "vscode";
import * as crypto from "crypto";
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
    body{font-family:var(--vscode-font-family,system-ui,-apple-system,"Segoe UI",sans-serif);font-size:var(--vscode-font-size,13px);
         color:var(--vscode-foreground,#d4d4d4);background:var(--vscode-editor-background,#1e1e1e);padding:16px}
    .tabs{display:flex;gap:4px;border-bottom:1px solid var(--vscode-panel-border,#3c3c3c);margin-bottom:12px;padding-bottom:4px}
    .tab{background:none;border:none;color:var(--vscode-foreground,#d4d4d4);cursor:pointer;padding:4px 12px;
         border-radius:4px 4px 0 0;opacity:.6;font-size:var(--vscode-font-size,13px)}
    .tab.active{opacity:1;background:var(--vscode-tab-activeBackground,#252526);
                border-bottom:2px solid var(--vscode-focusBorder,#007fd4)}
    .panel{display:none}.panel.active{display:block}
    .banner{padding:8px 12px;border-radius:6px;margin-bottom:12px;font-weight:600}
    .banner.ok  {background:rgba(0,200,100,.15);color:#4ec994}
    .banner.warn{background:rgba(255,180,0,.15);color:#e5a500}
    .banner.err {background:rgba(220,50,50,.15);color:#f14c4c}
    .banner.info{background:rgba(100,150,255,.15);color:#82b1ff}
    details{border:1px solid var(--vscode-panel-border,#3c3c3c);border-radius:6px;margin-bottom:8px;overflow:hidden}
    summary{padding:8px 12px;background:var(--vscode-sideBarSectionHeader-background,#2d2d30);
            cursor:pointer;font-weight:600;font-size:.85em;text-transform:uppercase;letter-spacing:.04em;
            list-style:none}
    summary::-webkit-details-marker{display:none}
    details[open] summary{border-bottom:1px solid var(--vscode-panel-border,#3c3c3c)}
    .section-body{padding:4px 0}
    .row{display:grid;grid-template-columns:160px 1fr;gap:4px;padding:4px 12px;
         border-bottom:1px solid var(--vscode-panel-border,#3c3c3c)}
    .row:last-child{border-bottom:none}
    .lbl{color:var(--vscode-descriptionForeground,#9d9d9d);font-size:.9em;align-self:start;padding-top:1px}
    .val{font-family:var(--vscode-editor-font-family,ui-monospace,SFMono-Regular,Consolas,monospace);word-break:break-all;white-space:pre-wrap}
    .mono{font-family:var(--vscode-editor-font-family,ui-monospace,SFMono-Regular,Consolas,monospace)}
    .tags{display:flex;flex-wrap:wrap;gap:4px}
    .tag{padding:2px 8px;border-radius:12px;background:var(--vscode-badge-background,#4d4d4d);
         color:var(--vscode-badge-foreground,#fff);font-size:.8em}
    .copy-btn{margin-left:8px;padding:1px 6px;background:none;cursor:pointer;
               border:1px solid var(--vscode-panel-border,#3c3c3c);border-radius:4px;
               color:var(--vscode-foreground,#d4d4d4);font-size:.78em}
    .copy-btn:hover{background:var(--vscode-button-secondaryHoverBackground,#3a3d41)}
    .link-btn{margin-top:8px;background:none;border:none;
               color:var(--vscode-textLink-foreground,#3794ff);cursor:pointer;
              text-decoration:underline;font-size:.85em}
    .badge-type{display:inline-block;padding:3px 10px;border-radius:12px;
                 background:var(--vscode-badge-background,#4d4d4d);color:var(--vscode-badge-foreground,#fff);
                font-size:.78em;font-weight:700;letter-spacing:.05em;margin-bottom:12px}
    .error-card{padding:16px;border:1px solid rgba(220,50,50,.4);border-radius:6px;
                background:rgba(220,50,50,.08)}
    .error-title{font-weight:700;color:#f14c4c;margin-bottom:8px}
    .error-detail{font-family:var(--vscode-editor-font-family,ui-monospace,SFMono-Regular,Consolas,monospace);font-size:.85em;
                  white-space:pre-wrap;word-break:break-all;
                  color:var(--vscode-descriptionForeground,#9d9d9d)}
    .help{display:inline-flex;align-items:center;justify-content:center;margin-left:6px;width:14px;height:14px;border-radius:50%;
          border:1px solid var(--vscode-descriptionForeground,#9d9d9d);color:var(--vscode-descriptionForeground,#9d9d9d);font-size:10px;font-weight:700;position:relative}
    .help:hover::after,.help:focus::after{content:attr(data-help);position:absolute;z-index:10;left:18px;top:-4px;width:320px;
          padding:8px;border:1px solid var(--vscode-panel-border,#3c3c3c);border-radius:6px;background:var(--vscode-editorHoverWidget-background,#252526);
          color:var(--vscode-editorHoverWidget-foreground,#d4d4d4);box-shadow:0 2px 8px rgba(0,0,0,.35);font-size:12px;font-weight:400;line-height:1.35;text-transform:none;letter-spacing:normal}
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
    case "bundle":
      return { type: "bundle", certs: doc.certificates.map(c => serializeCert(c, warningDays)), keys: doc.keys, warningDays };
    case "csr":
      return { type: "csr", csrs: doc.items.map(serializeCsr) };
    case "crl":
      return { type: "crl", crl: { issuer: doc.issuer, thisUpdate: doc.thisUpdate, nextUpdate: doc.nextUpdate, revokedCount: doc.revokedCount, signatureAlgorithm: doc.signatureAlgorithm, crlNumber: doc.crlNumber, authorityKeyIdentifier: doc.authorityKeyIdentifier, fingerprints: doc.fingerprints } };
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
    pubKeyDisplay: csr.publicKeyDisplay,
    keySize: csr.publicKeySize,
    keyCurve: csr.publicKeyCurve,
    keyExponent: csr.publicKeyExponent,
    publicKeyPem: csr.publicKeyPem,
    spkiFingerprints: csr.spkiFingerprints,
    fingerprints: csr.fingerprints,
    sigAlg: csr.signatureAlgorithm,
    sans: csr.subjectAltNames,
    requestedExtensions: csr.requestedExtensions,
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
    extKeyUsageDetails: cert.extendedKeyUsageDetails,
    sha1: cert.fingerprints.sha1,
    sha256: cert.fingerprints.sha256,
    pubKey: cert.publicKeyAlgorithm,
    pubKeyDisplay: cert.publicKeyDisplay,
    keySize: cert.publicKeySize,
    keyCurve: cert.publicKeyCurve,
    keyExponent: cert.publicKeyExponent,
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
  return crypto.randomBytes(16).toString("base64url");
}

function escapeAttr(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/"/g, "&quot;");
}
