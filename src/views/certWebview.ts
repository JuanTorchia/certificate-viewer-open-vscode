import * as vscode from "vscode";
import { ParsedDocument } from "../models/parsedDocument";
import { CertificateInfo, getCertificateStatus, getDaysUntilExpiry } from "../models/certificate";
import { CsrInfo } from "../parsers/csrParser";
import { formatDate, formatRelativeExpiry, getCertDisplayName, subjectToString } from "../utils/formatters";

export function buildWebviewHtml(
  _webview: vscode.Webview,
  _extensionUri: vscode.Uri,
  doc: ParsedDocument,
  warningDays: number
): string {
  const nonce = getNonce();
  const body = buildBody(doc, warningDays);
  return wrapHtml(nonce, body);
}

// ── Document type dispatchers ─────────────────────────────────────────────────

function buildBody(doc: ParsedDocument, warningDays: number): string {
  switch (doc.type) {
    case "certificates": return buildCertBody(doc.items, warningDays);
    case "csr":          return buildCsrBody(doc.items);
    case "crl":          return buildCrlBody(doc);
    case "pkcs12":       return buildCertBody(doc.items, warningDays);
    case "error":        return buildErrorBody(doc.message, doc.detail);
  }
}

// ── Certificate view ──────────────────────────────────────────────────────────

function buildCertBody(certs: CertificateInfo[], warningDays: number): string {
  if (certs.length === 0) return buildErrorBody("No certificates found", "The file contained no parseable certificate data.");

  const data = certs.map(c => serializeCert(c, warningDays));
  const dataJson = JSON.stringify(data);

  return /* html */`
<div id="app"></div>
<script nonce="{{NONCE}}">
const vscode = acquireVsCodeApi();
const certs = ${dataJson};
let active = 0;

function render() {
  document.getElementById('app').innerHTML = renderApp();
  bindEvents();
}

function renderApp() {
  const tabs = certs.length > 1
    ? '<div class="tabs">' + certs.map((c,i) =>
        '<button class="tab'+(i===active?' active':'')+'" data-i="'+i+'">'+esc(c.displayName)+'</button>'
      ).join('') + '</div>'
    : '';
  return tabs + certs.map((c,i) =>
    '<div class="panel'+(i===active?' active':'')+'" data-p="'+i+'">'+renderCert(c)+'</div>'
  ).join('');
}

function renderCert(c) {
  return banner(c)
    + section('Subject', nameFields(c.subject))
    + section('Issuer', nameFields(c.issuer))
    + section('Validity', validityFields(c))
    + (c.sans.length ? section('Subject Alternative Names', sanTags(c.sans)) : '')
    + (c.keyUsage.length ? section('Key Usage', tags(c.keyUsage)) : '')
    + (c.extKeyUsage.length ? section('Extended Key Usage', tags(c.extKeyUsage)) : '')
    + section('Fingerprints', fingerprintFields(c))
    + section('Details', detailFields(c))
    + '<button class="link-btn" onclick="openRaw()">Open as text ↗</button>';
}

function banner(c) {
  const label = {valid:'Valid',expired:'Expired','expiring-soon':'Expiring Soon','not-yet-valid':'Not Yet Valid'};
  const cls   = {valid:'ok',expired:'err','expiring-soon':'warn','not-yet-valid':'info'};
  return '<div class="banner '+cls[c.status]+'">'+esc(label[c.status])+' — '+esc(c.relExpiry)+'</div>';
}

function section(title, content) {
  return '<details open><summary>'+esc(title)+'</summary><div class="section-body">'+content+'</div></details>';
}

function nameFields(s) {
  return [['Common Name',s.commonName],['Organization',s.org?.join(', ')],
    ['Org. Unit',s.ou?.join(', ')],['Country',s.country?.join(', ')],
    ['State',s.state?.join(', ')],['Locality',s.locality?.join(', ')],
    ['Email',s.email?.join(', ')]]
    .filter(([,v])=>v).map(([k,v])=>row(k,v)).join('');
}

function validityFields(c) {
  return row('Not Before', c.notBefore) + row('Not After', c.notAfter) + row('Status', c.relExpiry);
}

function sanTags(sans) {
  return '<div class="row"><div class="tags">'+
    sans.map(s=>'<span class="tag">'+esc(s.type.toUpperCase())+': '+esc(s.value)+'</span>').join('')+
    '</div></div>';
}

function tags(items) {
  return '<div class="row"><div class="tags">'+
    items.map(t=>'<span class="tag">'+esc(t)+'</span>').join('')+
    '</div></div>';
}

function fingerprintFields(c) {
  return fpRow('SHA-1', c.sha1) + fpRow('SHA-256', c.sha256);
}

function detailFields(c) {
  return row('Serial Number', c.serial)
    + row('Version', 'v'+c.version)
    + row('Public Key', c.pubKey+(c.keySize?' '+c.keySize+' bit':''))
    + row('Signature Algorithm', c.sigAlg)
    + row('Self-Signed', c.selfSigned?'Yes':'No')
    + row('CA Certificate', c.isCA?'Yes':'No');
}

function row(label, value) {
  if (!value) return '';
  return '<div class="row"><span class="lbl">'+esc(label)+'</span><span class="val">'+esc(String(value))+'</span></div>';
}

function fpRow(label, value) {
  return '<div class="row"><span class="lbl">'+esc(label)+'</span><span class="val mono">'+esc(value)+
    '<button class="copy-btn" data-v="'+esc(value)+'">Copy</button></span></div>';
}

function esc(s) {
  return String(s??'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function bindEvents() {
  document.querySelectorAll('.tab').forEach(b=>b.addEventListener('click',()=>{active=+b.dataset.i;render();}));
  document.querySelectorAll('.copy-btn').forEach(b=>b.addEventListener('click',()=>{
    vscode.postMessage({command:'copyText',data:b.dataset.v});
  }));
}

function openRaw() { vscode.postMessage({command:'openRaw'}); }

render();
</script>`;
}

// ── CSR view ──────────────────────────────────────────────────────────────────

function buildCsrBody(csrs: CsrInfo[]): string {
  const items = csrs.map(c => ({
    displayName: c.subject.commonName ?? "Certificate Request",
    subject: {
      commonName: c.subject.commonName,
      org: c.subject.organization,
      ou: c.subject.organizationalUnit,
      country: c.subject.country,
      state: c.subject.state,
      locality: c.subject.locality,
      email: c.subject.emailAddress,
    },
    pubKey: c.publicKeyAlgorithm,
    keySize: c.publicKeySize,
    sigAlg: c.signatureAlgorithm,
    sans: c.subjectAltNames,
  }));

  return /* html */`
<div class="badge-type">CERTIFICATE REQUEST</div>
<div id="app"></div>
<script nonce="{{NONCE}}">
const vscode = acquireVsCodeApi();
const items = ${JSON.stringify(items)};
let active = 0;
function render() {
  document.getElementById('app').innerHTML =
    (items.length > 1 ? '<div class="tabs">'+items.map((c,i)=>'<button class="tab'+(i===active?' active':'')+'" data-i="'+i+'">'+esc(c.displayName)+'</button>').join('')+'</div>' : '') +
    items.map((c,i)=>'<div class="panel'+(i===active?' active':'')+'" data-p="'+i+'">'+renderCsr(c)+'</div>').join('');
  document.querySelectorAll('.tab').forEach(b=>b.addEventListener('click',()=>{active=+b.dataset.i;render();}));
}
function renderCsr(c) {
  return section('Requested Subject', nameFields(c.subject))
    + section('Public Key', row('Algorithm', c.pubKey) + (c.keySize ? row('Key Size', c.keySize+' bit') : ''))
    + row('Signature Algorithm', c.sigAlg)
    + (c.sans.length ? section('Requested SANs', '<div class="row"><div class="tags">'+c.sans.map(s=>'<span class="tag">'+esc(s)+'</span>').join('')+'</div></div>') : '');
}
function section(t,b){return '<details open><summary>'+esc(t)+'</summary><div class="section-body">'+b+'</div></details>';}
function nameFields(s){return[['Common Name',s.commonName],['Organization',s.org?.join(', ')],['Org. Unit',s.ou?.join(', ')],['Country',s.country?.join(', ')],['State',s.state?.join(', ')],['Locality',s.locality?.join(', ')],['Email',s.email?.join(', ')]].filter(([,v])=>v).map(([k,v])=>row(k,v)).join('');}
function row(l,v){if(!v)return'';return'<div class="row"><span class="lbl">'+esc(l)+'</span><span class="val">'+esc(String(v))+'</span></div>';}
function esc(s){return String(s??'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}
render();
</script>`;
}

// ── CRL view ─────────────────────────────────────────────────────────────────

function buildCrlBody(doc: { issuer: string; thisUpdate: string; nextUpdate: string; revokedCount: number; }): string {
  return `
<div class="badge-type">CERTIFICATE REVOCATION LIST</div>
<details open><summary>CRL Info</summary><div class="section-body">
  <div class="row"><span class="lbl">Issuer</span><span class="val">${esc(doc.issuer)}</span></div>
  <div class="row"><span class="lbl">This Update</span><span class="val">${esc(doc.thisUpdate)}</span></div>
  <div class="row"><span class="lbl">Next Update</span><span class="val">${esc(doc.nextUpdate)}</span></div>
  ${doc.revokedCount >= 0 ? `<div class="row"><span class="lbl">Revoked Entries</span><span class="val">${doc.revokedCount}</span></div>` : ""}
</div></details>
<button class="link-btn" onclick="acquireVsCodeApi().postMessage({command:'openRaw'})">Open raw ↗</button>`;
}

// ── Error view ────────────────────────────────────────────────────────────────

function buildErrorBody(message: string, detail?: string): string {
  return `
<div class="error-card">
  <div class="error-title">${esc(message)}</div>
  ${detail ? `<pre class="error-detail">${esc(detail)}</pre>` : ""}
</div>`;
}

// ── Serialization helpers ─────────────────────────────────────────────────────

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
  };
}

function esc(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

// ── HTML shell ────────────────────────────────────────────────────────────────

function wrapHtml(nonce: string, body: string): string {
  const withNonce = body.replace(/\{\{NONCE\}\}/g, nonce);
  return /* html */`<!DOCTYPE html>
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
    .val{font-family:var(--vscode-editor-font-family,monospace);word-break:break-all}
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
<body>${withNonce}</body>
</html>`;
}

function getNonce(): string {
  let t = "";
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  for (let i = 0; i < 32; i++) t += chars[Math.floor(Math.random() * chars.length)];
  return t;
}
