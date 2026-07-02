// CertView webview script
// Receives data via #__cv data-payload attribute injected by the extension host
(function () {
  const vscode = acquireVsCodeApi();
  var el = document.getElementById('__cv');
  const doc = el ? JSON.parse(el.getAttribute('data-payload') || 'null') : null;

  function esc(s) {
    return String(s == null ? '' : s)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  var HELP = {
    'cert.subject': 'RFC 5280 §4.1.2.6: distinguished name of the entity associated with the public key.',
    'cert.issuer': 'RFC 5280 §4.1.2.4: distinguished name of the certificate issuer.',
    'cert.validity': 'RFC 5280 §4.1.2.5: notBefore/notAfter validity interval.',
    'cert.san': 'RFC 5280 §4.2.1.6; RFC 6125 §6.4.4: subject alternative names and TLS identity guidance.',
    'cert.keyUsage': 'RFC 5280 §4.2.1.3: permitted cryptographic operations.',
    'cert.extKeyUsage': 'RFC 5280 §4.2.1.12: application-specific key purposes.',
    'cert.extensions': 'RFC 5280 §4.2: X.509 v3 extensions; critical extensions must be understood.',
    'cert.basicConstraints': 'RFC 5280 §4.2.1.9: CA flag and optional pathLenConstraint.',
    'cert.nameConstraints': 'RFC 5280 §4.2.1.10: permitted/excluded subject name subtrees.',
    'Fingerprints': 'Digest over DER certificate bytes; useful for comparison, not identity validation.',
    'cert.details': 'RFC 5280 §4.1: TBSCertificate fields and signature metadata.',
    'cert.publicKey': 'RFC 5280 §4.1.2.7: subject public key algorithm and key material.',
    'cert.name.commonName': 'RFC 5280 §4.1.2.4/§4.1.2.6: X.500 commonName; RFC 6125 §6.4.4 prefers subjectAltName for TLS identity.',
    'cert.name.organization': 'RFC 5280 §4.1.2.4/§4.1.2.6: organizationName attribute in a distinguished name.',
    'cert.name.organizationalUnit': 'RFC 5280 §4.1.2.4/§4.1.2.6: organizationalUnitName attribute in a distinguished name.',
    'cert.name.country': 'RFC 5280 §4.1.2.4/§4.1.2.6: countryName attribute in a distinguished name.',
    'cert.name.state': 'RFC 5280 §4.1.2.4/§4.1.2.6: stateOrProvinceName attribute in a distinguished name.',
    'cert.name.locality': 'RFC 5280 §4.1.2.4/§4.1.2.6: localityName attribute in a distinguished name.',
    'cert.name.email': 'RFC 5280 §4.1.2.6 and §4.2.1.6: email identities should be represented as subjectAltName rfc822Name.',
    'cert.validity.notBefore': 'RFC 5280 §4.1.2.5: start of the certificate validity interval.',
    'cert.validity.notAfter': 'RFC 5280 §4.1.2.5: end of the certificate validity interval.',
    'cert.validity.status': 'Advisory local time check against RFC 5280 §4.1.2.5 validity interval.',
    'cert.basicConstraints.ca': 'RFC 5280 §4.2.1.9: CA=true indicates the public key may verify certificate signatures.',
    'cert.basicConstraints.pathLen': 'RFC 5280 §4.2.1.9: maximum number of non-self-issued intermediate CA certificates below this CA.',
    'cert.nameConstraints.value': 'RFC 5280 §4.2.1.10: name constraints for subordinate certificate subject names.',
    'cert.serialNumber': 'RFC 5280 §4.1.2.2: CA-assigned positive serial number unique per issuer.',
    'cert.version': 'RFC 5280 §4.1.2.1: certificate version; extensions require v3.',
    'cert.publicKey.summary': 'RFC 5280 §4.1.2.7: subject public key algorithm and encoded key material.',
    'cert.publicKey.curve': 'Named curve from the SubjectPublicKeyInfo parameters when the certificate uses an elliptic-curve key.',
    'cert.publicKey.exponent': 'RSA public exponent from the SubjectPublicKeyInfo public key value.',
    'cert.signatureAlgorithm': 'RFC 5280 §4.1.1.2 and §4.1.2.3: algorithm used by the issuer to sign the certificate.',
    'cert.selfSigned': 'RFC 5280 §6: self-signed status alone does not establish trust.',
    'cert.isCA': 'RFC 5280 §4.2.1.9: CA status is indicated by Basic Constraints CA=true.',
    'cert.publicKey.pem': 'RFC 5280 §4.1.2.7: exported SubjectPublicKeyInfo PEM for the parsed certificate key.',
    'cert.fingerprint.sha1': 'Local SHA-1 digest over DER certificate bytes; identifier aid, not a trust decision.',
    'cert.fingerprint.sha256': 'Local SHA-256 digest over DER certificate bytes for comparison and inventory.',
    'key.kind': 'Public or private key object parsed from PEM, DER, or JWK input.',
    'key.algorithm': 'RFC 5280 §4.1.2.7 for SubjectPublicKeyInfo; RFC 5958 for private-key packages.',
    'key.publicExponent': 'RSA public exponent from the parsed public key or derived public key.',
    'key.format': 'RFC 7468 covers textual PEM; ITU-T X.690 / ISO/IEC 8825-1 covers DER; RFC 7517 covers JWK.',
    'key.encrypted': 'RFC 5958: EncryptedPrivateKeyInfo indicates password-based protection; CertView does not decrypt it.',
    'key.note': 'Security note for key handling in this viewer.',
    'key.publicKeyPem': 'RFC 5280 §4.1.2.7: exported SubjectPublicKeyInfo PEM derived from the parsed key.',
    'key.spki.sha1': 'SHA-1 digest over the DER-encoded SubjectPublicKeyInfo for the parsed key; useful for key continuity checks, not trust validation.',
    'key.spki.sha256': 'SHA-256 digest over the DER-encoded SubjectPublicKeyInfo for the parsed key; useful for key inventory and comparison.',
    'csr.subject': 'RFC 2986 §4.1: CertificationRequestInfo subject requested by the applicant.',
    'csr.publicKey': 'RFC 2986 §4.1: SubjectPublicKeyInfo included in the certification request.',
    'csr.signatureAlgorithm': 'RFC 2986 §4.1: algorithm used to sign the certification request.',
    'crl.info': 'RFC 5280 §5.1: certificate revocation list fields.',
    'crl.issuer': 'RFC 5280 §5.1.2.3: name of the entity that signed and issued the CRL.',
    'crl.thisUpdate': 'RFC 5280 §5.1.2.4: CRL issue date.',
    'crl.nextUpdate': 'RFC 5280 §5.1.2.5: date by which the next CRL will be issued.',
    'crl.revokedEntries': 'RFC 5280 §5.1.2.6: sequence of revoked certificate entries.'
  };

  var EXT_HELP = {
    '2.5.29.14': 'RFC 5280 §4.2.1.2: Subject Key Identifier identifies certificates containing a particular public key.',
    '2.5.29.35': 'RFC 5280 §4.2.1.1: Authority Key Identifier helps identify the issuing CA key.',
    '2.5.29.15': 'RFC 5280 §4.2.1.3: Key Usage restricts permitted cryptographic operations.',
    '2.5.29.37': 'RFC 5280 §4.2.1.12: Extended Key Usage indicates application-specific purposes.',
    '2.5.29.17': 'RFC 5280 §4.2.1.6: Subject Alternative Name carries DNS, IP, email, URI, and other identities.',
    '2.5.29.19': 'RFC 5280 §4.2.1.9: Basic Constraints identifies CA certificates and path length limits.',
    '2.5.29.30': 'RFC 5280 §4.2.1.10: Name Constraints limits permitted and excluded subject name spaces for subordinate CAs.',
    '2.5.29.31': 'RFC 5280 §4.2.1.13: CRL Distribution Points identifies where revocation lists may be obtained.',
    '1.3.6.1.5.5.7.1.1': 'RFC 5280 §4.2.2.1: Authority Information Access may identify OCSP responders and issuer certificate locations.',
    '2.5.29.32': 'RFC 5280 §4.2.1.4: Certificate Policies identifies policy OIDs applicable to the certificate.',
    '1.3.6.1.5.5.7.1.24': 'RFC 7633: TLS Feature extension, commonly used for OCSP Must-Staple.',
    '1.3.6.1.4.1.11129.2.4.2': 'RFC 6962: embedded Signed Certificate Timestamp list for Certificate Transparency.'
  };

  function hint(text) { return text ? ' title="' + esc(text) + '"' : ''; }

  function help(text) {
    return text ? '<span class="help" tabindex="0" role="note" data-help="' + esc(text) + '" title="' + esc(text) + '">?</span>' : '';
  }

  function row(fieldId, label, value) {
    if (arguments.length === 2) { value = label; label = fieldId; fieldId = label; }
    if (value === null || value === undefined || value === '') { return ''; }
    var h = HELP[fieldId] || HELP[label];
    return '<div class="row"' + hint(h) + '><span class="lbl">' + esc(label) + help(h) + '</span><span class="val">' + esc(String(value)) + '</span></div>';
  }

  function fpRow(fieldId, label, value) {
    return '<div class="row"' + hint(HELP[fieldId]) + '><span class="lbl">' + esc(label) + help(HELP[fieldId]) + '</span><span class="val mono">' + esc(value) +
      '<button class="copy-btn" data-v="' + esc(value) + '">Copy</button></span></div>';
  }

  function tags(fieldId, items) {
    return '<div class="row"><div class="tags">' +
      items.map(function (t) { return '<span class="tag"' + hint(HELP[fieldId]) + '>' + esc(t) + '</span>'; }).join('') +
      '</div></div>';
  }

  function ekuTags(items, details) {
    var byKey = (details || []).reduce(function (acc, item) { acc[item.key] = item; return acc; }, {});
    return '<div class="row"><div class="tags">' +
      items.map(function (t) {
        var detail = byKey[t] || {};
        var tip = detail.name ? detail.name + (detail.oid ? ' (' + detail.oid + ')' : '') : HELP['cert.extKeyUsage'];
        return '<span class="tag"' + hint(tip) + '>' + esc(t) + '</span>';
      }).join('') +
      '</div></div>';
  }

  function sanTags(sans) {
    return '<div class="row"><div class="tags">' +
      sans.map(function (s) { return '<span class="tag"' + hint(HELP['cert.san']) + '>' + esc(s.type.toUpperCase()) + ': ' + esc(s.value) + '</span>'; }).join('') +
      '</div></div>';
  }

  function section(fieldId, title, content) {
    if (arguments.length === 2) { content = title; title = fieldId; fieldId = title; }
    var h = HELP[fieldId] || HELP[title];
    return '<details open><summary' + hint(h) + '>' + esc(title) + help(h) + '</summary><div class="section-body">' + content + '</div></details>';
  }

  function validationBanner(findings, report) {
    if (!findings || !findings.length) {
      return '<div class="banner ok" title="Basic CertView lint checks passed; this is not a full compliance validation.">No lint findings' + (report ? '<button class="copy-btn" data-v="' + esc(report) + '">Copy lint report</button>' : '') + '</div>';
    }
    var counts = findings.reduce(function (acc, f) { acc[f.severity] = (acc[f.severity] || 0) + 1; return acc; }, {});
    var cls = findings.some(function (f) { return f.severity === 'error'; }) ? 'err' : findings.some(function (f) { return f.severity === 'warning'; }) ? 'warn' : 'info';
    return '<div class="banner ' + cls + '"><div>Lint findings: ' + (counts.error || 0) + ' errors / ' + (counts.warning || 0) + ' warnings / ' + (counts.info || 0) + ' info' + (report ? '<button class="copy-btn" data-v="' + esc(report) + '">Copy lint report</button>' : '') + '</div><ul>' +
      findings.map(function (f) { return '<li data-severity="' + esc(f.severity) + '"><strong>' + esc(f.severity.toUpperCase()) + '</strong>: ' + esc(f.message) + (f.rfc ? ' (' + esc(f.rfc) + ')' : '') + '</li>'; }).join('') +
      '</ul></div>';
  }

  function extensionRows(exts) {
    return exts.map(function (e) {
      var label = e.name + ' (' + e.oid + (e.critical ? ', critical' : ', noncritical') + ')';
      var value = e.value || '(present)';
      var h = EXT_HELP[e.oid] || 'RFC 5280 §4.2: X.509 v3 extension.';
      return '<div class="row"' + hint(h) + '><span class="lbl">' + esc(label) + help(h) + '</span><span class="val">' + esc(value) + '<button class="copy-btn" data-v="' + esc(value) + '">Copy</button></span></div>';
    }).join('');
  }

  function nameFields(s) {
    return [
      ['cert.name.commonName', 'Common Name', s.commonName],
      ['cert.name.organization', 'Organization', s.org ? s.org.join(', ') : null],
      ['cert.name.organizationalUnit', 'Org. Unit', s.ou ? s.ou.join(', ') : null],
      ['cert.name.country', 'Country', s.country ? s.country.join(', ') : null],
      ['cert.name.state', 'State', s.state ? s.state.join(', ') : null],
      ['cert.name.locality', 'Locality', s.locality ? s.locality.join(', ') : null],
      ['cert.name.email', 'Email', s.email ? s.email.join(', ') : null],
    ].filter(function (pair) { return pair[2]; })
      .map(function (pair) { return row(pair[0], pair[1], pair[2]); }).join('');
  }

  // ── Certificate view ────────────────────────────────────────────────────────

  function renderCerts(certs, warningDays, targetId) {
    var active = 0;
    targetId = targetId || 'app';

    function banner(c) {
      var labels = { valid: 'Valid', expired: 'Expired', 'expiring-soon': 'Expiring Soon', 'not-yet-valid': 'Not Yet Valid' };
      var cls = { valid: 'ok', expired: 'err', 'expiring-soon': 'warn', 'not-yet-valid': 'info' };
      return '<div class="banner ' + cls[c.status] + '">' + esc(labels[c.status]) + ' \u2014 ' + esc(c.relExpiry) + '</div>';
    }

    function renderCert(c) {
      return validationBanner(c.findings, c.lintReport)
        + banner(c)
        + section('cert.subject', 'Subject', nameFields(c.subject))
        + section('cert.issuer', 'Issuer', nameFields(c.issuer))
        + section('cert.validity', 'Validity',
          row('cert.validity.notBefore', 'Not Before', c.notBefore) + row('cert.validity.notAfter', 'Not After', c.notAfter) + row('cert.validity.status', 'Status', c.relExpiry))
        + (c.sans.length ? section('cert.san', 'Subject Alternative Names', sanTags(c.sans)) : '')
        + (c.keyUsage.length ? section('cert.keyUsage', 'Key Usage', tags('cert.keyUsage', c.keyUsage)) : '')
        + (c.extKeyUsage.length ? section('cert.extKeyUsage', 'Extended Key Usage', ekuTags(c.extKeyUsage, c.extKeyUsageDetails)) : '')
        + (c.basicConstraints ? section('cert.basicConstraints', 'Basic Constraints', row('cert.basicConstraints.ca', 'CA Certificate', c.basicConstraints.ca ? 'Yes' : 'No') + row('cert.basicConstraints.pathLen', 'Path Length', c.basicConstraints.pathLenConstraint)) : '')
        + (c.nameConstraints ? section('cert.nameConstraints', 'Name Constraints', row('cert.nameConstraints.value', 'Constraints', c.nameConstraints)) : '')
        + (c.extensions && c.extensions.length ? section('cert.extensions', 'Extensions', extensionRows(c.extensions)) : '')
        + section('Fingerprints', fpRow('cert.fingerprint.sha1', 'SHA-1', c.sha1) + fpRow('cert.fingerprint.sha256', 'SHA-256', c.sha256))
        + section('cert.details', 'Details',
          row('cert.serialNumber', 'Serial Number', c.serial)
          + row('cert.version', 'Version', 'v' + c.version)
          + row('cert.publicKey.summary', 'Public Key', c.pubKeyDisplay || (c.pubKey + (c.keySize ? ' ' + c.keySize + ' bit' : '')))
          + row('cert.publicKey.curve', 'Named Curve', c.keyCurve)
          + row('cert.publicKey.exponent', 'Public Exponent', c.keyExponent)
          + row('cert.signatureAlgorithm', 'Signature Algorithm', c.sigAlg)
          + row('cert.selfSigned', 'Self-Signed', c.selfSigned ? 'Yes' : 'No')
          + row('cert.isCA', 'CA Certificate', c.isCA ? 'Yes' : 'No'))
        + (c.publicKeyPem ? section('cert.publicKey', 'Public Key', row('cert.publicKey.pem', 'Public Key PEM', c.publicKeyPem)) : '')
        + '<button class="link-btn" data-action="openRaw">Open as text \u2197</button>';
    }

    function render() {
      var tabs = certs.length > 1
        ? '<div class="tabs">' + certs.map(function (c, i) {
          return '<button class="tab' + (i === active ? ' active' : '') + '" data-i="' + i + '">' + esc(c.displayName) + '</button>';
        }).join('') + '</div>'
        : '';
      var panels = certs.map(function (c, i) {
        return '<div class="panel' + (i === active ? ' active' : '') + '" data-p="' + i + '">' + renderCert(c) + '</div>';
      }).join('');
      document.getElementById(targetId).innerHTML = tabs + panels;
      wireActions(targetId, function (button) { active = parseInt(button.dataset.i, 10); render(); });
    }

    render();
  }

  // ── CSR view ────────────────────────────────────────────────────────────────

  function renderCsrs(csrs) {
    var active = 0;

    function renderCsr(c) {
      return '<div class="badge-type">CERTIFICATE SIGNING REQUEST</div>'
        + section('csr.subject', 'Subject', nameFields(c.subject))
        + section('csr.publicKey', 'Public Key',
          row('csr.publicKey', 'Algorithm', c.pubKeyDisplay || (c.pubKey + (c.keySize ? ' ' + c.keySize + ' bit' : '')))
          + row('cert.publicKey.curve', 'Named Curve', c.keyCurve)
          + row('cert.publicKey.exponent', 'Public Exponent', c.keyExponent)
          + row('csr.signatureAlgorithm', 'Signature Algorithm', c.sigAlg))
        + (c.sans && c.sans.length ? section('cert.san', 'Subject Alternative Names', tags('cert.san', c.sans)) : '')
        + (c.requestedExtensions && c.requestedExtensions.length ? section('cert.extensions', 'Requested Extensions', tags('cert.extensions', c.requestedExtensions)) : '')
        + section('Fingerprints', fpRow('cert.fingerprint.sha1', 'CSR SHA-1', c.fingerprints.sha1) + fpRow('cert.fingerprint.sha256', 'CSR SHA-256', c.fingerprints.sha256) + (c.spkiFingerprints ? fpRow('key.spki.sha1', 'SPKI SHA-1', c.spkiFingerprints.sha1) + fpRow('key.spki.sha256', 'SPKI SHA-256', c.spkiFingerprints.sha256) : ''))
        + (c.publicKeyPem ? section('cert.publicKey', 'Public Key PEM', row('key.publicKeyPem', 'Public Key PEM', c.publicKeyPem)) : '');
    }

    function render() {
      var tabsHtml = csrs.length > 1
        ? '<div class="tabs">' + csrs.map(function (c, i) {
          return '<button class="tab' + (i === active ? ' active' : '') + '" data-i="' + i + '">' + esc(c.displayName) + '</button>';
        }).join('') + '</div>'
        : '';
      var panels = csrs.map(function (c, i) {
        return '<div class="panel' + (i === active ? ' active' : '') + '" data-p="' + i + '">' + renderCsr(c) + '</div>';
      }).join('');
      document.getElementById('app').innerHTML = tabsHtml + panels;
      wireActions('app', function (button) { active = parseInt(button.dataset.i, 10); render(); });
    }

    render();
  }

  // ── CRL view ────────────────────────────────────────────────────────────────

  function renderCrl(data) {
    var html = '<div class="badge-type">CERTIFICATE REVOCATION LIST</div>'
      + section('crl.info', 'CRL Info',
        row('crl.issuer', 'Issuer', data.issuer)
        + row('crl.thisUpdate', 'This Update', data.thisUpdate)
        + row('crl.nextUpdate', 'Next Update', data.nextUpdate)
        + row('cert.signatureAlgorithm', 'Signature Algorithm', data.signatureAlgorithm)
        + row('cert.extensions', 'CRL Number', data.crlNumber)
        + row('cert.extensions', 'Authority Key Identifier', data.authorityKeyIdentifier)
        + (data.fingerprints ? fpRow('cert.fingerprint.sha1', 'SHA-1', data.fingerprints.sha1) + fpRow('cert.fingerprint.sha256', 'SHA-256', data.fingerprints.sha256) : '')
        + (data.revokedCount >= 0 ? row('crl.revokedEntries', 'Revoked Entries', String(data.revokedCount)) : ''))
      + '<button class="link-btn" data-action="openRaw">Open raw \u2197</button>';
    document.getElementById('app').innerHTML = html;
    wireActions('app');
  }

  function renderKeys(keys, targetId) {
    targetId = targetId || 'app';
    var html = keys.map(function (k) {
      return '<div class="badge-type">' + esc(k.kind.toUpperCase()) + ' KEY</div>'
        + section('cert.publicKey', 'Public Key', row('key.algorithm', 'Algorithm', k.display || (k.algorithm + (k.keySize ? ' ' + k.keySize + ' bit' : '') + (k.curve ? ' ' + k.curve : '')))
          + row('key.format', 'Format', k.format)
          + row('key.publicExponent', 'Public Exponent', k.publicExponent)
          + row('key.encrypted', 'Encrypted', k.encrypted ? 'Yes' : '')
          + row('key.note', 'Note', k.note)
          + (k.spkiFingerprints ? section('Fingerprints', fpRow('key.spki.sha1', 'SPKI SHA-1', k.spkiFingerprints.sha1) + fpRow('key.spki.sha256', 'SPKI SHA-256', k.spkiFingerprints.sha256)) : '')
          + row('key.publicKeyPem', 'Public Key PEM', k.publicKeyPem));
    }).join('');
    document.getElementById(targetId).innerHTML = html;
    wireActions(targetId);
  }

  function wireActions(targetId, onTab) {
    var root = document.getElementById(targetId);
    if (!root || root.dataset.actionsWired === 'true') return;
    root.dataset.actionsWired = 'true';
    root.addEventListener('click', function (event) {
      var target = event.target;
      if (!target || !target.closest) return;
      var copy = target.closest('.copy-btn');
      if (copy && root.contains(copy)) {
        vscode.postMessage({ command: 'copyText', data: copy.dataset.v });
        return;
      }
      var tab = target.closest('.tab');
      if (tab && root.contains(tab) && onTab) {
        onTab(tab);
        return;
      }
      var openRaw = target.closest('[data-action="openRaw"]');
      if (openRaw && root.contains(openRaw)) vscode.postMessage({ command: 'openRaw' });
    });
  }

  function renderBundle(data) {
    document.getElementById('app').innerHTML = '<h2>Certificates</h2><div id="certBundle"></div><h2>Keys</h2><div id="keyBundle"></div>';
    renderCerts(data.certs, data.warningDays, 'certBundle');
    renderKeys(data.keys, 'keyBundle');
  }

  // ── Error view ───────────────────────────────────────────────────────────────

  function renderError(message, detail) {
    document.getElementById('app').innerHTML =
      '<div class="error-card"><div class="error-title">' + esc(message) + '</div>'
      + (detail ? '<pre class="error-detail">' + esc(detail) + '</pre>' : '')
      + '</div>';
  }

  // ── Dispatch ─────────────────────────────────────────────────────────────────

  if (!doc) { renderError('No data received', ''); return; }

  switch (doc.type) {
    case 'certificates': renderCerts(doc.certs, doc.warningDays); break;
    case 'bundle': renderBundle(doc); break;
    case 'csr': renderCsrs(doc.csrs); break;
    case 'crl': renderCrl(doc.crl); break;
    case 'keys': renderKeys(doc.keys); break;
    case 'error': renderError(doc.message, doc.detail); break;
    default: renderError('Unknown document type', '');
  }
}());
