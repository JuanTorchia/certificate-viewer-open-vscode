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
    'Subject': 'RFC 5280 section 4.1.2.6: entity associated with the public key.',
    'Issuer': 'RFC 5280 section 4.1.2.4: CA that signed the certificate.',
    'Validity': 'RFC 5280 section 4.1.2.5: notBefore/notAfter validity interval.',
    'Subject Alternative Names': 'RFC 5280 section 4.2.1.6; RFC 6125 uses SAN for TLS identity checks.',
    'Key Usage': 'RFC 5280 section 4.2.1.3: permitted cryptographic operations.',
    'Extended Key Usage': 'RFC 5280 section 4.2.1.12: application-specific key purposes.',
    'Extensions': 'RFC 5280 section 4.2: X.509 v3 extensions; critical extensions must be understood.',
    'Basic Constraints': 'RFC 5280 section 4.2.1.9: CA flag and optional pathLenConstraint.',
    'Name Constraints': 'RFC 5280 section 4.2.1.10: permitted/excluded subject name subtrees.',
    'Fingerprints': 'Digest over DER certificate bytes; useful for comparison, not identity validation.',
    'Public Key': 'RFC 5280 section 4.1.2.7: subject public key algorithm and key material.'
  };

  function hint(text) { return text ? ' title="' + esc(text) + '"' : ''; }

  function row(label, value) {
    if (value === null || value === undefined || value === '') { return ''; }
    return '<div class="row"' + hint(HELP[label]) + '><span class="lbl">' + esc(label) + '</span><span class="val">' + esc(String(value)) + '</span></div>';
  }

  function fpRow(label, value) {
    return '<div class="row"><span class="lbl">' + esc(label) + '</span><span class="val mono">' + esc(value) +
      '<button class="copy-btn" data-v="' + esc(value) + '">Copy</button></span></div>';
  }

  function tags(items) {
    return '<div class="row"><div class="tags">' +
      items.map(function (t) { return '<span class="tag">' + esc(t) + '</span>'; }).join('') +
      '</div></div>';
  }

  function sanTags(sans) {
    return '<div class="row"><div class="tags">' +
      sans.map(function (s) { return '<span class="tag">' + esc(s.type.toUpperCase()) + ': ' + esc(s.value) + '</span>'; }).join('') +
      '</div></div>';
  }

  function section(title, content) {
    return '<details open><summary' + hint(HELP[title]) + '>' + esc(title) + '</summary><div class="section-body">' + content + '</div></details>';
  }

  function validationBanner(findings) {
    if (!findings || !findings.length) {
      return '<div class="banner ok" title="Basic CertView lint checks passed; this is not a full compliance validation.">No lint findings</div>';
    }
    var counts = findings.reduce(function (acc, f) { acc[f.severity] = (acc[f.severity] || 0) + 1; return acc; }, {});
    var cls = findings.some(function (f) { return f.severity === 'error'; }) ? 'err' : findings.some(function (f) { return f.severity === 'warning'; }) ? 'warn' : 'info';
    return '<div class="banner ' + cls + '"><div>Lint findings: ' + (counts.error || 0) + ' errors / ' + (counts.warning || 0) + ' warnings / ' + (counts.info || 0) + ' info</div><ul>' +
      findings.map(function (f) { return '<li data-severity="' + esc(f.severity) + '"><strong>' + esc(f.severity.toUpperCase()) + '</strong>: ' + esc(f.message) + (f.rfc ? ' (' + esc(f.rfc) + ')' : '') + '</li>'; }).join('') +
      '</ul></div>';
  }

  function extensionRows(exts) {
    return exts.map(function (e) {
      var label = e.name + ' (' + e.oid + (e.critical ? ', critical' : ', noncritical') + ')';
      var value = e.value || '(present)';
      return '<div class="row"><span class="lbl">' + esc(label) + '</span><span class="val">' + esc(value) + '<button class="copy-btn" data-v="' + esc(value) + '">Copy</button></span></div>';
    }).join('');
  }

  function nameFields(s) {
    return [
      ['Common Name', s.commonName],
      ['Organization', s.org ? s.org.join(', ') : null],
      ['Org. Unit', s.ou ? s.ou.join(', ') : null],
      ['Country', s.country ? s.country.join(', ') : null],
      ['State', s.state ? s.state.join(', ') : null],
      ['Locality', s.locality ? s.locality.join(', ') : null],
      ['Email', s.email ? s.email.join(', ') : null],
    ].filter(function (pair) { return pair[1]; })
      .map(function (pair) { return row(pair[0], pair[1]); }).join('');
  }

  // ── Certificate view ────────────────────────────────────────────────────────

  function renderCerts(certs, warningDays) {
    var active = 0;

    function banner(c) {
      var labels = { valid: 'Valid', expired: 'Expired', 'expiring-soon': 'Expiring Soon', 'not-yet-valid': 'Not Yet Valid' };
      var cls = { valid: 'ok', expired: 'err', 'expiring-soon': 'warn', 'not-yet-valid': 'info' };
      return '<div class="banner ' + cls[c.status] + '">' + esc(labels[c.status]) + ' \u2014 ' + esc(c.relExpiry) + '</div>';
    }

    function renderCert(c) {
      return validationBanner(c.findings)
        + banner(c)
        + section('Subject', nameFields(c.subject))
        + section('Issuer', nameFields(c.issuer))
        + section('Validity',
          row('Not Before', c.notBefore) + row('Not After', c.notAfter) + row('Status', c.relExpiry))
        + (c.sans.length ? section('Subject Alternative Names', sanTags(c.sans)) : '')
        + (c.keyUsage.length ? section('Key Usage', tags(c.keyUsage)) : '')
        + (c.extKeyUsage.length ? section('Extended Key Usage', tags(c.extKeyUsage)) : '')
        + (c.basicConstraints ? section('Basic Constraints', row('CA Certificate', c.basicConstraints.ca ? 'Yes' : 'No') + row('Path Length', c.basicConstraints.pathLenConstraint)) : '')
        + (c.nameConstraints ? section('Name Constraints', row('Constraints', c.nameConstraints)) : '')
        + (c.extensions && c.extensions.length ? section('Extensions', extensionRows(c.extensions)) : '')
        + section('Fingerprints', fpRow('SHA-1', c.sha1) + fpRow('SHA-256', c.sha256))
        + section('Details',
          row('Serial Number', c.serial)
          + row('Version', 'v' + c.version)
          + row('Public Key', c.pubKey + (c.keySize ? ' ' + c.keySize + ' bit' : ''))
          + row('Signature Algorithm', c.sigAlg)
          + row('Self-Signed', c.selfSigned ? 'Yes' : 'No')
          + row('CA Certificate', c.isCA ? 'Yes' : 'No'))
        + (c.publicKeyPem ? section('Public Key', row('Public Key PEM', c.publicKeyPem)) : '')
        + '<button class="link-btn" id="openRawBtn">Open as text \u2197</button>';
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
      document.getElementById('app').innerHTML = tabs + panels;

      document.querySelectorAll('.tab').forEach(function (b) {
        b.addEventListener('click', function () { active = parseInt(b.dataset.i, 10); render(); });
      });
      document.querySelectorAll('.copy-btn').forEach(function (b) {
        b.addEventListener('click', function () { vscode.postMessage({ command: 'copyText', data: b.dataset.v }); });
      });
      var openBtn = document.getElementById('openRawBtn');
      if (openBtn) {
        openBtn.addEventListener('click', function () { vscode.postMessage({ command: 'openRaw' }); });
      }
    }

    render();
  }

  // ── CSR view ────────────────────────────────────────────────────────────────

  function renderCsrs(csrs) {
    var active = 0;

    function renderCsr(c) {
      return '<div class="badge-type">CERTIFICATE SIGNING REQUEST</div>'
        + section('Subject', nameFields(c.subject))
        + section('Public Key',
          row('Algorithm', c.pubKey + (c.keySize ? ' ' + c.keySize + ' bit' : ''))
          + row('Signature Algorithm', c.sigAlg))
        + (c.sans && c.sans.length ? section('Subject Alternative Names', sanTags(c.sans)) : '');
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
      document.querySelectorAll('.tab').forEach(function (b) {
        b.addEventListener('click', function () { active = parseInt(b.dataset.i, 10); render(); });
      });
    }

    render();
  }

  // ── CRL view ────────────────────────────────────────────────────────────────

  function renderCrl(data) {
    var html = '<div class="badge-type">CERTIFICATE REVOCATION LIST</div>'
      + '<details open><summary>CRL Info</summary><div class="section-body">'
      + row('Issuer', data.issuer)
      + row('This Update', data.thisUpdate)
      + row('Next Update', data.nextUpdate)
      + (data.revokedCount >= 0 ? row('Revoked Entries', String(data.revokedCount)) : '')
      + '</div></details>'
      + '<button class="link-btn" id="openRawBtn">Open raw \u2197</button>';
    document.getElementById('app').innerHTML = html;
    var btn = document.getElementById('openRawBtn');
    if (btn) {
      btn.addEventListener('click', function () { vscode.postMessage({ command: 'openRaw' }); });
    }
  }

  function renderKeys(keys) {
    var html = keys.map(function (k) {
      return '<div class="badge-type">' + esc(k.kind.toUpperCase()) + ' KEY</div>'
        + section('Public Key', row('Algorithm', k.algorithm + (k.keySize ? ' ' + k.keySize + ' bit' : '') + (k.curve ? ' ' + k.curve : ''))
          + row('Format', k.format)
          + row('Public Key PEM', k.publicKeyPem));
    }).join('');
    document.getElementById('app').innerHTML = html;
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
    case 'csr': renderCsrs(doc.csrs); break;
    case 'crl': renderCrl(doc.crl); break;
    case 'keys': renderKeys(doc.keys); break;
    case 'error': renderError(doc.message, doc.detail); break;
    default: renderError('Unknown document type', '');
  }
}());
