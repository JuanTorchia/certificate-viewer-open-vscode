# Roadmap

This roadmap is intentionally pragmatic. The goal is to make CertView more useful for daily certificate work while keeping parsing safe, offline, and predictable.

## Near Term

- Add more parser fixtures for malformed PEM, large bundles, uncommon extensions, and real-world CSR/CRL edge cases.
- Improve Marketplace presentation with clearer screenshots, badges, keywords, and "offline/no telemetry" positioning.

## Product Improvements

- Add export actions for lint report, certificate metadata JSON, and public key PEM.
- Add optional certificate comparison: fingerprint, subject, issuer, SAN, public key, validity, and extensions.
- Improve diagnostics mapping from file-level findings to more precise PEM block positions.

## Parser and Security Hardening

- Move expensive PKCS#7, PKCS#12, CRL, and large bundle parsing off the extension host hot path (conditional on real extension-host blocking showing up as per [#44](https://github.com/JuanTorchia/certificate-viewer-open-vscode/discussions/44)).
- Add timeout or cancellation-aware parsing boundaries where VS Code APIs allow it.
- Expand DER/ASN.1 malformed-input tests.
- Keep private-key behavior conservative: detect and describe encrypted keys without prompting for decryption.
- Document and test all hard limits: input size, PEM block count, PEM block size, and certificate count.

## Community and Collaboration

- Maintain a short "help wanted" list in GitHub Issues.
- Use small, reviewable PRs with screenshots for UI changes and fixtures for parser changes.
- Publish clear release notes for every Marketplace release.

## Later

- Add localization support if there is sustained contributor interest.
- Add optional trust-store or chain-validation integrations only after a design discussion, because that changes the product's security boundary.
- Explore a dedicated certificate inventory view for workspaces with many certificates.

## Shipped

- Clean VSIX packaging so only runtime assets are published.
- Add issue templates, PR template, contribution guide, security policy, and roadmap links.
- Cache parsed workspace files by URI, size, and mtime to reduce repeated parsing in the explorer and diagnostics.
- Add a compact chain summary showing leaf, intermediates, root, issuer matching, and validity nesting.
- Add configurable workspace scan limits and excludes for large monorepos.
- Label issues by area: parser, webview, diagnostics, docs, good first issue, help wanted, security.
