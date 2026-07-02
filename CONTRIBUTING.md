# Contributing to X509 Certificate Utility

Thanks for helping improve CertView. This project is useful only if certificate behavior is predictable, well-tested, and clear to users who are not PKI specialists.

## Good First Contributions

- Add or improve certificate, CSR, CRL, PKCS#7, PKCS#12, key, or JWK fixtures.
- Improve field labels, RFC references, or explanations in the webview.
- Add parser tests for unsupported or malformed real-world files.
- Improve VS Code UX for the tree view, diagnostics, and copy actions.
- Improve documentation, screenshots, examples, or Marketplace copy.

## Before Opening a PR

Run:

```powershell
pnpm install --frozen-lockfile
pnpm lint
pnpm test:unit
pnpm package:ci
```

For UI or VS Code integration changes, also run:

```powershell
pnpm test
```

`pnpm package:ci` builds the VSIX and audits its contents. CI runs the same packaging smoke check on PRs and uploads the generated VSIX as a workflow artifact for maintainer review.

## Development Notes

- Keep parsing offline. Do not add telemetry, network lookups, OCSP calls, CT log fetching, or external validation without an explicit design discussion.
- Treat certificate parsing as untrusted input handling. Prefer size limits, bounded loops, clear errors, and tests for malformed inputs.
- Do not add private keys, production certificates, customer certificates, or secrets to fixtures.
- Prefer generated local fixtures or clearly disposable test certificates.
- Keep UI copy precise. CertView provides advisory linting, not trust validation or compliance certification.

## Pull Request Expectations

- Explain the user-visible change.
- Include tests for parser, linter, diagnostics, or rendering behavior when practical.
- Update `CHANGELOG.md` under `Unreleased` when the PR changes behavior, test coverage, release process, packaging, documentation, or contributor workflow.
- Mention any unsupported formats or known limitations.
- Include screenshots for visible webview or sidebar changes.
- Keep unrelated refactors out of the PR.

## Release Flow

Maintainers publish from version tags such as `v0.3.6`. Release notes should describe user-facing changes, parser/security hardening, and compatibility notes.
