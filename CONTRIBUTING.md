# Contributing to X509 Certificate Utility

Thanks for helping improve CertView. This project is useful only if certificate behavior is predictable, well-tested, and clear to users who are not PKI specialists.

## Good First Contributions

- Add or improve certificate, CSR, CRL, PKCS#7, PKCS#12, key, or JWK fixtures.
- Improve field labels, RFC references, or explanations in the webview.
- Add parser tests for unsupported or malformed real-world files.
- Improve VS Code UX for the tree view, diagnostics, and copy actions.
- Improve documentation, screenshots, examples, or Marketplace copy.

## Project Map

Use this map to find the right part of the project before opening a PR.

- `src/parsers`: file parsing for certificates, CSRs, CRLs, PKCS#7, PKCS#12/PFX, private/public keys, JWKs, limits, and parser errors.
- `src/models`: normalized certificate and parsed-document shapes shared by parsers, providers, tests, and views.
- `src/providers`: VS Code integration for the custom editor, explorer tree, diagnostics, and commands.
- `src/views`: webview HTML assembly and data passed into the certificate viewer.
- `media`: browser-side webview JavaScript loaded by the VS Code custom editor.
- `src/test/unit`: fast tests for parsers, models, formatting, lint findings, and document parsing.
- `src/test/suite`: VS Code integration tests for custom editor behavior, tree provider behavior, diagnostics, and open behavior.
- `src/test/fixtures`: synthetic certificates, malformed files, bundles, CRLs, and keys used by tests. Do not add private or production material.
- `scripts`: maintainer and fixture helpers, including local fixture generation and VSIX package auditing.
- `.github`: issue templates, pull request template, Dependabot, CodeQL, CI, packaging, and publish automation.
- `README.md`, `CHANGELOG.md`, `ROADMAP.md`, `SECURITY.md`, `CONTRIBUTING.md`: user-facing and contributor-facing project documentation.
- `.vscodeignore`, `package.json`, `esbuild.js`, `pnpm-lock.yaml`: extension packaging, scripts, dependency policy, and bundle configuration.

## Contribution Paths

- Parser or fixture changes: update `src/parsers`, `src/test/unit`, and `src/test/fixtures`; run `pnpm test:unit`.
- Webview UI changes: update `src/views` or `media`; run `pnpm test` and include screenshots when the visible UI changes.
- VS Code behavior changes: update `src/providers` or `src/extension.ts`; run `pnpm test`.
- Diagnostics or linting changes: update provider/linter code and focused unit tests; run `pnpm test:unit` and `pnpm test` when diagnostics are visible in VS Code.
- Packaging, CI, or release changes: update `.github`, `scripts`, `package.json`, or `.vscodeignore`; run `pnpm package:ci`.
- Marketplace or README changes: update screenshots or copy, keep security claims conservative, and run `pnpm marketplace:audit`.
- Documentation-only changes: update the relevant Markdown file and `CHANGELOG.md` when the change affects contributor workflow, release process, Marketplace presentation, or user-visible guidance.

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
- This project and its documentation include AI-assisted content. Review generated or AI-assisted content before using it as compliance evidence, audit evidence, legal submission, accreditation material, or external assurance material.

## Pull Request Expectations

- Explain the user-visible change.
- Include tests for parser, linter, diagnostics, or rendering behavior when practical.
- Update `CHANGELOG.md` under `Unreleased` when the PR changes behavior, test coverage, release process, packaging, documentation, or contributor workflow.
- Mention any unsupported formats or known limitations.
- Include screenshots for visible webview or sidebar changes.
- Keep unrelated refactors out of the PR.

## Release Flow

Maintainers publish from version tags such as `v0.3.6`. Release notes should describe user-facing changes, parser/security hardening, and compatibility notes.
