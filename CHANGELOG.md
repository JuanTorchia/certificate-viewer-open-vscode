# Changelog

All notable changes to CertView are documented here.

## Unreleased

### Added

- After regular use (5 distinct days with a certificate or key file displayed without errors, at least 14 days after first use), CertView may ask for a Marketplace rating in a non-modal notification. "Later" postpones it 30 days; "Rate" or "Don't ask again" stop it for good, and it is never shown more than twice. It only appears in Microsoft VS Code, makes no network calls, and can be turned off with `certview.ratingPrompt.enabled`.

### Changed

- Aligned the README title, install instructions, and contributing guide with the Marketplace name "CertView: X.509 Certificate Inspector".
- Added an animated README demo (open a PEM file, check expiry and details, copy the SHA-256 fingerprint) with committed source frames and a `pnpm demo:gif` generator.
- Switched README images to absolute URLs so they render on the Marketplace, and excluded README-only images from the VSIX.
- Replaced the `Other` Marketplace category with `Linters`, next to `Visualization`, and added a gallery banner matching the icon.

### Fixed

- Fixed PEM files with explanatory text before or between `-----BEGIN` boundaries (for example `openssl x509 -text` output or PKCS#12 Bag Attributes) failing to parse (#78).

## 0.4.0 - 2026-09-30

### Added

- Added corrupt PKCS#12/PFX parser coverage for wrong passwords, truncated bundles, empty files, and non-PKCS#12 DER inputs.
- Added a contributors section to the README generated using the All Contributors specification and documented the management commands.
- Added a reusable VSIX packaging smoke check that audits package contents and uploads the generated VSIX artifact in CI.
- Added a contributor project map that explains repository areas, ownership, and validation paths.
- Added automated Marketplace readiness checks for README copy, screenshots, manifest metadata, and risky security claims.
- Added a bounded parsed document cache for repeated certificate reads across the editor, explorer, and diagnostics.
- Added workspace scan limits and exclude settings for the Certificates explorer.
- Added configurable Certificates explorer auto-refresh behavior for large workspaces.
- Added lightweight webview state restoration for certificate tabs without retaining hidden webview contexts.
- Added a compact certificate chain summary for multi-certificate webviews.
- Added a pre-merge security review checklist for CodeQL, GitHub Advanced Security, GitGuardian, Dependabot, and related automation comments.
- Added webview rendering hardening tests for hostile certificate, error, and key fields.
- Documented the VS Code and Node compatibility policy for dependency and API baseline changes.

### Changed

- Changed the release job to run the lockfile-pinned `@vscode/vsce` through `pnpm exec` instead of resolving the latest version with `npx --yes` at publish time.

### Security

- Updated the development dependency security floor for `brace-expansion`, `fast-uri`, `js-yaml`, `markdown-it`, `qs`, and `undici`, clearing the current high, moderate, and low advisories without a major-version upgrade.
- Bumped the `fast-uri` and `linkify-it` pnpm overrides to patched releases, clearing GHSA-v2hh-gcrm-f6hx (CVE-2026-16221) and GHSA-v245-v573-v5vm (CVE-2026-59887) from the development dependency tree.
- Declared explicit read-only `contents` permissions on both CI jobs instead of relying on the repository-wide default.
- Excluded `AGENTS.md` from the published VSIX so internal working agreements and local tooling paths no longer ship to Marketplace users.
