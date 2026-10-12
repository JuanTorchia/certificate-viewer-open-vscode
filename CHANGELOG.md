# Changelog

All notable changes to CertView are documented here.

## Unreleased

### Changed

- Documented the release steps, the secretless Marketplace (Microsoft Entra) and Open VSX (trusted publishing) setup, rotation, and rollback in `CONTRIBUTING.md`.

## 0.5.2 - 2026-10-12

### Changed

- Documented features that shipped without README coverage: the Certificates explorer status view, lint findings in the Problems panel (including live diagnostics while editing PEM text), the CSR viewer, the key and JWK viewer, PEM syntax highlighting, and the **Open as text** action. Added screenshots for the explorer and Problems panel, the CSR viewer, and the key viewer.
- Added the Open VSX listing to the install instructions for VSCodium, Cursor, Windsurf, and Gitpod users.
- Expanded the Marketplace description and keywords with the terms people search for (`p12`, `keystore`, `certificate-chain`, `expiry`, `fingerprint`, `pkcs10`, `pkcs8`, `lint`).
- Removed `certview.showExpiredWarning` from the README settings table: the setting is declared but not read by the extension.
- Recaptured the first frame of the README demo GIF without a local file-path tooltip.

## 0.5.1 - 2026-10-07

### Security

- Fixed a denial of service in PEM parsing: `splitPemBlocks` rejoined the whole accumulated block on every line, so a single sub-256 KiB block made of many one-character lines parsed in O(n²) time (~88 s for 120k lines) and froze the extension host. Length is now tracked incrementally with a single join at the block footer.
- Fixed a denial of service in PKCS#12/PFX parsing: the MAC and PBE iteration counts were read straight from the file into node-forge's synchronous key derivation with no cap, and a 128-byte integer parses to `Infinity`, so the derivation loop never terminated. Because CertView tries the empty password automatically when a `.p12`/`.pfx` is opened, this was reachable without any password. A preflight now reads the MAC, PBES2/PBKDF2 and PKCS#12-PBE iteration counts from the ASN.1 directly and rejects any above `MAX_PKCS12_KDF_ITERATIONS` (100,000) before node-forge runs.

## 0.5.0 - 2026-10-05

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
