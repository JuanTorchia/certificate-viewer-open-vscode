# Changelog

All notable changes to CertView are documented here.

## Unreleased

### Added

- Added corrupt PKCS#12/PFX parser coverage for wrong passwords, truncated bundles, empty files, and non-PKCS#12 DER inputs.
- Added a reusable VSIX packaging smoke check that audits package contents and uploads the generated VSIX artifact in CI.
- Added a contributor project map that explains repository areas, ownership, and validation paths.
- Added automated Marketplace readiness checks for README copy, screenshots, manifest metadata, and risky security claims.
- Added a bounded parsed document cache for repeated certificate reads across the editor, explorer, and diagnostics.
- Added workspace scan limits and exclude settings for the Certificates explorer.
- Added a pre-merge security review checklist for CodeQL, GitHub Advanced Security, GitGuardian, Dependabot, and related automation comments.
- Added webview rendering hardening tests for hostile certificate, error, and key fields.
- Documented the VS Code and Node compatibility policy for dependency and API baseline changes.
