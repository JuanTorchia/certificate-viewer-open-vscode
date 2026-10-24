# Worker-Backed Certificate Linting

## Goal

Keep all product linting off VS Code's extension-host thread while preserving the existing synchronous parser APIs for direct unit tests. The worker processes raw file bytes for normal documents. PKCS#12 password prompting, decryption, and certificate-bag extraction stay on the host, but extracted certificate PEMs are sent to the worker for parsing and linting. No private-key fields are added to `ParsedDocument` or diagnostics.

## Scope and pull-request split

### MR 1: Worker architecture

- Add one persistent Node worker for parsing and linting requests.
- Route extension-host lint paths through the worker, including cached file reads, live text diagnostics, and certificate PEMs extracted from PKCS#12 files.
- Move the current lint rules, including the existing bounded P-384 scalar check, into the worker's execution path without changing their behavior.
- Bundle the worker as `out/workers/lintWorker.js`, explicitly include it in the VSIX, require it in the packaging audit, and terminate it during extension deactivation.
- Preserve the existing parsed-document result shape and diagnostic/webview behavior.

### MR 2: Additional key checks

Based on the worker architecture, add RSA Wiener-recovery checks and extend bounded EC small-scalar checks to the supported curves. Apply the checks to certificate public keys, CSR public keys, and supported public/private key files.

Shared-prime detection and repeated-ECDSA-nonce detection are out of scope because they require comparing a set of keys or signatures. EdDSA and ML-DSA receive no generic entropy claim; their key encodings remain subject to parser/runtime validation.

## Worker boundary

For normal documents, the extension host sends `{ id, kind: "parse", filename, raw }`; the worker calls the existing `parseDocument` pipeline. For PKCS#12, the host preserves the empty-password attempt and password prompt, extracts certificate PEMs without linting, and sends `{ id, kind: "certificates", filename, pems }`; the worker parses/lints those PEMs and returns a certificate document. The PKCS#12 password and private-key bags never cross the worker boundary. Existing input, KDF-iteration, and certificate-count limits remain in force. The existing synchronous `parsePkcs12` API remains for unit tests and wraps the extraction helper; the extension uses the extraction-only helper and worker method.

Both request kinds return `{ id, document }`. The worker converts unexpected parse errors into an `ErrorDocument`; worker-level failures reject pending requests, and editor, tree, and diagnostics providers surface them as parse errors rather than falling back to main-thread linting.

One worker processes requests serially. This avoids pool management and preserves ordering; add a pool only if measurements show a throughput problem. When live-document parsing returns, diagnostics must check that the document version is still current and that it is not closed before publishing results.

An asynchronous cache miss captures the file stat and invalidation generation. After worker parsing, it rechecks both before caching. If the file changed during parsing, retry once from fresh bytes; if it changes again, return a structured "file changed while parsing" error and do not cache a stale result. Invalidations increment the per-URI generation so in-flight results cannot repopulate stale cache entries. Live diagnostics recheck both document version and `TextDocument.isClosed` after the worker responds.

Private key bytes cross only the local worker-thread boundary for parsing; they are not included in returned parsed-document key models, findings, diagnostics, logs, or webview payloads. Encrypted private keys remain unopened as they are today.

## Integration

- `ParsedDocumentCache` accepts an asynchronous parser dependency and awaits it.
- `CertEditorProvider`, `CertTreeProvider`, and diagnostics receive the worker client; disk-backed reads use the shared cache, and any uncached parse uses the worker directly.
- Live text diagnostics send their current text bytes directly to the same worker and discard stale responses.
- `CertEditorProvider` keeps the PKCS#12 password prompt and extraction flow on the host, then sends only extracted public certificate PEMs to the worker.
- `pkcs12Parser.ts` exposes an extraction-only PEM helper; the existing synchronous `parsePkcs12` function remains a wrapper for direct parser tests.
- Worker failures are rendered as error documents by editor, tree, and diagnostics paths; the extension never runs lint synchronously as a fallback.
- The worker entry point is bundled alongside the extension and is also emitted at the same path by TypeScript compilation for integration tests.
- `.vscodeignore` allows the worker bundle into the VSIX, and `scripts/audit-vsix-contents.js` verifies both `out/extension.js` and `out/workers/lintWorker.js` are packaged.
- Worker lifecycle is owned by extension activation/deactivation; all pending requests must settle on worker failure or disposal.

## Validation

- Unit-test request/result matching, worker parse/lint results, error propagation, and disposal.
- Unit-test cache generation/stat checks, one bounded retry, PKCS#12 extraction without linting, worker parsing/linting of extracted PEMs, and parse error propagation.
- Add integration tests for weak-key diagnostics through the worker, stale/closed live-document results, and worker failures surfaced as parse errors.
- Run `pnpm lint`, `pnpm test:unit`, `pnpm test`, and `pnpm package:ci` per the upstream contribution guide.
- Update `CHANGELOG.md` under `Unreleased`. Include a screenshot if the lint-banner presentation changes.
