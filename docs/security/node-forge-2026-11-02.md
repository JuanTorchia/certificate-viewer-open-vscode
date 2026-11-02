# node-forge runtime remediation — 2026-11-02

Scope: [issue #114](https://github.com/JuanTorchia/certificate-viewer-open-vscode/issues/114).
The runtime dependency floor and lockfile move from 1.4.0 to 1.4.2. This is a
compatible patch update; VS Code `^1.85.0`, Node 18 runtime assumptions and the
offline parsing boundary stay unchanged. No advisory suppression is added.

## Reachability and treatment

| HIGH advisory | Application path and treatment |
| --- | --- |
| [PEM decoding ReDoS](https://github.com/digitalbazaar/forge/security/advisories/GHSA-7wch-p9px-956x) | Certificate and CSR metadata parsing call Forge's PEM readers. The certificate path first uses native `crypto.X509Certificate`; the CSR path does not have that preliminary check. Existing file/block limits do not replace a linear decoder. Upgrade Forge, reject mismatched PEM boundary labels and run malformed/long-header decoder regressions in killable subprocesses. |
| [PKCS#12 zero-iteration MAC/PBE](https://github.com/digitalbazaar/forge/security/advisories/GHSA-jc66-7q78-782g) | `parsePkcs12` invokes `pkcs12FromAsn1`. Existing guards reject visible non-positive/oversized MAC, PBE and PBKDF2 iteration counts before Forge; encrypted content still requires the upstream fix. Upgrade Forge, retain the guards and test all three visible paths plus Forge's key-derivation primitive. Invalid MAC metadata now retains its iteration error instead of becoming a wrong-password error. |
| [RSA nested DigestAlgorithm forgery](https://github.com/advisories/GHSA-86w9-cpqp-85rv) | Runtime code does not call Forge RSA signature verification or CSR `verify()`. Certificate/CSR parsing and advisory linting do not establish signature trust. The upstream 1.4.1 changelog also documents the nested-element fix, included in 1.4.2; the database's `patched: None` field is stale relative to that release. The candidate runtime audit no longer reports the advisory. |
| [TLS fragmented-handshake DoS](https://github.com/digitalbazaar/forge/security/advisories/GHSA-8hrf-8g6f-7xwp) | No runtime call to Forge's TLS connection machinery. The application parses local files; this upgrade includes the upstream fix without enabling networking. |
| [TLS recursive processing DoS](https://github.com/digitalbazaar/forge/security/advisories/GHSA-hqq3-7jhf-c5jx) | Same offline boundary: no TLS record processing is exposed by the extension. Fixed upstream dependency is bundled nevertheless. |
| [Deprecated Basic Constraints OID bypass](https://github.com/digitalbazaar/forge/security/advisories/GHSA-5x38-2vff-x55p) | Runtime code never invokes Forge `verifyCertificateChain`. Reading/displaying extensions and advisory linting are not certification-path validation. Upgrade includes the upstream fix; no new trust-validation claim is made. |

Other node-forge audit findings against 1.4.0 also disappear after the update.
See the [upstream changelog](https://github.com/digitalbazaar/forge/blob/v1.4.2/CHANGELOG.md)
for fixes in 1.4.1 and the Buffer-input compatibility correction in 1.4.2.

## Regression evidence

- A generated malformed PEM input with 200,000 newline characters is below the
  application's 256 KiB block limit. An isolated probe of published Forge 1.4.0
  was terminated at its three-second timeout; 1.4.2 rejected it and exited in
  about 142 ms in that single probe. This is a bounded regression check, not a
  benchmark or a guarantee for arbitrary inputs.
- The same probe against `pkcs12.generateKey` with zero iterations returns a
  constant key on 1.4.0 and throws on 1.4.2. The regression asserts rejection
  for zero and negative iterations without generating or saving private data.
- `nodeForgeSecurity.test.ts` isolates decoder/KDF calls in child processes
  with a three-second timeout and bounded output, so a regression cannot hang
  the complete unit-test process. It also checks application-level CSR boundary
  rejection. Existing valid certificate/CSR/PFX tests remain in the full suite.
- `pkcs12Parser.test.ts` checks empty, zero and negative INTEGER encodings for
  MAC, PBES2 and PKCS#12 PBE paths before the Forge parser is invoked, retaining
  their metadata errors. Existing oversized-iteration checks remain intact.
- CI runs `scripts/check-parser-runtime.cjs` under Node 18 against the compiled
  certificate/CSR/PFX parsers and their rejection paths, then returns to Node 22
  for packaging. It uses disposable generated CSR keys only in memory.

## Audits and release boundary

The candidate `pnpm audit --prod` reports zero findings. The full audit retains
one LOW and three MODERATE development-tooling findings (`serialize-javascript`,
`qs`, `minimatch`, `glob`); there are no HIGH or CRITICAL findings in the
candidate. This is not an assertion that every development dependency is clean.
CI now gates HIGH/CRITICAL runtime findings before building release artifacts.

Full lint, unit, VS Code integration, compatibility and VSIX checks run in CI.
Inspect the resulting VSIX and verify Dependabot closure on merged main before
marking remediation complete. Prepare a separate patch-release PR afterward;
the currently published version is not changed by merging this fix.

Rollback: revert the remediation commit to restore the previous parser/dependency
state. That reintroduces Forge 1.4.0 and must retain the release blocker; it is
not security remediation. Prefer a tested fix forward for a published release.
