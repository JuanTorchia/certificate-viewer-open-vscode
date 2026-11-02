# Development dependency security backport

`pnpm.patchedDependencies` applies upstream minimatch commit
[77a0f5c](https://github.com/isaacs/minimatch/commit/77a0f5c4b80bdc641c3c930a1d9edf5ad2db57f8)
to the exact locked minimatch 10.2.6 CommonJS and ESM builds. The patch caps
level-2 pattern splitting at `braceExpandMax` and skips quadratic deduplication
above 1000 patterns. It preserves the 10.x `makeRe()` API removed in 11.x.
The pnpm lock records the patch hash; missing or mismatched patch application
fails installation. CI probes both module formats in killable subprocesses.

Raw audit tools compare versions and still report GHSA-g3hv-75wg-m249 for
10.2.6. Keep this residual visible; no advisory is suppressed or marked fixed
in GitHub solely because of this backport. Remove the patch only after all
consumers accept a patched upstream API and the regression gate passes.

Glob 14 is development-only and brings its own minimatch 11 matcher. Its
async glob API remains compatible with the packaging/test consumers, subject
to full CI validation. qs and serialize-javascript use safe minimum caret
ranges so subsequent compatible fixes can update the lock. Node 18 parser
support is unchanged; serializer is only used by tooling on Node 22.

Reverting this patch restores the vulnerable preprocessing code. This tooling
change does not require a marketplace release; runtime node-forge remains 1.4.2.
Override-policy issue #68 remains open for the other overrides and fast-uri.

Lockfile-only verification on 2026-11-02 resolved glob 14.0.3, its minimatch
11.0.4, qs 6.17.1 and serializer 7.1.4. The raw full audit dropped from four
advisories to one moderate; that remaining counter is the patched 10.2.6 copy.
The frozen-install, real execution and publisher authentication gates remain
required before integration.
