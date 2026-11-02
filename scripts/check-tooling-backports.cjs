// Keep the API used by ESLint/Mocha while checking the upstream DoS backport.
const { readdirSync } = require('node:fs');
const { resolve } = require('node:path');
const { spawnSync } = require('node:child_process');
const entries = readdirSync('node_modules/.pnpm').filter(name => name.startsWith('minimatch@10.2.6'));
if (entries.length !== 1) throw new Error('Review the minimatch backport after dependency changes');
const location = resolve('node_modules/.pnpm', entries[0], 'node_modules/minimatch');
for (const format of ['commonjs', 'esm']) {
  const file = resolve(location, 'dist', format, 'index.js');
  const child = spawnSync(process.execPath, ['--max-old-space-size=128', '-e', `
    const assert = require('node:assert/strict');
    const { pathToFileURL } = require('node:url');
    (async () => {
      const { Minimatch } = await import(pathToFileURL(${JSON.stringify(file)}).href);
      const pattern = Array(30).fill('**/../a/b').join('/');
      const bounded = new Minimatch(pattern, { optimizationLevel: 2, braceExpandMax: 64 });
      assert.equal(bounded.set.length, 64);
      const large = new Minimatch('{x,*}/{0..999}', { optimizationLevel: 2 });
      assert.equal(large.set.length, 2000);
      assert.equal(large.match('y/999'), true);
      assert.equal(large.match('.y/5'), false);
      const lsp = new Minimatch('**/*.{cfg,conf}', { dot: true });
      assert(lsp.makeRe() instanceof RegExp);
      assert.equal(lsp.match('/etc/.haproxy.cfg'), true);
    })().catch(error => { console.error(error); process.exitCode = 1; });
  `], { timeout: 5000, maxBuffer: 16 * 1024, encoding: 'utf8' });
  if (child.error || child.status !== 0) throw new Error(`${format}: ${child.error || child.stderr}`);
}
console.log('Verified minimatch CommonJS/ESM backport and makeRe compatibility');
