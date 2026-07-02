const { listFiles, PackageManager } = require("@vscode/vsce");

const unexpectedPatterns = [
  /(^|\/)scripts\//,
  /(^|\/)esbuild\.js$/,
  /^src\//,
  /^out\/(models|parsers|providers|test|utils|views)\//,
  /(^|\/)fixtures\//,
  /(^|\/)testcerts\//,
];

async function main() {
  const files = await listFiles({ packageManager: PackageManager.None });
  const contents = `${files.join("\n")}\n`;
  process.stdout.write(contents);

  const unexpected = files
  .filter(Boolean)
  .filter(file => unexpectedPatterns.some(pattern => pattern.test(file)));

  if (unexpected.length > 0) {
    console.error("Unexpected development or test files found in VSIX contents:");
    for (const file of unexpected) {
      console.error(`- ${file}`);
    }
    process.exit(1);
  }
}

main().catch(error => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
});
