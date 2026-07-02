const { execFileSync } = require("node:child_process");
const path = require("node:path");

const vsceBin = path.resolve(
  __dirname,
  "..",
  "node_modules",
  ".bin",
  process.platform === "win32" ? "vsce.cmd" : "vsce"
);

const root = path.resolve(__dirname, "..");
const contents = process.platform === "win32"
  ? execFileSync("cmd.exe", ["/d", "/c", vsceBin, "ls", "--no-dependencies"], {
    cwd: root,
    encoding: "utf8",
    timeout: 30000,
  })
  : execFileSync(vsceBin, ["ls", "--no-dependencies"], {
    cwd: root,
    encoding: "utf8",
    timeout: 30000,
  });

process.stdout.write(contents);

const unexpectedPatterns = [
  /(^|\/)scripts\//,
  /(^|\/)esbuild\.js$/,
  /^src\//,
  /^out\/(models|parsers|providers|test|utils|views)\//,
  /(^|\/)fixtures\//,
  /(^|\/)testcerts\//,
];

const unexpected = contents
  .split(/\r?\n/)
  .filter(Boolean)
  .filter(file => unexpectedPatterns.some(pattern => pattern.test(file)));

if (unexpected.length > 0) {
  console.error("Unexpected development or test files found in VSIX contents:");
  for (const file of unexpected) {
    console.error(`- ${file}`);
  }
  process.exit(1);
}
