import * as path from "path";
import Mocha from "mocha";
import * as fs from "fs";

export function run(): Promise<void> {
  const mocha = new Mocha({ ui: "tdd", color: true, timeout: 10000 });
  const testsRoot = path.resolve(__dirname, ".");

  return new Promise((resolve, reject) => {
    const files = fs.readdirSync(testsRoot).filter(f => f.endsWith(".test.js"));
    files.forEach(f => mocha.addFile(testFilePath(testsRoot, f)));
    mocha.run((failures: number) => {
      if (failures > 0) reject(new Error(`${failures} test(s) failed.`));
      else resolve();
    });
  });
}

function testFilePath(testsRoot: string, fileName: string): string {
  if (!/^[A-Za-z0-9_.-]+\.test\.js$/.test(fileName)) throw new Error(`Unexpected test filename: ${fileName}`);
  return path.resolve(testsRoot, fileName);
}

// Allow running directly: node out/test/unit/index.js
if (require.main === module) {
  run().then(() => process.exit(0)).catch(() => process.exit(1));
}
