import * as assert from "assert";
import * as fs from "fs";
import * as path from "path";

const REPO_ROOT = path.resolve(__dirname, "../../..");
const SRC_ROOT = path.join(REPO_ROOT, "src");

function readSourceFiles(dir: string): string[] {
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap(entry => {
    const name = path.basename(entry.name);
    if (name !== entry.name || name === "." || name === "..") return [];
    const full = `${dir}${path.sep}${name}`;
    if (entry.isDirectory()) return full === path.join(SRC_ROOT, "test") ? [] : readSourceFiles(full);
    return entry.name.endsWith(".ts") ? [fs.readFileSync(full, "utf-8")] : [];
  });
}

suite("contributed settings", () => {
  test("every certview.* setting in package.json is read by the extension", () => {
    const manifest = JSON.parse(fs.readFileSync(path.join(REPO_ROOT, "package.json"), "utf-8"));
    const keys = Object.keys(manifest.contributes.configuration.properties);
    const source = readSourceFiles(SRC_ROOT).join("\n");

    const unread = keys.filter(key => {
      const name = key.split(".").pop() as string;
      return !source.includes(`"${name}"`) && !source.includes(`"${key.slice("certview.".length)}"`);
    });

    assert.ok(keys.length > 0);
    assert.deepStrictEqual(unread, []);
  });
});
