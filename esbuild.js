const esbuild = require("esbuild");

const shared = {
  bundle: true,
  format: "cjs",
  platform: "node",
  target: "node18",
  sourcemap: false,
  minify: false,
};

Promise.all([
  esbuild.build({ ...shared, entryPoints: ["src/extension.ts"], outfile: "out/extension.js", external: ["vscode"] }),
  esbuild.build({ ...shared, entryPoints: ["src/workers/lintWorker.ts"], outfile: "out/workers/lintWorker.js" }),
]).catch(() => process.exit(1));
