#!/usr/bin/env node

const { spawnSync } = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");

const repoRoot = path.resolve(__dirname, "..");
const imageDir = path.join(repoRoot, "docs", "images");

const demo = {
  output: "certview-demo.gif",
  width: 1024,
  colors: 128,
  frames: [
    { file: "demo-01-explorer.png", delay: 120 },
    { file: "demo-02-details.png", delay: 300 },
    { file: "demo-03-fingerprint.png", delay: 150 },
    { file: "demo-04-copied.png", delay: 300 },
  ],
};

function findImageMagick() {
  for (const command of ["magick", "convert"]) {
    const result = spawnSync(command, ["-version"], { encoding: "utf8", stdio: "pipe" });
    if (result.status === 0 && /ImageMagick/.test(result.stdout)) {
      return command;
    }
  }
  throw new Error("ImageMagick is required to generate the demo GIF. Install it from https://imagemagick.org before running this script.");
}

function requireFrames() {
  const missing = demo.frames.filter(frame => !fs.existsSync(path.join(imageDir, frame.file)));
  if (missing.length > 0) {
    throw new Error(`Missing source frame(s) for ${demo.output}: ${missing.map(frame => frame.file).join(", ")}`);
  }
}

function generateGif(command) {
  const outputPath = path.join(imageDir, demo.output);
  const frameArgs = demo.frames.flatMap(frame => ["-delay", String(frame.delay), path.join(imageDir, frame.file)]);
  const args = [
    ...frameArgs,
    "-loop", "0",
    "-resize", `${demo.width}x`,
    "+dither",
    "-colors", String(demo.colors),
    "-layers", "Optimize",
    outputPath,
  ];

  const result = spawnSync(command, args, { encoding: "utf8", stdio: "pipe" });
  if (result.status !== 0) {
    throw new Error(`Failed to generate ${demo.output}:\n${result.stderr || result.stdout}`);
  }

  const sizeInKb = Math.round(fs.statSync(outputPath).size / 1024);
  console.log(`Generated docs/images/${demo.output} (${sizeInKb} KB)`);
}

try {
  const command = findImageMagick();
  requireFrames();
  generateGif(command);
} catch (error) {
  console.error(error instanceof Error ? error.message : error);
  process.exit(1);
}
