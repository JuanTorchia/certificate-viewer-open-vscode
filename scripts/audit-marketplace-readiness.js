const fs = require("node:fs");
const path = require("node:path");

const root = path.resolve(__dirname, "..");
const requiredFiles = ["README.md", "CHANGELOG.md", "LICENSE", "package.json"];
const requiredManifestFields = ["displayName", "description", "repository", "bugs", "homepage", "icon", "keywords", "categories"];
const requiredReadmePatterns = [
  { name: "Marketplace badge or link", pattern: /marketplace\.visualstudio\.com\/items\?itemName=gmm\.certview/i },
  { name: "offline positioning", pattern: /\boffline\b/i },
  { name: "no telemetry positioning", pattern: /no telemetry|does not include telemetry|without telemetry/i },
  { name: "installation section", pattern: /^## Install\b/im },
  { name: "screenshot image", pattern: /!\[[^\]]+\]\([^)]+\)/ },
  { name: "clear user problem: issuer", pattern: /\b(who issued|issuer)\b/i },
  { name: "clear user problem: expiry", pattern: /expir|validity/i },
  { name: "clear user problem: fingerprints", pattern: /\bfingerprint/i },
];
const riskyClaimPatterns = [
  /\bguarantees?\s+(trust|compliance|revocation|security)\b/i,
  /\bestablishes?\s+certificate\s+trust\b/i,
  /\bfull\s+RFC\s*5280\s+(path\s+)?validation\b/i,
  /\b(WebPKI|FIPS|Common Criteria)\s+compliant\b/i,
  /\bcertified\s+(for|as)\s+(compliance|security|audit)\b/i,
];

const failures = [];

for (const file of requiredFiles) {
  if (!fs.existsSync(path.join(root, file))) {
    failures.push(`Missing required Marketplace file: ${file}`);
  }
}

const manifestPath = path.join(root, "package.json");
const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
for (const field of requiredManifestFields) {
  if (manifest[field] === undefined || manifest[field] === "" || (Array.isArray(manifest[field]) && manifest[field].length === 0)) {
    failures.push(`package.json is missing required Marketplace field: ${field}`);
  }
}

if (Array.isArray(manifest.keywords) && manifest.keywords.length > 30) {
  failures.push(`package.json has ${manifest.keywords.length} keywords; VS Code Marketplace allows at most 30.`);
}

if (!/\b(local|locally|offline)\b/i.test(manifest.description ?? "")) {
  failures.push("package.json description should mention local/offline inspection.");
}

if (manifest.icon && !fs.existsSync(path.join(root, manifest.icon))) {
  failures.push(`package.json icon does not exist: ${manifest.icon}`);
}

const readmePath = path.join(root, "README.md");
const readme = fs.readFileSync(readmePath, "utf8");
const firstScreen = readme.slice(0, 2500);
for (const check of requiredReadmePatterns) {
  if (!check.pattern.test(firstScreen)) {
    failures.push(`README first screen is missing: ${check.name}`);
  }
}

const localImageRefs = [...readme.matchAll(/!\[([^\]]*)\]\((?!https?:\/\/)([^)#]+)(?:#[^)]+)?\)/g)]
  .map(match => ({ alt: match[1], ref: match[2] }));
if (localImageRefs.length < 3) {
  failures.push(`README should reference at least 3 local screenshots; found ${localImageRefs.length}.`);
}
if (![...firstScreen.matchAll(/!\[[^\]]+\]\((?!https?:\/\/)([^)#]+)(?:#[^)]+)?\)/g)].length) {
  failures.push("README first screen should include at least one local screenshot.");
}
for (const image of localImageRefs) {
  if (!image.alt.trim()) {
    failures.push(`README image is missing alt text: ${image.ref}`);
  }
  const imagePath = path.join(root, image.ref);
  if (!fs.existsSync(imagePath)) {
    failures.push(`README references a missing local image: ${image.ref}`);
    continue;
  }
  const size = fs.statSync(imagePath).size;
  if (size > 500 * 1024) {
    failures.push(`README image is larger than 500 KiB: ${image.ref}`);
  }
}

for (const pattern of riskyClaimPatterns) {
  const match = readme.match(pattern);
  if (match) {
    failures.push(`README contains a risky Marketplace claim: "${match[0]}"`);
  }
}

if (failures.length > 0) {
  console.error("Marketplace readiness audit failed:");
  for (const failure of failures) {
    console.error(`- ${failure}`);
  }
  process.exit(1);
}

console.log("Marketplace readiness audit passed.");
