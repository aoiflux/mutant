import { execSync } from "node:child_process";
import { createRequire } from "node:module";
import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

// Builds one platform-specific .vsix per target. Staging runs here, once per
// target, rather than inside vscode:prepublish -- a prepublish hook cannot be
// told which target vsce is packaging except through the environment, and Mutant
// takes no configuration from the environment. See docs/CONFIGURATION_POLICY.md.
// vscode:prepublish is compile-only for the same reason: were it still staging,
// vsce would re-stage all six binaries and clobber the single one placed here.
const require = createRequire(import.meta.url);
const { version } = require("../package.json");

const targets = [
  "win32-x64",
  "win32-arm64",
  "linux-x64",
  "linux-arm64",
  "darwin-x64",
  "darwin-arm64",
];

mkdirSync("dist", { recursive: true });

// This script stages from lsp/dist without building, so nothing else stands
// between a months-old binary and six published VSIXs. The check is here
// rather than in the wrapper because the wrapper builds first and would only
// ever be asking a question it had just answered.
console.log("=== Checking staged LSP binaries against the sources ===");
execSync("node ./scripts/stage-lsp-binaries.mjs --check", { stdio: "inherit" });

const packaged = [];
for (const target of targets) {
  const name = `mutant-language-tools-${target}-${version}.vsix`;
  const out = `dist/${name}`;
  console.log(`\n=== Packaging ${target} -> ${out} ===`);
  execSync(`node ./scripts/stage-lsp-binaries.mjs --target ${target}`, { stdio: "inherit" });
  execSync(`npx @vscode/vsce package --target ${target} -o ${out}`, { stdio: "inherit" });
  packaged.push(name);
}

// SHA256SUMS in the format `sha256sum -c` reads, so someone who downloads a
// VSIX from a release page can verify it with a tool they already have. Bare
// names and LF endings: it sits in dist/ beside what it covers, and the reader
// is as likely to be Linux as Windows. Sorted, so the same build writes the
// same file.
const sums = packaged
  .slice()
  .sort()
  .map((name) => {
    const digest = createHash("sha256").update(readFileSync(join("dist", name))).digest("hex");
    return `${digest}  ${name}`;
  })
  .join("\n");
writeFileSync(join("dist", "SHA256SUMS"), sums + "\n");

console.log(`\nPackaged ${targets.length} platform VSIXs into dist/.`);
console.log("Wrote dist/SHA256SUMS -- verify with: cd dist && sha256sum -c SHA256SUMS");
