import { execSync } from "node:child_process";
import { createRequire } from "node:module";
import { mkdirSync } from "node:fs";

// Builds one platform-specific .vsix per target. Each vsce invocation runs
// vscode:prepublish, where stage-lsp-binaries.mjs reads MUTANT_TARGET and stages
// exactly one mlsp binary, so every package ships only its own platform's server.
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

for (const target of targets) {
  const out = `dist/mutant-language-tools-${target}-${version}.vsix`;
  console.log(`\n=== Packaging ${target} -> ${out} ===`);
  execSync(`npx @vscode/vsce package --target ${target} -o ${out}`, {
    stdio: "inherit",
    env: { ...process.env, MUTANT_TARGET: target },
  });
}

console.log(`\nPackaged ${targets.length} platform VSIXs into dist/.`);
