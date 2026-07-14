import { copyFileSync, existsSync, mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const scriptDir = dirname(fileURLToPath(import.meta.url));
const extensionRoot = resolve(scriptDir, "..");
const lspDist = resolve(extensionRoot, "..", "lsp", "dist");
const outDir = resolve(extensionRoot, "bin");

const binaryNames = [
  "mlsp-windows-amd64.exe",
  "mlsp-windows-arm64.exe",
  "mlsp-linux-amd64",
  "mlsp-linux-arm64",
  "mlsp-darwin-amd64",
  "mlsp-darwin-arm64",
];

const missing = [];
for (const name of binaryNames) {
  const source = resolve(lspDist, name);
  if (!existsSync(source)) {
    missing.push(source);
  }
}

if (missing.length > 0) {
  console.error("Missing LSP binaries in lsp/dist. Build them first using lsp/build.ps1 or lsp/build.sh.");
  for (const source of missing) {
    console.error(`  - ${source}`);
  }
  process.exit(1);
}

mkdirSync(outDir, { recursive: true });
for (const name of binaryNames) {
  const source = resolve(lspDist, name);
  const destination = resolve(outDir, name);
  copyFileSync(source, destination);
  console.log(`Staged ${name}`);
}

console.log(`Staged ${binaryNames.length} LSP binaries into ${outDir}`);
