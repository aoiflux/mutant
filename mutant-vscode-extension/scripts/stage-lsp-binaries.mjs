import { copyFileSync, existsSync, mkdirSync, readdirSync, rmSync, statSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const scriptDir = dirname(fileURLToPath(import.meta.url));
const extensionRoot = resolve(scriptDir, "..");
const repoRoot = resolve(extensionRoot, "..");
const lspRoot = resolve(repoRoot, "lsp");
const lspDist = resolve(lspRoot, "dist");
const outDir = resolve(extensionRoot, "bin");

// Maps a vsce --target to the single platform binary it should ship.
const targetToBinary = {
  "win32-x64": "mlsp-windows-amd64.exe",
  "win32-arm64": "mlsp-windows-arm64.exe",
  "linux-x64": "mlsp-linux-amd64",
  "linux-arm64": "mlsp-linux-arm64",
  "darwin-x64": "mlsp-darwin-amd64",
  "darwin-arm64": "mlsp-darwin-arm64",
};

const allBinaries = Object.values(targetToBinary);

// --check: fail if any Go source under lsp/ is newer than the oldest built
// binary, i.e. the binaries in lsp/dist are stale relative to the sources.
if (process.argv.includes("--check")) {
  const newestSource = newestMTime(lspRoot, (name) => name.endsWith(".go"));
  const oldestBinary = oldestBinaryMTime();
  if (oldestBinary === null) {
    console.error("No mlsp binaries in lsp/dist. Build them first with lsp/build.ps1 or lsp/build.sh.");
    process.exit(1);
  }
  if (newestSource !== null && newestSource > oldestBinary) {
    console.error("LSP binaries are stale relative to lsp/**/*.go. Rebuild with lsp/build.ps1 or lsp/build.sh.");
    process.exit(1);
  }
  console.log("LSP binaries are up to date with lsp sources.");
  process.exit(0);
}

// Determine which binaries to stage: one for MUTANT_TARGET, else all six.
const target = process.env.MUTANT_TARGET;
let binariesToStage;
if (target) {
  const name = targetToBinary[target];
  if (!name) {
    console.error(`Unknown MUTANT_TARGET "${target}". Expected one of: ${Object.keys(targetToBinary).join(", ")}`);
    process.exit(1);
  }
  binariesToStage = [name];
} else {
  binariesToStage = allBinaries;
}

// Verify every required source binary exists.
const missing = binariesToStage
  .map((name) => resolve(lspDist, name))
  .filter((source) => !existsSync(source));
if (missing.length > 0) {
  console.error("Missing LSP binaries in lsp/dist. Build them first using lsp/build.ps1 or lsp/build.sh.");
  for (const source of missing) {
    console.error(`  - ${source}`);
  }
  process.exit(1);
}

// Clear any previously staged binaries so a per-target package never ships a
// leftover from another platform.
mkdirSync(outDir, { recursive: true });
for (const existing of readdirSync(outDir)) {
  if (existing.startsWith("mlsp-")) {
    rmSync(join(outDir, existing), { force: true });
  }
}

for (const name of binariesToStage) {
  copyFileSync(resolve(lspDist, name), resolve(outDir, name));
  console.log(`Staged ${name}`);
}
console.log(`Staged ${binariesToStage.length} LSP binary(ies) into ${outDir}${target ? ` for ${target}` : ""}`);

function newestMTime(dir, matcher) {
  let newest = null;
  const walk = (current) => {
    let entries;
    try {
      entries = readdirSync(current, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      const full = join(current, entry.name);
      if (entry.isDirectory()) {
        if (entry.name === ".git" || entry.name === "node_modules" || entry.name === "dist") {
          continue;
        }
        walk(full);
      } else if (matcher(entry.name)) {
        const m = statSync(full).mtimeMs;
        if (newest === null || m > newest) {
          newest = m;
        }
      }
    }
  };
  walk(dir);
  return newest;
}

function oldestBinaryMTime() {
  let oldest = null;
  for (const name of allBinaries) {
    const p = resolve(lspDist, name);
    if (!existsSync(p)) {
      continue;
    }
    const m = statSync(p).mtimeMs;
    if (oldest === null || m < oldest) {
      oldest = m;
    }
  }
  return oldest;
}
