import { execFileSync } from "node:child_process";
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

// Directories the source walk never enters: build output, dependencies, and
// the two index directories. None hold module sources, and `dist` in
// particular holds the binaries being judged.
const SKIPPED_DIRS = new Set([".git", ".codegraph", "node_modules", "dist", "bin"]);

// --check: fail if the binaries in lsp/dist no longer match the sources.
//
// The comparison is against the whole module, not just lsp/**. The analyzer
// imports mutant/builtin and derives arity, parameter kinds, result types and
// deprecation from it, so registering a builtin changes what the server
// teaches while leaving every file under lsp/ untouched -- which is how an
// editor falls months behind a language without a single file under lsp/
// looking stale.
if (process.argv.includes("--check")) {
  const absent = allBinaries.filter((name) => !existsSync(resolve(lspDist, name)));
  if (absent.length > 0) {
    console.error(`Missing ${absent.length} of ${allBinaries.length} mlsp binaries in lsp/dist. Build them with lsp/build.ps1 or lsp/build.sh.`);
    for (const name of absent) {
      console.error(`  - ${name}`);
    }
    process.exit(1);
  }

  // Ask the one binary this machine can execute what it is, and compare that
  // with what the sources build. This runs before the mtime comparison because
  // it is the precise answer: it names the drift instead of reporting that
  // something under the tree is newer than something under dist.
  const hostName = hostBinaryName();
  if (hostName) {
    const fromBinary = runVersion(resolve(lspDist, hostName), ["--version"], lspDist);
    const fromSource = runVersion(goCommand(), ["run", "./lsp/cmd/mlsp", "--version"], repoRoot);
    if (fromBinary === null) {
      console.warn(`Could not run ${hostName} to read its version; comparing mtimes only.`);
    } else if (fromSource === null) {
      console.warn("Go toolchain unavailable; comparing mtimes only, not the reported versions.");
    } else if (fromBinary !== fromSource) {
      console.error(`The staged server is not the language in this tree. ${hostName} reports "${fromBinary}"; the sources build "${fromSource}". Rebuild with lsp/build.ps1 or lsp/build.sh.`);
      process.exit(1);
    } else {
      console.log(`${hostName} reports "${fromBinary}", matching the sources.`);
    }
  }

  // mtimes are the coverage net for the five targets this machine cannot run,
  // and for every change the version line does not move: a lint rule, a fix in
  // the parser. They lie after a fresh clone or a copied tree, which is why
  // they are the second question rather than the only one.
  //
  // Test files are excluded because no byte of one reaches a binary, and a
  // gate that demands a rebuild after an edit no shipped artifact can see is a
  // gate people learn to skip.
  const newestSource = newestMTime(repoRoot, (name) => name.endsWith(".go") && !name.endsWith("_test.go"));
  const oldestBinary = oldestBinaryMTime();
  if (newestSource !== null && oldestBinary !== null && newestSource > oldestBinary) {
    console.error("LSP binaries are older than the module's Go sources. Rebuild with lsp/build.ps1 or lsp/build.sh.");
    process.exit(1);
  }

  console.log("LSP binaries are up to date with the module's sources.");
  process.exit(0);
}

// Determine which binaries to stage: one for --target <t>, else all six.
// The target arrives on argv rather than in the environment so the command that
// produced a given VSIX is visible in the build log and reproducible from it.
// See docs/CONFIGURATION_POLICY.md.
const target = readTargetArg(process.argv.slice(2));
let binariesToStage;
if (target) {
  const name = targetToBinary[target];
  if (!name) {
    console.error(`Unknown --target "${target}". Expected one of: ${Object.keys(targetToBinary).join(", ")}`);
    process.exit(1);
  }
  binariesToStage = [name];
} else {
  binariesToStage = allBinaries;
}

// Accepts both `--target win32-x64` and `--target=win32-x64`.
function readTargetArg(args) {
  for (let i = 0; i < args.length; i += 1) {
    if (args[i] === "--target") {
      if (i + 1 >= args.length) {
        console.error("--target requires a value.");
        process.exit(1);
      }
      return args[i + 1];
    }
    if (args[i].startsWith("--target=")) {
      return args[i].slice("--target=".length);
    }
  }
  return undefined;
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
        if (SKIPPED_DIRS.has(entry.name)) {
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

// The staged binary for the platform running this script, or null when that
// platform is not one of the six shipped targets.
function hostBinaryName() {
  const platform = { win32: "win32", linux: "linux", darwin: "darwin" }[process.platform];
  const arch = { x64: "x64", arm64: "arm64" }[process.arch];
  if (!platform || !arch) {
    return null;
  }
  return targetToBinary[`${platform}-${arch}`] ?? null;
}

function goCommand() {
  return process.platform === "win32" ? "go.exe" : "go";
}

// Returns the trimmed first line, or null if the command could not be run at
// all -- a missing toolchain and a wrong answer are different failures, and
// only the second one should stop a package.
function runVersion(command, args, cwd) {
  try {
    const out = execFileSync(command, args, {
      cwd,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
    });
    return out.trim().split(/\r?\n/)[0] ?? null;
  } catch {
    return null;
  }
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
