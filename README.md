<p align='center'>
  <img src='./logo.png' />
</p>

# The [mutant](https://mudocs.aoiflux.xyz) Programming Language

mutant is an open source programming language whose aim is to provide an
accessible, secure system for programming & security research.

# Key features of mutant

1. KISS: The language is simple enough to be learnt in under an hour
2. Compile time & Runtime Security: Encrypted byte code ensures security on disk
   and in memory
3. Cross Platform: MVM (Mutant Virtual Machine) makes sure that the language
   works on **YOUR** machine
4. Cross Compilation: mutant supports compiling standalone, independent binary
   executables for multiple platforms.

## Download & Install

### Binary Distributions

Official binaries are available in this repository's release section

### Installing mutant from source

Pre-Installation: Download & Install [GoLang](https://golang.org/)

```bash
git clone https://github.com/gaurav-gogia/mutant
cd mutant
go install
```

### Build scripts

Mutant release packaging now uses Go-only build scripts (no external Rust/cgo
toolchain required).

Linux/macOS/WSL:

```bash
./scripts/build.sh --host-only
```

Windows PowerShell:

```powershell
./scripts/build.ps1 -HostOnly
```

Common options:

- `--output-dir <dir>` / `-OutputDir <dir>`
- `--assets-out <dir>` / `-AssetsOut <dir>`
- `--final-name <name>` / `-FinalName <name>`
- `--host-only` / `-HostOnly`
- `--wasm-repl` / `-WasmRepl`
- `--wasm-out-dir <dir>` / `-WasmOutDir <dir>`

Wasm build via scripts (optional):

```bash
./scripts/build.sh --host-only --wasm-repl
```

```powershell
./scripts/build.ps1 -HostOnly -WasmRepl
```

## CLI Quick Start

Mutant now exposes a more structured CLI with explicit subcommands for
generation, release packaging, and help.

### Core usage

```bash
mutant
mutant hello.mut
mutant hello.mu --secure --signer-auth
mutant help
mutant help gen
mutant help release
```

- `mutant` starts the REPL
- `mutant hello.mut` compiles source into encrypted bytecode
- `mutant hello.mu` runs compiled bytecode in the Mutant VM

### Bytecode generation

```bash
mutant gen --src hello.mut
mutant gen hello.mut --password "My$tr0ngPass!"
mutant gen hello.mut --mutation 5 --seed 42
```

### Release asset generation

```bash
mutant gen assets
mutant gen assets --out ./releaseassets
```

Legacy form is still supported:

```bash
mutant gen --release-assets --out ./releaseassets
```

### Standalone release builds

```bash
mutant release --src hello.mut
mutant release hello.mut --os windows --arch amd64
mutant release hello.mut --password "My$tr0ngPass!" --mutation 5
```

Supported release targets:

- OS: `darwin`, `linux`, `windows`
- ARCH: `amd64`, `arm64`, `arm`, `386`, `x86`

### Runtime security options

When running `.mu` files or embedded standalone payloads, these flags are
available:

- `--secure` to enforce secure mode
- `--compat` to allow weaker compatibility-mode checks
- `--dev` for developer mode and local password fallback
- `--signer-auth` to require trusted signer verification
- `--security-log-level <none|error|info|debug|trace>`
- `--log-level <none|error|info|debug|trace>` as an alias

## Browser REPL (WASM, experimental)

Mutant includes an experimental browser REPL build target.

Build the wasm bundle into the default output folder:

```bash
./scripts/build.sh --host-only --wasm-repl
```

```powershell
./scripts/build.ps1 -HostOnly -WasmRepl
```

By default that produces a browser bundle in `dist/wasm-repl/`.

There is now a checked-in example page at `examples/wasm-repl/index.html`. Build
into that folder if you want the HTML page and wasm artifacts side by side:

```bash
./scripts/build.sh --host-only --wasm-repl --wasm-out-dir examples/wasm-repl
```

```powershell
./scripts/build.ps1 -HostOnly -WasmRepl -WasmOutDir examples/wasm-repl
```

Then serve `examples/wasm-repl/` with any static server. The page expects these
files to exist side-by-side:

- `examples/wasm-repl/index.html`
- `examples/wasm-repl/mutant_repl.wasm`
- `examples/wasm-repl/wasm_exec.js`

The browser bridge currently exposes:

- `mutantReplReady` (boolean)
- `mutantReplEval(input)` -> `{ ok, output?, error?, supported, builtins }`
- `mutantReplComplete(prefix, mode)` -> `{ ok, candidates }`
- `mutantReplCompleteLine(line, mode)` -> `{ ok, candidates }`

Minimal JavaScript usage:

```html
<script src="./wasm_exec.js"></script>
<script>
  const go = new Go();

  async function start() {
    const response = await fetch("./mutant_repl.wasm");
    const { instance } = await WebAssembly.instantiateStreaming(
      response,
      go.importObject,
    );
    go.run(instance);

    const result = window.mutantReplEval("len([1, 2, 3])");
    console.log(result.output);

    const completions = window.mutantReplCompleteLine("text_", "supported");
    console.log(completions.candidates);
  }

  start();
</script>
```

Current wasm REPL support intentionally focuses on a lightweight subset:

- integers, booleans, strings
- arrays, hashes, indexing
- `let` bindings and identifiers
- browser-safe builtins: `len`, `first`, `last`, `rest`, `push`
- text builtins: `text_contains`, `text_index`, `text_count`, `text_split`,
  `text_replace`
- `if/else`
- prefix `!` and unary `-`
- infix `+ - * / < > == !=`

## Practical Security and Forensics Examples

The `examples/` directory now includes practical scripts that can be used for
real security and forensics workflows:

- `security_environment_report.mut`: Collects debugger/sandbox diagnostics,
  computes a risk score, and writes a JSON report.
- `network_service_recon_graph.mut`: Performs DNS + TCP reconnaissance, persists
  a graph model, and writes a machine-readable findings report.
- `ioc_event_triage.mut`: Seeds/parses IOC events from JSON, scores suspicious
  activity, and emits triage findings.
- `persistence_triage_commands.mut`: Captures startup and scheduled task
  snapshots using command execution builtins and writes a forensic artifact.

Suggested run sequence:

```bash
mutant examples/security_environment_report.mut
mutant examples/network_service_recon_graph.mut
mutant examples/ioc_event_triage.mut
mutant examples/persistence_triage_commands.mut
```

Artifacts are written under `example_output/`.

### Command execution requirements

`persistence_triage_commands.mut` uses `cmd_builder`, `cmd_add`, and `cmd_run`.
Those are policy controlled.

Optional policy tuning:

- `MUTANT_COMMAND_EXEC_TIMEOUT_MS`
- `MUTANT_COMMAND_EXEC_MAX_OUTPUT_BYTES`

## Featured In

- [Gopherlabs Conference 2021 by CloudNativeFolks](https://youtu.be/rhSwwGSt90c?t=2223)
- [Nullcon Goa Sep 2022](https://archive.nullcon.net/website/goa-2022/speakers/pushing-security-left-by-mutating-byte-code.php)
- [Nullcon Goa Sep 2022 YouTube Video](https://youtu.be/ivrM8rytaKY)
- [DEFCON AppSec Village 1st Place Winning Entry](https://eval.blog/research/breaking-the-mutant-languages-encryption/)
- [Hackaday - This Week in Security](https://hackaday.com/2023/08/18/this-week-in-security-tunnelcrack-mutant-and-not-discord/)

## Documentaiton

For all things mutant, please visit the
[official website](https://mudocs.aoiflux.xyz) ^.^

For VS Code language tooling specifics (teaching hovers, signature help, and
snippet completions), see:

- [docs/WHAT_IS_MUTANT.md](docs/WHAT_IS_MUTANT.md)
- [docs/VSCODE_LSP_TEACHING_REFERENCE.md](docs/VSCODE_LSP_TEACHING_REFERENCE.md)
- [docs/LSP_EXTENSION_LLD.md](docs/LSP_EXTENSION_LLD.md)
- [docs/LSP_EXTENSION_ONBOARDING_60_MIN.md](docs/LSP_EXTENSION_ONBOARDING_60_MIN.md)
