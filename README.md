<p align='center'>
  <img src='./logo.png' />
</p>

# The [mutant](https://mudocs.netlify.app) Programming Language

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

## Featured In

- [Gopherlabs Conference 2021 by CloudNativeFolks](https://youtu.be/rhSwwGSt90c?t=2223)
- [Nullcon Goa Sep 2022](https://archive.nullcon.net/website/goa-2022/speakers/pushing-security-left-by-mutating-byte-code.php)
- [Nullcon Goa Sep 2022 YouTube Video](https://youtu.be/ivrM8rytaKY)
- [DEFCON AppSec Village 1st Place Winning Entry](https://eval.blog/research/breaking-the-mutant-languages-encryption/)
- [Hackaday - This Week in Security](https://hackaday.com/2023/08/18/this-week-in-security-tunnelcrack-mutant-and-not-discord/)

## Documentaiton

For all things mutant, please visit the
[official website](https://mudocs.netlify.app) ^.^
