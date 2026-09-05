# Changelog

All notable changes to Mutant are recorded here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
What "breaking" means for artifacts, builtins, the language and the CLI is
defined in [CONTRIBUTING.md](CONTRIBUTING.md#compatibility-and-stability).

Entries for v2.4.0 and later are written from the release notes and the commits.
Entries before that are reconstructed from git history and are summaries, not
exhaustive lists.

## [Unreleased]

The v2.5 line — *trustworthy: structural correctness*. The theme is that every
claim the README makes becomes verifiable.

### Added

- **A real `bytes` type.** `BYTES` is a first-class object: it indexes to an
  integer 0–255, concatenates with `+`, compares by content, measures with
  `len`, and hashes in a keyspace disjoint from strings. Every disk sector, PE
  section, memory page and socket read previously travelled in a Go string, and
  nothing in the language could tell a binary value from text — so `str_reverse`
  turned every non-UTF-8 byte into U+FFFD and `str_substr` indexed by rune while
  `bytes_get` indexed by byte, both without failing.
- `string_to_bytes(s, encoding)` and `bytes_to_string(b, encoding)`, with
  `"raw"`, `"utf8"` (validated, not substituted), `"latin1"`, `"hex"` and
  `"base64"`. Because every pre-existing producer already returned byte-exact
  data in a string, `string_to_bytes(x, "raw")` bridges all of them losslessly.
- 16 native `*_bytes` producers — `fs_read_bytes`, `hex_decode_bytes`,
  `base64_decode_bytes`, `gunzip_bytes`, `zlib_decompress_bytes`,
  `aes_decrypt_bytes`, `net_conn_read_bytes`, six `*_read_file_bytes` filesystem
  readers and three `*_read_at_bytes` image readers. **Builtin count 409 → 427**
  across 33 categories.
- **Runtime tracebacks with source positions.** A fault used to print one
  sentence with no way back to a line. The VM now prints every frame with the
  arguments it received, the line it is on, and an underline beneath the failing
  span; deep recursion collapses to "N frames repeated M more times". Positions
  ride in a delta-encoded line table costing single-digit percent of the
  instruction stream it annotates, and the program's source text travels with
  the artifact so a failing `.mu` can quote the line it died on.
- **Builtin stability tiers.** Metadata declares `stable` (the unwritten
  default), `experimental` or `deprecated`; a deprecated builtin names its
  replacement. Surfaced as an LSP hover footer and a new `builtinDeprecated`
  diagnostic.
- `--timing` for stage timing, `--trusted-key <path>` for the verification key,
  and `--target` for release cross-builds — replacing the environment variables
  that used to carry them.
- Credential handling that never records the secret: interactive prompt (the
  default), `--password-file <path>`, and `--password-stdin`.
- **A documentation path from nothing to a shipped binary.**
  `docs/TUTORIAL_30_MIN.md` ("Mutant in 30 minutes") goes from install to a
  signed standalone executable; `docs/COOKBOOK.md` is fourteen complete
  programs organised by investigation rather than by builtin category, ending
  with the traps that actually bit while writing them; `docs/COMPARISON.md`
  places Mutant against Python+plaso, Velociraptor, osquery and YARA+Sigma,
  including a section naming eight cases where it is the wrong tool. Every
  command and output in the tutorial and the cookbook was run against a binary
  built from this tree.
- `docs/CONFIGURATION_POLICY.md`, `docs/WHAT_IS_MUTANT.md`,
  `docs/WASM_REPL_REFERENCE.md`, and this file, plus
  [SECURITY.md](SECURITY.md), [CONTRIBUTING.md](CONTRIBUTING.md) and
  [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
- `examples/data/autoruns_hive.json` and `examples/data/phish.eml` — synthetic
  fixtures so two of the cookbook recipes run unchanged.

### Changed

- **Builtins resolve by name, not by registry ordinal.** `OpGetBuiltin` carried
  an index into the global registry, which made that registry append-only
  forever — nothing could be renamed, retired or reordered without silently
  repointing every artifact ever compiled. The compiler now interns the builtins
  a program references and ships that table in the artifact; the VM binds every
  name before an instruction runs, so a missing builtin fails by name at load.
  `ByteCode.Version` is **2**.
- Binary-accepting builtins widen rather than fork: the whole `bytes_*` family,
  the hash and encoding families, `fs_write`, `fs_append` and `net_conn_write`
  take `BYTES` **or** `STRING` and hand back the representation they were given.
  No existing builtin changed its return type — the `bytes` work is additive,
  and every `.mut` program written before it behaves identically.
- Debug information is unconditional in development artifacts and stripped only
  by `mutant release`, rather than being gated on a mode flag. Gating would have
  coupled debuggability to a security downgrade.
- The polymorphic engine carries line tables through the offset remap it already
  builds for jump targets, so mutated builds keep their positions.

### Removed

- **All environment-variable configuration.** Mutant takes no configuration from
  the environment, in code or in documentation: the environment is part of the
  untrusted thing a forensic tool examines, and an environment switch is an
  unlogged control channel absent from the command line an analyst records.
  Ten dead exported `*Env` constants across five files were deleted and 16
  documents purged of the variables they described — several of which named
  knobs the code had already collapsed to constants.
- The environment-driven builtin capability allowlist. *Capability
  configuration is under design; no interface is specified.*

### Fixed

- `mutil.EncryptObject`'s default arm returns an error both call sites discard,
  so an object type without an explicit arm travelled **unencrypted with nothing
  said**. `BYTES` has arms in both directions, with a test asserting the sealed
  type rather than trusting the suite.
- The parameter-kind conformance probe drew from a fixed candidate list that
  never exercised the new kind. Making it reachable immediately caught **15
  under-declared builtins**, including `len` and `json_stringify`, that a hand
  audit had missed.
- The evaluator has never indexed strings while the VM has. Bytes indexing was
  implemented in **both** engines so the new type does not inherit the
  divergence.
- A missing or malformed trusted-key file now fails hard instead of silently
  falling back to the local keystore.
- LSP: the type lattice, the function-parameter solver, inlay hints and
  signature help all know `bytes`; `builtinArgType` reports binary passed into a
  text builtin and names the conversion.
- `email_urls` declared `[]STRING` elements over an implementation that returns
  a `{host, scheme, url}` hash per link, so the published signature, the hover
  and the argument-type diagnostic were all confidently wrong about
  `u["host"]`. The contract now matches the code. **The conformance probe could
  not have caught it:** it checked only the top-level returned kind, never the
  declared element kind. It now checks both, verified by mis-declaring
  `text_split` and watching it fail.
- The generated `docs/CAPABILITY_REFERENCE.md` still told every reader that
  Mutant "has no separate bytes type" — untrue since `BYTES` shipped, and
  contradicted by a signature on the same page. Fixed in `cmd/gendocs`, which
  is where generated prose lives.

### Security

- `go test ./policy/...` — an AST guard, part of the ordinary `go test ./...` —
  fails the build on a `MUTANT_`-prefixed string literal anywhere in the module,
  on an environment read outside ten allowlisted functions with pinned line
  budgets, and on an environment write outside a build-time child `go build`.
  Sandbox, VM and debugger detection is unchanged: those probes read variables
  set by Sandboxie, WSL, a debugger or an injector — never by a Mutant user —
  and the only outcome they can produce is a refusal to run.
- `SecureStack.clearObject`'s `*String` arm zeroes `[]byte(v.Value)`, a copy Go
  makes at the conversion, so it has never wiped anything and cannot: Go strings
  are immutable. It is documented in place. Key material belongs in a `bytes`,
  whose backing array `Zero()` genuinely clears.

## [2.4.0] — 2026-08-25 — "Legion"

One compiled program, many minds running it.

### Added

- **Concurrency.** The unit is a whole VM, not a goroutine sharing one: a worker
  gets its own stack and frames and a *snapshot* of the globals over the same
  bytecode, so nothing is shared and nothing needs a lock. `spawn`, channels,
  and `pmap`/`peach`, up to 1024 workers. 10 new builtins; **399 → 409**.
- Compound assignment operators.
- Struct and enum hover in the language server; SSA-based analysis and ghost-code
  resolution in the extension.

### Changed

- **The polymorphic engine went live.** Previously 1 of 5 transforms, active only
  at level ≥ 6; now 4 of 4 from level 1.
- Execution engines reduced from three to two — the separate WASM REPL
  interpreter was deleted rather than kept in sync.
- LSP diagnostics 7 → 12. The VS Code extension moved to 0.1.0 with per-platform
  packaging.
- **A failing run now exits non-zero.** It previously exited `0`.

### Fixed

- Hash literal and LSP formatter fixes; operator parity between the two engines;
  nopsled and polymorphic correctness fixes.

## [2.3.0] — 2026-08-11

### Added

- The forensic suite in depth: MFT, prefetch, registry, `fs_deleted`, syslog,
  SQLite and regex builtins, link builtins, process listing, and process
  injection detection.
- Higher-order collection functions; `&&` and `||` operators.
- Workshop functions and example programs.

### Changed

- Parser, formatter and extension updates; SQLite excluded from the WASM build.

## [2.2.0] — 2026-07-14

### Added

- Interactive REPL tab completion with context-aware ranking; shared help docs
  across the REPL and web surfaces.
- The WASM REPL and automatic WASM builds; LSP build scripts and extension
  packaging.

### Changed

- Compiled bytecode is compressed. Multi-value returns were reworked, and `len`
  returns a single object.
- Sandbox detection updated; macro fixes.
- Moved to the `aoiflux` domain and the AGPL-3.0 licence.

### Removed

- An earlier round of environment variables, and large files from the tree.

## [2.1.0] — 2026-06-28

### Added

- The polymorphic bytecode engine; sandbox, VM and debugger detection; deep
  binary protection and randomised in-code security checks.
- Sandboxed Lua: a bytecode integration, an executor with timeouts and scrubbed
  errors, and pre-VM Lua patch execution under tamper policy.
- Structs, enums, loops, float types and the modulo operator; encrypted structs
  and enums; command execution; many builtins.
- Dynamic stack size, global size and frame limits.

### Changed

- Moved to a pure-Go implementation; improved runtime encryption and security
  logging.

## [2.0.1] — 2022-06-26

### Added

- Graceful exit handling.

### Changed

- Go version upgrade.

## [2.0.0] — 2021-06-02

### Added

- `mutant release` — standalone compiled binaries for multiple platforms, with
  per-platform binary formats and extensions.
- A basic CLI with help and argument validation.

## [1.0.1] — 2021-03-29

Documentation only.

## [1.0.0] — 2021-03-22

Initial release: the language, the compiler, the VM, and encrypted bytecode.

[Unreleased]: https://github.com/aoiflux/mutant/compare/v2.4.0...HEAD
[2.4.0]: https://github.com/aoiflux/mutant/compare/v2.3.0...v2.4.0
[2.3.0]: https://github.com/aoiflux/mutant/compare/v2.2.0...v2.3.0
[2.2.0]: https://github.com/aoiflux/mutant/compare/v2.1.0...v2.2.0
[2.1.0]: https://github.com/aoiflux/mutant/compare/v2.0.1...v2.1.0
[2.0.1]: https://github.com/aoiflux/mutant/compare/v2.0.0...v2.0.1
[2.0.0]: https://github.com/aoiflux/mutant/compare/v1.0.1...v2.0.0
[1.0.1]: https://github.com/aoiflux/mutant/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/aoiflux/mutant/releases/tag/v1.0.0
