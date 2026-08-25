# Mutant Release Notes

> A summary of new capabilities, changes, and upgrades for this release. For the
> full builtin catalog see the [Capability Reference](CAPABILITY_REFERENCE.md).

## v2.4.0

- **Developer-tooling CLIs**: three new `mutant` subcommands, sharing the exact
  formatter and analyzer the language server uses (via a new `mutant/lsp/api`
  facade), so command-line and editor results always agree.
  - `mutant fmt [--check] [--stdout] <file-or-dir>...` — rewrites Mutant source
    in the canonical style in place; `--check` reports files that are not
    formatted (exit 1) without writing; `--stdout` prints the result.
    Idempotent.
  - `mutant lint [--strict] <file-or-dir>...` — prints diagnostics as
    `file:line:col: severity: message [source]` and exits non-zero on any error
    (or, with `--strict`, any warning). Same rule set as the LSP.
  - `mutant test [file-or-dir]...` — runs every `*_test.mut` file; a test passes
    unless running it errors (parse/compile/runtime) or its final value is
    `false`. No new language surface — a test file is just a program. Directory
    arguments are walked (skipping `.git`/`node_modules`/`vendor`), making all
    three CLIs suitable for CI over `examples/` and user projects.

- **Compound assignment and increment/decrement.** `+= -= *= /= %=` update a
  variable in place, and postfix `++` / `--` add or subtract one — so loop
  bodies and counters read `total += x` and `i++` instead of `total = total + x`
  and `i = i + 1`. They are pure sugar (`x += y` ≡ `x = x + y`, `x++` ≡
  `x = x + 1`), so they inherit the existing operator semantics: integer/float
  promotion, `+=` concatenates strings, and integer division/modulo by zero
  still errors. The target must be an assignable lvalue (variable, field, or
  index), and the expression evaluates to the newly stored value. Implemented
  once in the parser and shared across all three engines (compiler+VM,
  evaluator, web REPL); the language server lexes, parses, and formats the new
  operators (the formatter preserves the compact spelling rather than expanding
  it).

## v2.3.1 (patch)

Correctness patch that makes Mutant's three execution engines agree on every
documented operator.

- **Operator parity across engines.** The tree-walking evaluator (used by CLI
  `--macros` mode) and the WASM web REPL were missing `%`, `<=`, and `>=`, and
  the evaluator did not evaluate float literals or perform float arithmetic at
  all — so expressions that worked in the compiler+VM silently misbehaved in the
  other two engines. All three now implement identical semantics for
  `+ - * / % < >
  <= >= == !=` over integers and floats (integer
  division/modulo by zero error; a float operand promotes both operands to
  float). Whole-valued float results now stay floats (e.g. `2.0 * 3.0` is
  `6.000000`, no longer collapsed to `6`), matching the VM.
- **Shared operator core (anti-drift).** The evaluator and web REPL now route
  all numeric infix operators through a single implementation
  (`object.NumericInfix`) instead of three hand-maintained switch statements, so
  the engines can no longer diverge. A new cross-engine golden test (`parity/`)
  pins the evaluator and the VM to identical results for a table of expressions.

## v2.3.0

## Highlights

- **The standard library roughly doubled — now 399 builtins across 32 capability
  categories**, all pure-Go (`CGO_ENABLED=0`) and cross-platform.
- **First-class functions and closures are usable from the collection
  builtins.** `map`, `filter`, `reduce`, `each`, and `sort_by` now call Mutant
  closures.
- **OS-aware tooling.** The language server warns when a program calls a builtin
  that is not supported on the operating system it is running on.
- **New documentation set**: a generated capability reference plus deep-dive
  guides for the graph database, runtime integration, structured data, and
  networking.
- **All `aoiflux/*` forensic libraries upgraded to their latest releases.**

## New language capabilities

- **Higher-order collection functions**: `map` / `filter` / `reduce` / `each` /
  `sort_by`, backed by a closure-from-builtin bridge so callbacks can be
  ordinary Mutant closures (with full free-variable capture).
  `map`/`filter`/`each` callbacks accept `(element)` or `(element, index)`;
  `reduce` is `(accumulator, element)`.
- The broader functional/collection surface (`sort`, `reverse`, `unique`,
  `range`, `zip`, `contains`, `index_of`, hash
  `keys`/`values`/`entries`/`merge`/`set`/…) and the generic standard library
  (strings, math, hashing, time, structured data, type conversion) are
  documented end-to-end in the [Capability Reference](CAPABILITY_REFERENCE.md).

## New standard-library capabilities (by category)

- **Structured data**: JSON, base64/base32/hex/URL encoding, gzip/zlib
  compression, base and type conversion, and Apple property lists. See
  [STRUCTURED_DATA.md](STRUCTURED_DATA.md).
- **Cryptography & fingerprinting**: X.509 parsing, JWT decoding, PEM decoding,
  AES-GCM, HMAC, and `imphash` / `ja3` / NT & LM hashes.
- **Networking**: sockets and TLS sessions, an in-process X.509 CA, HTTP message
  inspection, WebSocket framing, offline pcap analysis, and passive OS
  fingerprinting. See [SECURE_NETWORKING.md](SECURE_NETWORKING.md).
- **Graph database**: typed nodes/edges, named relations, indexed artifacts,
  BFS, shortest-path, statistics, and timelines. See
  [GRAPH_DATABASE.md](GRAPH_DATABASE.md).
- **Runtime integration**: sandboxed Lua execution. See
  [RUNTIME_INTEGRATION.md](RUNTIME_INTEGRATION.md).
- **Forensics**: Windows artifacts (Prefetch, EVTX, LNK, Jump Lists, Amcache,
  Shimcache), filesystem parsers (NTFS/FAT/exFAT/ext/HFS+/XFS, `$MFT`), disk
  images (raw/EWF/VHD(X), MBR/GPT), registry (hive/JSON/live), browser artifacts
  and SQLite, syslog, Mach-O/Go binary analysis, and timeline building.

## LSP updates (the `mlsp` language server)

- **NEW `platformSupport` diagnostic (OS-aware).** Warns when a program calls a
  builtin unsupported on the host operating system — e.g. `process_modules` or
  `process_memory_scan` (Windows/Linux only) used on macOS. The
  supported-platform set comes from the builtin metadata; the host OS is
  `runtime.GOOS`.
- **NEW `unreachableCode` diagnostic.** Flags statements after an unconditional
  `return` / `break` / `continue`.
- **Capability categories in hover and completion.** Hover shows a builtin's
  category (e.g. `filesystem`, `graph database`) and any platform constraint;
  completion detail reads `builtin · <category>`.
- **Strict semicolon formatting confirmed.** The formatter emits semicolons from
  the AST — repairing missing ones and removing redundant ones on format — and
  the `semicolon` diagnostic surfaces them while typing.
- All new rules are configurable via `mutant.lint.rules.<rule>.severity` in the
  VS Code extension.

## Library upgrades

All `github.com/aoiflux/*` dependencies were upgraded to their latest releases
and verified building `CGO_ENABLED=0` on Windows, Linux, and macOS with the full
test suite green:

| Library  | From   | To     |
| -------- | ------ | ------ |
| libewf   | v0.2.0 | v0.2.1 |
| libntfs  | v0.3.0 | v0.3.1 |
| libtable | v0.2.0 | v0.2.2 |
| libxfat  | v1.1.0 | v1.2.0 |
| libxfs   | v0.2.0 | v0.3.1 |

(`libext`, `libfat`, `libhfs`, `libvhdi`, and `graphene` were already at their
latest versions.) No call-site changes were required by these bumps.

## Deprecations & compatibility

- **`net_syn_scan` is deprecated in favor of `net_connect_scan`.** The builtin
  was always a full TCP `connect()` scan, not a half-open SYN scan (real SYN
  needs raw sockets and elevated privileges, which conflict with the pure-Go,
  unprivileged design). `net_connect_scan` is the truthful name; `net_syn_scan`
  remains as an alias so existing programs and compiled bytecode keep working.
- **`net_conn_write` and `ws_write_frame` gained an optional trailing
  `timeout_ms` argument.** This is backward compatible (existing calls are
  unchanged); a write deadline now defaults to 30s so a stalled peer can no
  longer hang a write. Pass `<= 0` to restore indefinite blocking.
- **`http_build_request`** now adds a `Content-Length` header when a body is
  present and none was supplied (matching `http_build_response`).

## Documentation

- NEW: [CAPABILITY_REFERENCE.md](CAPABILITY_REFERENCE.md) (full builtin catalog,
  generated from metadata), [GRAPH_DATABASE.md](GRAPH_DATABASE.md),
  [RUNTIME_INTEGRATION.md](RUNTIME_INTEGRATION.md),
  [STRUCTURED_DATA.md](STRUCTURED_DATA.md), and this file.
- Updated: [MUTANT_LANGUAGE_REFERENCE.md](MUTANT_LANGUAGE_REFERENCE.md)
  (accurate 399-builtin count, new language-capability sections, platform
  notes), [SECURE_NETWORKING.md](SECURE_NETWORKING.md),
  [WASM_REPL_REFERENCE.md](WASM_REPL_REFERENCE.md),
  [WHAT_IS_MUTANT.md](WHAT_IS_MUTANT.md), the LSP LLD/onboarding docs, and the
  README.
- NEW examples under `examples/` covering filesystem triage, network recon,
  HTTP, structured data, sandboxed Lua, graph modeling, command-execution
  sandboxing, detection, cryptography, functional collections, forensic
  timelines, and a multi-file project layout
  (`examples/project/portscan_service/`).
