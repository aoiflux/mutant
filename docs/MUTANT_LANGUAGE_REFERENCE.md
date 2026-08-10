# Mutant Language Reference

This document is the practical reference for Mutant language features, reserved keywords, and builtins.

Source of truth:
- Keywords: token/token.go
- Builtins registry: builtin/builtin.go
- Builtin names/constants: builtin/names.go
- Builtin teaching metadata/signatures: builtin/metadata.go

Related references:
- [Capability Reference](CAPABILITY_REFERENCE.md) — the full, category-grouped catalog of every builtin (generated from the metadata above).
- Deep-dive guides: [Secure Networking](SECURE_NETWORKING.md), [Graph Database](GRAPH_DATABASE.md), [Runtime Integration](RUNTIME_INTEGRATION.md), [Structured Data](STRUCTURED_DATA.md).

## Language Features

Mutant supports:
- Variables and assignment with `let`
- Primitive literals: integers, floats, booleans, strings
- Compound literals: arrays, hashes, struct literals
- Prefix operators: `!` and unary `-`
- Infix operators: `+ - * / % < > == !=`
- Indexing and field access
- Conditionals: `if` / `else`
- Loops: `for`, with `break` and `continue`
- First-class functions, closures, and function calls
- Return statements (single and multi-value)
- Macros
- Type declarations: `struct` and `enum`

### Multi-value returns (the `(value, err)` idiom)

Fallible builtins return two values — a result and an error — which you bind together:

```mutant
let load = fn(path) {
    let data, err = fs_read(path);
    if (err) {
        putln("[error] fs_read:", err);
        return "";
    };
    return data;
};

let report = load("report.json");
putln("read", len(report), "bytes");
```

This convention runs through the whole standard library; the [Capability Reference](CAPABILITY_REFERENCE.md) marks which builtins return a pair. (Idiom note: keep `return` inside functions rather than at the top level of a program.)

### First-class functions and closures

Functions are values: you can bind them, pass them, return them, and capture free variables.

```mutant
let adder = fn(n) {
    return fn(x) { return x + n; };   // closes over n
};
let add10 = adder(10);
putln(add10(5));                       // 15
```

### Higher-order collection functions

Closures compose with the functional collection builtins `map`, `filter`, `reduce`, `each`, and `sort_by`:

```mutant
let nums = [5, 3, 8, 1];
let doubled = map(nums, fn(x) { return x * 2; });
let big = filter(nums, fn(x) { return x > 3; });
let total = reduce(nums, fn(acc, x) { return acc + x; }, 0);
let sorted = sort_by(nums, fn(x) { return x; });
```

`map`/`filter`/`each` callbacks may also take `(element, index)`.

Notes:
- String literals are simple quoted strings; escape-sequence behavior is intentionally limited.
- **Semicolons are required to terminate statements** — including statements whose value is a block, e.g. `let f = fn() { ... };` and `if (c) { ... };`. The language server's formatter enforces this canonically (it repairs missing semicolons and removes redundant ones on format), and the `semicolon` diagnostic flags them while you type.

## Reserved Keywords

- break
- continue
- else
- enum
- false
- fn
- for
- if
- let
- macro
- return
- struct
- true

## Builtins

**Total builtins currently registered: 399**, across 32 capability categories.

The complete catalog — every builtin with its signature, platform support, and description — lives in the **[Capability Reference](CAPABILITY_REFERENCE.md)**, which is generated directly from `builtin/metadata.go` so it never goes stale. The categories are indexed below; each links into that reference.

| Category | Count | What it covers |
| --- | --- | --- |
| [Standard library](CAPABILITY_REFERENCE.md#standard-library-54) | 54 | Core primitives, collection/hash ops, higher-order functions, I/O, introspection |
| [Strings](CAPABILITY_REFERENCE.md#strings-18) | 18 | Rune-aware string manipulation |
| [Text analysis](CAPABILITY_REFERENCE.md#text-analysis-14) | 14 | Search, split/replace, regex, fuzzy matching |
| [Structured data](CAPABILITY_REFERENCE.md#structured-data-25) | 25 | JSON, encoding, compression, type/base conversion, plist |
| [Math](CAPABILITY_REFERENCE.md#math-5) | 5 | Constants and random helpers |
| [Hashing](CAPABILITY_REFERENCE.md#hashing-11) | 11 | Digests, HMAC, UUID/ID generators |
| [Time](CAPABILITY_REFERENCE.md#time-7) | 7 | Unix timestamps, formatting, parsing, arithmetic |
| [Bytes](CAPABILITY_REFERENCE.md#bytes-30) | 30 | Binary buffer read/write, cursor, slicing |
| [Filesystem](CAPABILITY_REFERENCE.md#filesystem-19) | 19 | Files/dirs plus file-level forensics (hash, entropy, magic, carve, deleted) |
| [Network](CAPABILITY_REFERENCE.md#network-32) | 32 | Sockets, TLS/CA, HTTP inspection, WebSocket, scanning, pcap |
| [Http](CAPABILITY_REFERENCE.md#http-11) | 11 | HTTP client + request/response parse/build |
| [Graph database](CAPABILITY_REFERENCE.md#graph-database-14) | 14 | Nodes/edges/relations, traversal, pathfinding, stats |
| [Cache](CAPABILITY_REFERENCE.md#cache-8) | 8 | In-memory key/value cache with TTLs |
| [Policy](CAPABILITY_REFERENCE.md#policy-5) | 5 | Allow/deny policy evaluation and tracing |
| [Runtime integration](CAPABILITY_REFERENCE.md#runtime-integration-3) | 3 | Sandboxed Lua execution |
| [Command execution](CAPABILITY_REFERENCE.md#command-execution-4) | 4 | Guarded external command execution |
| [Cryptography](CAPABILITY_REFERENCE.md#cryptography-5) | 5 | X.509, JWT, PEM, AES-GCM |
| [Fingerprinting](CAPABILITY_REFERENCE.md#fingerprinting-4) | 4 | imphash, JA3, NT/LM hashes |
| [Network intelligence](CAPABILITY_REFERENCE.md#network-intelligence-11) | 11 | IOC defang/refang, IP/CIDR, domain/eTLD+1, IOC extraction |
| [Detection](CAPABILITY_REFERENCE.md#detection-5) | 5 | Injection, beaconing, persistence, priv-esc, suspicious files |
| [Process forensics](CAPABILITY_REFERENCE.md#process-forensics-9) | 9 | Live process inspection, memory scan, modules |
| [Memory forensics](CAPABILITY_REFERENCE.md#memory-forensics-6) | 6 | Memory-dump analysis, PE/shellcode discovery |
| [Binary analysis](CAPABILITY_REFERENCE.md#binary-analysis-14) | 14 | PE/ELF/Mach-O/DWARF, imports, GoReSym |
| [Registry forensics](CAPABILITY_REFERENCE.md#registry-forensics-15) | 15 | Hive/JSON/live registry, Amcache, Shimcache |
| [Filesystem forensics](CAPABILITY_REFERENCE.md#filesystem-forensics-31) | 31 | NTFS/FAT/exFAT/ext/HFS+/XFS parsers, $MFT |
| [Disk image forensics](CAPABILITY_REFERENCE.md#disk-image-forensics-17) | 17 | Raw/EWF/VHD(X) images, MBR/GPT tables |
| [Windows artifacts](CAPABILITY_REFERENCE.md#windows-artifacts-4) | 4 | Prefetch, EVTX, LNK, Jump Lists |
| [Unix artifacts](CAPABILITY_REFERENCE.md#unix-artifacts-1) | 1 | syslog (RFC 5424 / 3164) |
| [Browser artifacts](CAPABILITY_REFERENCE.md#browser-artifacts-4) | 4 | Chromium/Firefox history/cookies/downloads, SQLite |
| [Forensic timeline](CAPABILITY_REFERENCE.md#forensic-timeline-5) | 5 | Timestamp normalize, merge/sort, bodyfile/mactime |
| [Email forensics](CAPABILITY_REFERENCE.md#email-forensics-5) | 5 | Header/body/attachment parsing, DKIM verification |
| [Hash-set forensics](CAPABILITY_REFERENCE.md#hash-set-forensics-3) | 3 | NSRL-style known-file filtering |

### Platform support

Almost every builtin is pure-Go and cross-platform — the forensic parsers operate on *captured* artifacts, so they run on any host. A few live-system builtins are platform-restricted and fail honestly elsewhere; the language server warns when you call one on an unsupported OS:

- `process_memory_scan` — Windows, Linux
- `process_modules` — Windows, Linux
- `reg_open` — cross-platform for hive-file/JSON inputs; the live-registry path (`HKLM\...`) is Windows-only
- `process_kill` — cross-platform; on Windows only SIGKILL semantics apply

## Quick Example

```mutant
// Read a JSON target list, resolve each host, and print a report.
// Program logic lives in a function so `return` is never used at the top level.
let run = fn() {
    let raw, err = fs_read("targets.json");
    if (err) {
        putln("[error] fs_read:", err);
        return false;
    };

    let targets, parse_err = json_parse(raw);
    if (parse_err) {
        putln("[error] json_parse:", parse_err);
        return false;
    };

    let results = map(targets["hosts"], fn(host) {
        let addrs, resolve_err = net_resolve(host);
        if (resolve_err) {
            return { "host": host, "ok": false, "error": resolve_err };
        };
        return { "host": host, "ok": true, "addresses": addrs };
    });

    let report, stringify_err = json_stringify({ "results": results });
    if (stringify_err) {
        putln("[error] json_stringify:", stringify_err);
        return false;
    };
    putln(report);
    return true;
};

run();
```

## Maintenance

When adding or changing language keywords or builtins, update the source definitions first
(`token/token.go`, `builtin/builtin.go`, `builtin/names.go`, `builtin/metadata.go`), then
regenerate [CAPABILITY_REFERENCE.md](CAPABILITY_REFERENCE.md) from the metadata and review this
file. The category counts above and in the capability reference come straight from the registry,
so keep them in sync by regenerating rather than hand-editing.
