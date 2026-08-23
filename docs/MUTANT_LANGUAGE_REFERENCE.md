# Mutant Language Reference

This document is the practical reference for Mutant language features, reserved keywords, and builtins.

Source of truth:
- Keywords: token/token.go
- Builtins registry: builtin/builtin.go
- Builtin names/constants: builtin/names.go
- Builtin teaching metadata/signatures: builtin/metadata.go

Related references:
- [Capability Reference](CAPABILITY_REFERENCE.md) — the full, category-grouped catalog of every builtin, with parameter types (generated from the metadata above by `cmd/gendocs`).
- Deep-dive guides: [Secure Networking](SECURE_NETWORKING.md), [Graph Database](GRAPH_DATABASE.md), [Runtime Integration](RUNTIME_INTEGRATION.md), [Structured Data](STRUCTURED_DATA.md).

## Language Features

Mutant supports:
- Variables and assignment with `let`
- Primitive literals: integers, floats, booleans, strings
- Compound literals: arrays, hashes, struct literals
- Prefix operators: `!` and unary `-`
- Infix operators: `+ - * / % < > <= >= == != && ||`
- Assignment: `=`, compound assignment `+= -= *= /= %=`, and postfix `++` / `--`
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

### Binding several names at once

`let a, b = ...` binds more than one name from a single expression. What it does
depends on what is on the right:

```mutant
let data, err = fs_read(path);   // a fallible builtin: result, then error
let first, second = [1, 2, 3];   // an array: element by element -- 1 and 2
let value, extra = 42;           // anything else: value goes to the first name,
                                 // extra is null
```

Names past the end are null, and elements past the last name are dropped.

**This is worth knowing before you write `let x, err = ...` out of habit.** A
builtin that cannot fail returns one value, not a pair — and if that value is an
array, the binding takes it apart instead of reporting an error:

```mutant
let items = ["a", "b"];
let updated, err = push(items, "c");   // WRONG: push returns one array
                                       // updated is "a", err is "b"

let updated = push(items, "c");        // right: ["a", "b", "c"]
```

Nothing about this fails at compile time, and `err` is usually falsy, so an
`if (err)` check passes and the program carries on with the wrong value. Check
the [Capability Reference](CAPABILITY_REFERENCE.md) for whether a builtin returns
a pair; `push`, `first`, `last`, `rest` and `len` do not.

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

### Running a callback in parallel (`pmap` / `peach`)

Collection work in this language is usually I/O- or CPU-bound per element --
hashing a directory of files, resolving a list of domains, scanning a range of
ports -- and doing it one element at a time is what makes a collection script
slow. `pmap` is `map` with the elements processed concurrently; `peach` is `each`.

```mutant
// Hash every file in a directory, eight at a time.
let digests = pmap(paths, fn(path) {
    let digest, err = fs_hash(path, "sha256");
    if (err) { return ""; };
    return digest;
}, 8);
```

**Results keep the input's order.** Workers finish out of order, but each result
lands back in its element's position, so `pmap` is a drop-in replacement for
`map` wherever the callback is independent per element.

The third argument caps how many run at once. Omit it and the worker count
follows the machine's CPU count, capped by the array length.

**What the callback may rely on.** Each worker runs on its own VM with a
*snapshot* of globals, taken when the call starts. So a callback can read
globals and its own captured variables, but an assignment to a global stays
local to that worker and is lost when it finishes. Write callbacks that return
their result rather than accumulating into a global; when workers genuinely need
to share state, put it in a `cache_*` or `db_*` store, which is what `net_serve`
handlers already do.

An error raised inside a callback stops the whole call and surfaces, the same as
in `map`.

### Running one function alongside the program (`spawn` / channels)

`pmap` covers the case where the work is an array. When it isn't -- a server
handling connections, a long collection running while the program does something
else -- `spawn` runs a single function on its own VM and hands back a handle:

```mutant
let t, err = spawn(fn(dir) {
    let entries, e = fs_walk(dir);
    return len(entries);
}, "/evidence");

// ... do other work here ...

let count, werr = task_wait(t);
```

`spawn(fn)` calls a function of no parameters and `spawn(fn, arg)` one of a
single parameter. `task_wait(handle)` blocks for the result; `task_wait(handle,
ms)` gives up after a while and leaves the task collectable; `task_done(handle)`
answers without waiting. Whatever stopped a task -- an error, a division by zero
-- comes back in `task_wait`'s error slot rather than taking the program down.
Collecting a task releases its handle, so wait for it once.

**A spawned task follows the same rules as a `pmap` worker**: its own VM, its own
stack, and a *snapshot* of globals taken at the spawn. It can read globals and
its captured variables; its own writes stay local. The way back is the return
value, or a channel.

#### Channels

A channel passes values between concurrently running code, since the pieces
share no variables:

```mutant
let ch, e = chan_new(16);            // 16 values may queue; 0 is unbuffered

let t, se = spawn(fn(c) {
    let entries, err = fs_walk("/evidence");
    for (let i = 0; i < len(entries); i++) {
        let sent, serr = chan_send(c, entries[i]["path"]);
    }
    let closed, cerr = chan_close(c);   // tells the receiver there is no more
}, ch);

for (;;) {
    let r, rerr = chan_recv(ch, 5000);  // wait up to 5s
    if (!r["ok"]) { break; }            // closed, or timed out
    putln(r["value"]);
}
```

`chan_recv` reports `{ok, value, closed, timeout}` rather than returning the
value directly, because `null` is itself a sendable value: `ok` is the only way
to tell "received null" from "received nothing". `chan_try_recv` is the same
without ever waiting. Values already queued survive a close, so a receive loop
drains a closed channel before it sees `closed`.

`chan_send` returns true once the value is handed over and false if its timeout
ran out; sending on a *closed* channel is an error, because the value had
nowhere to go.

#### What happens at exit

The runtime waits for every spawned task before the program ends, so work
started and never collected still finishes. The flip side is that a task which
never returns keeps the program alive -- close the channel it is waiting on, or
give its receive a timeout.

At most 1024 tasks run at once. Past that `spawn` reports an error rather than
blocking, so an accept loop can shed load instead of deadlocking.

### Logical operators

`&&` (and) and `||` (or) combine conditions and **short-circuit** — the right
operand is only evaluated when the left doesn't already decide the result. They
return a strict boolean (using the same truthiness rules as `if`). Precedence:
comparisons bind tighter than `&&`, which binds tighter than `||`.

```mutant
// The right side is skipped when the left decides the outcome.
let has_both = si_frac == 0 && fn_frac > 0;   // both conditions must hold
let ready = configured || force;               // either is enough
```

### Compound assignment and increment/decrement

`+= -= *= /= %=` update a variable in place using its current value, and postfix
`++` / `--` add or subtract one. They are pure syntactic sugar: `x += y` is exactly
`x = x + y`, and `x++` is exactly `x = x + 1`, so they follow the same operator
semantics (integer vs. float promotion, `+=` concatenating strings, integer
division/modulo-by-zero errors). The target must be an assignable lvalue — a
variable, field, or index — and, like any `=`, the whole expression evaluates to
the newly stored value.

```mutant
let total = 0;
for (let i = 0; i < 5; i++) {   // i++ in the loop's post section
    total += i * 2;             // total = total + i * 2
};

let name = "mut";
name += "ant";                  // string concatenation -> "mutant"

let n = 100;
n -= 30;   n /= 2;   n %= 9;    // chained: 100 -> 70 -> 35 -> 8
```

### Macros (`macro`, `quote`, `unquote`)

A macro is a template the compiler expands before it generates any code. It
receives its arguments as **source**, not as values, and returns source that is
substituted at the call site.

```mutant
let unless = macro(condition, consequence, alternative) {
    quote(if (!(unquote(condition))) { unquote(consequence); } else { unquote(alternative); });
};

unless(1 > 2, putln("smaller"), putln("bigger"));   // prints: smaller
```

- `quote(expr)` captures `expr` as source instead of evaluating it. A macro body
  must end in one; a body that produces an ordinary value is a compile error.
- `unquote(expr)` is only meaningful inside a `quote`. It evaluates `expr` at
  expansion time and splices the result in as source. Only values with a literal
  spelling can make that trip — integers, floats, strings, booleans, and
  already-quoted source. Splicing an array, a hash or a function is a compile
  error.
- Macro parameters arrive already quoted, so `unquote(param)` substitutes the
  **argument's source**, unevaluated. `add(dynamic, 5)` substitutes the
  identifier `dynamic`, not whatever it holds at expansion time.

**Declaration and scope.** Macros are collected from top-level statements only,
and their declarations are removed from the program before compilation. A macro
declared inside a function or a block is never collected, and is reported as
such. A macro is not a value: it cannot be passed to a function, stored in an
array, or called at run time.

**Where calls expand.** Anywhere an expression can appear — as a call argument,
an array element, an index, a `for` header, an assignment's right side, a struct
literal field. A macro may also expand into a call to another macro; expansion
repeats until nothing changes. A macro that expands into a call to itself never
settles and is reported rather than run forever.

**When expansion happens.** During compilation, so `mutant gen` needs no flag
and neither do the examples in [examples/macros/](../examples/macros/). The
interactive REPL only defines macros when started with `-em` /
`--enable-macros`; it then expands and compiles them on the same path the CLI
uses, so the flag does not change what the language means.

### Notes
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

**Total builtins currently registered: 409**, across 33 capability categories.

The complete catalog — every builtin with its typed signature, platform support, and description — lives in the **[Capability Reference](CAPABILITY_REFERENCE.md)**, which is generated directly from `builtin/metadata.go` by `cmd/gendocs` so it never goes stale. Regenerate it with `go run ./cmd/gendocs` after adding or changing a builtin; `go run ./cmd/gendocs -check` (and the `cmd/gendocs` test) fails if it has drifted. The categories are indexed below; each links into that reference.

| Category | Count | What it covers |
| --- | --- | --- |
| [Standard library](CAPABILITY_REFERENCE.md#standard-library-56) | 56 | Core primitives, collection/hash ops, higher-order functions (including parallel `pmap`/`peach`), I/O, introspection |
| [Concurrency](CAPABILITY_REFERENCE.md#concurrency-8) | 8 | Background tasks (`spawn`/`task_wait`) and channels for passing values between them |
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

## Command-line tooling

Beyond compiling and running, the `mutant` CLI exposes the same formatter and
analyzer the language server uses, so editor and command-line results agree:

- `mutant fmt [--check] [--stdout] <file-or-dir>...` — rewrite source in the
  canonical style in place. `--check` lists files that are not already formatted
  and exits non-zero (for CI) without writing; `--stdout` prints the formatted
  result instead of editing. Formatting is idempotent.
- `mutant lint [--strict] <file-or-dir>...` — print diagnostics as
  `file:line:col: severity: message [source]`; exits non-zero on any error, or on
  any warning with `--strict`.
- `mutant test [file-or-dir]...` — run every `*_test.mut` file. A test file is an
  ordinary program: it **passes** unless running it errors (parse, compile, or
  runtime) or its final value is `false`. With no path it tests the current
  directory.

Directory arguments are walked recursively (skipping `.git`, `node_modules`, and
`vendor`).

```mutant
// math_test.mut  -> `mutant test .`
let add = fn(a, b) { return a + b; };
add(2, 3) == 5 && add(-1, -1) == -2;   // final value must be true to pass
```

## Maintenance

When adding or changing language keywords or builtins, update the source definitions first
(`token/token.go`, `builtin/builtin.go`, `builtin/names.go`, `builtin/metadata.go`), then
regenerate [CAPABILITY_REFERENCE.md](CAPABILITY_REFERENCE.md) from the metadata and review this
file. The category counts above and in the capability reference come straight from the registry,
so keep them in sync by regenerating rather than hand-editing.
