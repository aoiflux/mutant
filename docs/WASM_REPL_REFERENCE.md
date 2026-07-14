# Mutant WASM REPL Definitive Guide

This document is the implementation-accurate reference for the browser WASM
REPL:

- what language features are supported
- which builtins are available
- exact API contracts
- known differences from CLI REPL
- what is intentionally unsupported and why

Source of truth:

- cmd/replwasm/main_wasm.go
- webrepl/repl.go

## Quick Reference

| Area                    | Status        | Notes                                                                          |
| ----------------------- | ------------- | ------------------------------------------------------------------------------ |
| Runtime mode            | Supported     | Persistent session state across eval calls                                     |
| API globals             | Supported     | mutantReplReady, mutantReplEval, mutantReplComplete, mutantReplCompleteLine    |
| Core language           | Supported     | numbers (int/float), bool, string, arrays, hashes, if/for, functions           |
| Struct/enum features    | Supported     | declarations, literals, field access/assignment                                |
| Return/break/continue   | Supported     | control-flow propagation implemented                                           |
| Macro system            | Not supported | macros and quote/unquote are intentionally excluded                            |
| Builtins (browser-safe) | Supported     | 81 builtins across core, bytes, json, regex, text, policy, cache, in-memory db |
| Host-bound builtins     | Not supported | fs/process/exec/network/registry/memory/binary/disk-image families             |
| Completion modes        | Supported     | supported (callable-now) and all (discoverability)                             |
| Output model            | Supported     | buffered putf/putln + optional final expression append                         |
| Error model             | Supported     | parser/runtime errors returned as ok=false                                     |

## CLI to WASM Migration Cheat Sheet

| If your CLI REPL usage looks like this                                | In WASM REPL, do this                                                                                           | Why                                                                                       |
| --------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------- |
| Use filesystem and disk/image builtins (fs__, ntfs__, vhdi_*, etc.)   | Move data loading to browser-side JavaScript and pass data into browser-safe builtins                           | Browser sandbox does not expose host filesystem/block devices                             |
| Use process/exec builtins (process__, cmd__, exec_string)             | Replace with deterministic in-memory workflows and explicit JS integration points                               | No shell/process table access in WASM browser runtime                                     |
| Use net__/http__ directly from Mutant                                 | Perform network fetches in JavaScript, then hand responses to Mutant (for example json_parse/text_* operations) | Current browser bridge does not map full Go networking builtin behavior                   |
| Depend on registry/memory/binary host artifacts (reg__, mem__, bin_*) | Pre-collect artifacts outside WASM and feed parsed or raw content as Mutant values                              | These families require host forensic sources                                              |
| Use db_open_disk                                                      | Use db_open (in-memory) and recreate needed state per session                                                   | Disk-backed handles are not browser-safe                                                  |
| Expect all CLI builtins to be callable                                | Use mutantReplEval(...).builtins or mutantReplComplete(..., "supported") to discover callable set               | WASM intentionally exposes only browser-safe builtin subset                               |
| Rely on MultiValue builtin pairs in script logic                      | Call builtins normally; WASM wrappers unwrap (value,error) and surface error as runtime failure                 | Browser REPL normalizes builtin results for interactive use                               |
| Use macro/quote workflows                                             | Rewrite using plain functions/expressions                                                                       | Macros and quote/unquote are intentionally unsupported                                    |
| Debug parser issues with escaped strings                              | Keep policy/module strings simple; avoid heavy escaping and nested quotes                                       | String literal handling is intentionally minimal and easier to break with complex escapes |
| Need concise output only from putln/putf                              | End with null-producing statement if you do not want trailing expression echo                                   | REPL may append final non-null expression to buffer output                                |

Minimal migration checklist:

1. Replace host-bound builtins with browser-side data acquisition.
2. Verify callable builtins with supported completion mode.
3. Convert disk-backed DB flows to db_open in-memory flows.
4. Simplify quote-heavy strings in policy/testing snippets.
5. Re-test expected output formatting (putf/putln plus final expression
   behavior).

## 1) Runtime Model

The WASM REPL runs a browser-safe evaluator and keeps one persistent session
environment.

What this means:

- Variables, functions, structs, enums, and values persist across eval calls.
- Output buffer is per-eval call and resets at the start of each call.
- Evaluation is synchronous from JavaScript caller perspective.

Design goal:

- Closest practical parity with CLI language behavior
- Expose builtins that are meaningful and safe in browser runtime
- Explicitly reject host-bound capabilities (filesystem/process/registry/etc.)

## 2) Browser Bridge API

The runtime exposes four globals:

- mutantReplReady: boolean
- mutantReplEval(input)
- mutantReplComplete(prefix, mode)
- mutantReplCompleteLine(line, mode)

### 2.1 mutantReplReady

- Type: boolean
- Meaning: bridge functions are registered and ready to accept calls

### 2.2 mutantReplEval(input)

Input:

- input: string

Success response shape:

```json
{
  "ok": true,
  "output": "...",
  "supported": "...",
  "builtins": ["..."]
}
```

Error response shape:

```json
{
  "ok": false,
  "error": "..."
}
```

Notes:

- supported is a compact, human-readable capability summary string.
- builtins is the sorted list of builtins supported by this WASM runtime.

### 2.3 mutantReplComplete(prefix, mode)

Inputs:

- prefix: string (optional)
- mode: string (optional, default: supported)

Response shape:

```json
{
  "ok": true,
  "candidates": ["..."]
}
```

Modes:

- supported: completion constrained to supported builtins and current symbols
- all: includes non-supported builtin names in help/completion contexts for
  discoverability

### 2.4 mutantReplCompleteLine(line, mode)

Context-aware completion for full lines, especially:

- :help topics
- help("topic") and help("topic", "mode") argument completion

Response shape is the same as mutantReplComplete.

## 3) Evaluation Semantics

### 3.1 Output behavior

- putf appends text without newline.
- putln appends text with newline.
- If final expression is non-null and output buffer is empty, returned output is
  expression Inspect string.
- If final expression is non-null and buffer has content, returned output is
  buffer + final expression Inspect.
- If final expression is null, returned output is buffered text with trailing
  newline trimmed.

### 3.2 Error behavior

- Parse errors are returned as ok=false with parser messages.
- Runtime errors are returned as ok=false with error Inspect text.
- Unsupported syntax returns explicit unsupported syntax error.

### 3.3 Truthiness

Falsey values:

- null
- false
- integer 0
- empty or whitespace-only string

All other values are truthy.

### 3.4 Numeric behavior

- Integers and floats are supported.
- Integer-only operations produce integers.
- Mixed/inferred numeric operations produce float when needed.
- Division by zero returns runtime error.

### 3.5 Return behavior

- return short-circuits function body execution.
- Returns propagate correctly through nested blocks and loops.

## 4) Language Feature Matrix

Supported:

- integers, floats, booleans, strings
- arrays, hashes, indexing
- let bindings (single and destructuring)
- assignment expressions
- if/else expressions
- for loops with init/condition/post
- break and continue
- function literals and user-defined function calls
- struct declarations and struct literals
- enum declarations and variant access
- field access and field assignment on structs
- return statements
- builtin calls listed in this guide

Intentionally unsupported:

- macros
- quote/unquote macro expansion flow

## 5) Builtin Support (Current)

Total supported builtins: 81

### 5.1 Core

- help
- len
- first
- last
- rest
- push
- pop
- putf
- putln

### 5.2 Bytes

- bytes_len
- bytes_get
- bytes_slice
- bytes_read_u16_le
- bytes_read_u16_be
- bytes_read_u32_le
- bytes_read_u32_be
- bytes_read_u64_le
- bytes_read_u64_be
- bytes_write_u16_le
- bytes_write_u16_be
- bytes_write_u32_le
- bytes_write_u32_be
- bytes_write_u64_le
- bytes_write_u64_be
- bytes_cstr_at
- bytes_hex
- bytes_char_from_int
- bytes_int_from_char
- bytes_cursor_new
- bytes_cursor_tell
- bytes_cursor_seek
- bytes_cursor_eof
- bytes_cursor_read_u8
- bytes_cursor_read_u16_le
- bytes_cursor_read_u16_be
- bytes_cursor_read_u32_le
- bytes_cursor_read_u32_be
- bytes_cursor_read_u64_le
- bytes_cursor_read_u64_be

### 5.3 JSON

- json_parse
- json_stringify

### 5.4 Regex

- regex_match
- regex_find
- regex_find_all
- regex_replace
- regex_capture_groups

### 5.5 Text

- text_contains
- text_index
- text_count
- text_split
- text_replace
- text_levenshtein
- text_similarity
- text_fuzzy_find
- text_jaro_winkler

### 5.6 Policy

- policy_load
- policy_eval
- policy_allow
- policy_rules
- policy_trace

### 5.7 Cache

- cache_open
- cache_put
- cache_get
- cache_delete
- cache_keys
- cache_stats
- cache_clear
- cache_close

### 5.8 Graph Database (In-Memory)

- db_open
- db_close
- db_add_node
- db_add_edge
- db_add_artifact
- db_add_relation
- db_index_prop
- db_query_nodes
- db_query
- db_bfs
- db_shortest_path
- db_timeline
- db_stats

## 6) Unsupported Builtins and Rationale

The following are intentionally unavailable in browser runtime.

### 6.1 Host filesystem/disk/image access

- fs_*
- ntfs__, fat__, xfat__, ext__, hfs__, xfs__
- vhdi__, ewf__, raw__, table__
- db_open_disk

Reason:

- Require host path or block device access not available in browser sandbox.

### 6.2 Host process/command/runtime security APIs

- process_*
- debug_status
- sandbox_status
- security_diagnostics
- exec_string
- cmd_*

Reason:

- Require process table, shell execution, or runtime host telemetry.

### 6.3 Network and live protocol access

- net_*
- http_*

Reason:

- Current builtin implementations rely on Go runtime networking sockets/pcap
  behavior not mapped to browser bridge.

### 6.4 Host forensic data sources

- reg_*
- mem_*
- bin_*
- email_*
- detect_*

Reason:

- Depend on host files, memory dumps, registry hives, executable artifacts, or
  privileged environment context.

### 6.5 Lua runtime integration

- lua_*

Reason:

- Current implementation expects host IO/network capabilities and full Lua
  runtime setup beyond current WASM bridge scope.

## 7) CLI REPL vs WASM REPL Notes

WASM aims for language parity where feasible, but there are runtime model
differences:

- Builtin wrapping: many builtins in CLI return value/error pairs as MultiValue.
  In WASM wrappers unwrap pair results and surface error slot as runtime error.
- Host-bound capabilities are excluded in WASM (see Section 6).
- Macro/quote workflows are not part of WASM runtime.

## 8) Completion and Help Behavior

### 8.1 Meta-help commands

Supported:

- :help
- :help keywords
- :help builtins
- :help examples
- :help docs
- help("topic")
- help("topic", "mode")

### 8.2 Completion mode semantics

- supported: prioritize symbols and builtins actually callable in WASM
- all: broader discoverability list (useful for learning CLI surface, even when
  not callable in browser)

## 9) Usage Patterns and Examples

### 9.1 Loop over array values

```mutant
let items = ["bytecode", "sandbox", "signing", "lsp"];
for (let i = 0; i < len(items); i = i + 1) {
  putln(items[i]);
};
```

### 9.2 Functions, structs, and enums

```mutant
struct Point { x; y; };
enum Color { Red, Green, Blue };

let scale = fn(p, factor) {
  let out = Point { x: p.x * factor, y: p.y * factor };
  return out;
};

let p = Point { x: 1.5, y: 2 };
let p2 = scale(p, 2);
putln(p2.x);
putln(Color.Green);
```

### 9.3 Policy + cache + in-memory graph

```mutant
policy_load("allow_policy", {
  "module": "package access
default allow = false
allow { true }
decision = allow
rules = [1]",
  "eval_query": "data.access.decision",
  "allow_query": "data.access.allow",
  "rules_query": "data.access.rules"
});

putln(policy_allow("allow_policy", {"user": "analyst"}));

cache_open("session");
cache_put("session", "count", 7);
putln(cache_get("session", "count")["value"]);

let h = db_open();
let n1 = db_add_node(h);
let n2 = db_add_node(h);
db_add_edge(h, n1, n2);
putln(len(db_query_nodes(h)));
```

### 9.4 Browser invocation

```javascript
const result = window.mutantReplEval("len([1, 2, 3])");
if (!result.ok) {
  console.error(result.error);
} else {
  console.log(result.output);
  console.log(result.supported);
  console.log(result.builtins);
}

const c1 = window.mutantReplComplete("text_", "supported");
console.log(c1.candidates);

const c2 = window.mutantReplCompleteLine('help("bu', "supported");
console.log(c2.candidates);
```

## 10) Troubleshooting

### Symptom: parser error for complex inline module strings

Cause:

- Mutant string literal behavior is intentionally simple; complex
  quoting/escaping is easy to break.

Fix:

- Keep policy module strings simple and avoid nested quote-heavy content.
- Build data structures with Mutant hashes/arrays where possible instead of
  deeply escaped JSON-like strings.

### Symptom: builtin appears in docs but fails in browser

Cause:

- You may be calling a host-bound builtin family.

Fix:

- Check Section 6 unsupported families.
- Use browser-safe alternatives where possible.

### Symptom: unexpected output concatenation

Cause:

- putf/putln buffer semantics plus final expression append behavior.

Fix:

- End scripts with null-producing statements when you only want printed output.

## 11) Maintenance Rules

When webrepl features change:

1. Update webrepl/repl.go supported builtin registry and wrappers.
2. Update webrepl tests to cover new support and failure modes.
3. Update this document in the same change.
4. Keep totals and support matrix synchronized with SupportedBuiltinNames
   output.
