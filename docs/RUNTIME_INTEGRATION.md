# Runtime Integration: Embedding Lua

Mutant can embed and run Lua scripts from a string, a file, or a remote HTTP
endpoint. This is useful for anything you want to keep as data instead of
compiled logic: scoring functions, detection/classification rules, response
policies — content that a rules team can edit and ship without touching the
Mutant program that drives it.

Because embedded scripts may come from outside the program (a file on disk, or
a URL that returns whatever its server chooses to return), every script runs
inside a restricted Lua sandbox by default. The sandbox is the same for all
three entry points: a fixed set of safe standard libraries, no filesystem or
process access from Lua's own standard library, and a bounded execution time.
Treat any script whose origin you do not fully control — especially one
fetched over HTTP — as untrusted input, and rely on the sandbox (not on the
script's good behavior) to contain it.

---

## Capability table

| Builtin | Signature | Returns |
| --- | --- | --- |
| `lua_run_string` | `(code)` | `(result, err)` — `result` is a hash, see below |
| `lua_run_file` | `(path)` | `(result, err)` — `result` is a hash, see below |
| `lua_run_http` | `(url)` | `(result, err)` — `result` is a hash, see below |

All three follow the language's `(result, err)` convention, but — like
`net_conn_read` / `net_accept` in `SECURE_NETWORKING.md` — a Lua-level failure
is reported *inside* the result hash, not through `err`. `err` (the second
return value) only fires for problems outside the Lua VM itself: a bad
argument type, a `lua_run_file` path that can't be read, or a `lua_run_http`
request that fails at the HTTP layer. Once the script is actually loaded, its
outcome always lands in the hash, so check both:

```
let result, err = lua_run_string(code);
if (err) {
    putln("[lua error] ", err);
} else if (!result["ok"]) {
    putln("[lua script error] ", result["error"]);
} else {
    putln("[lua result] ", result["result"]);
};
```

`result` is always a hash with these fields:

| Field | Type | Meaning |
| --- | --- | --- |
| `ok` | bool | `false` if the script failed to compile/run (syntax error, runtime error, or timeout) |
| `result` | string | the script's outcome — see "Result and print capture" below |
| `error` | string | the Lua compile/runtime error message, empty when `ok` is `true` |
| `schema_version` | int | `1` |

### Result and print capture

Whatever the Lua chunk returns is converted to a **string** and placed in
`result["result"]`:

- Strings, numbers, and booleans stringify to their obvious text form.
- `nil`/no return stringifies to the literal string `"nil"`.
- Tables, functions, userdata, and threads are **not serialized** — they
  render as opaque placeholders like `<table>`. A script that wants to hand
  back structured data must build that string itself (see
  `examples/lua/static_binary_parser.lua`, which hand-assembles a JSON
  string), and the caller can then parse it with Mutant's own JSON builtins.
- If the chunk returns nothing at all *and* it called Lua's `print(...)`,
  the captured print output (joined the way `print` normally joins its
  arguments, trailing newline trimmed) is returned instead — this lets quick
  scripts use `print` instead of an explicit `return`.

`print` inside the sandbox does **not** write to Mutant's own stdout; it is
captured into a buffer and surfaces only through `result["result"]` as
described above.

---

## Secure execution guidelines

The Lua state backing all three builtins (`lua_run_string`, `lua_run_file`,
`lua_run_http`) is built the same way, with `SkipOpenLibs` and only a curated
set of libraries opened on top:

- **Opened:** `base`, `math`, `string`, `table`, `os`.
- **Never opened:** `io` — it would expose arbitrary host file read/write
  through ordinary Lua code, so it is left out entirely (not just hidden).
- **Removed after opening**, even if a base library would otherwise expose
  them: `debug`, `package`, `require`, `dofile`, `load`, `loadfile`,
  `loadstring`, `collectgarbage`, and (defensively) `io`. These are the
  globals that let a script load/eval further code or reach outside the
  sandbox at the language level.
- **Stripped from `os`:** `os.execute`, `os.exit`, `os.remove`, `os.rename`,
  `os.setenv`, `os.getenv`, `os.tmpname`. These are the host-affecting parts
  of the `os` library — command execution, process exit (which would also
  bypass the timeout below), filesystem mutation, and environment access.
  What remains on `os` is limited to the safe time/date helpers such as
  `os.time`, `os.date`, and `os.clock`.
- **Execution timeout:** every chunk runs under a Go `context` with a fixed
  **5-second** deadline, applied via `state.SetContext` before the `PCall`
  that executes it. Lua's VM checks that deadline as it runs, so a
  script that runs long (or loops forever) is aborted with a context-deadline
  error surfaced as `result["ok"] = false`. This timeout is fixed by the
  runtime; there is no argument on any `lua_*` builtin to change it.

There is one **intentional, non-sandboxed** capability exposed to every
script regardless of entry point: a `mutant` table is injected as a Lua
global with `mutant.version()`, `mutant.patch_name()`, and
`mutant.read_file(path)`. `mutant.read_file` reads a file **with the same
filesystem permissions as the Mutant process itself** — it is how a Lua
script gets file input without the general-purpose `io` library. Because it
is not scoped in any way, a script loaded from any source (including
`lua_run_http`) can use it to read any file the host process can read.
Do not treat "no `io` library" as "no file access" — file access exists, just
funneled through this one deliberate, auditable function. Do not use
`lua_run_http` (or `lua_run_file` with an untrusted path) against sources you
do not trust to behave, and do not assume `mutant.read_file` limits what a
script can reach.

### Why `lua_run_http` is higher risk

`lua_run_string` and `lua_run_file` run code you already chose to ship.
`lua_run_http` runs whatever the server behind that URL returns *right now* —
the content is not pinned, versioned, or reviewed by Mutant, and a
compromised or spoofed endpoint (or a plain MITM on an unencrypted URL) can
substitute arbitrary Lua. Treat the URL, and everything it returns, as
untrusted input:

- Prefer `https://` endpoints you control, and pin/verify them the same way
  you would any other remote dependency.
- The sandbox described above is the mitigation, not the script's contents:
  no `io`, no `os.execute`/`exit`/`remove`/`rename`, no environment access,
  and a 5-second execution cap apply identically whether the code came from
  a literal string, a local file, or a remote URL. `lua_run_http` gets no
  extra restrictions beyond that shared sandbox, so the sandbox is what has
  to hold — do not assume there is a stronger, separate "remote" mode.
- Because `mutant.read_file` is not restricted, remote code can still read
  local files; make sure any endpoint you point `lua_run_http` at is one you
  actually trust to receive that capability.
- Always check the `err` return (transport/DNS/HTTP failure) *and*
  `result["ok"]` (the fetched script failed to compile or run) before
  trusting `result["result"]`.

### No environment-variable configuration

Mutant code and its tests must never rely on environment variables — this
extends to the Lua sandbox. There is no `lua_*` configuration knob that reads
from the process environment, `os.getenv` is stripped from the Lua side, and
these docs deliberately give no "set FOO=bar" instructions. Configure
behavior (timeouts aside, which are fixed) through Mutant values you pass in
explicitly — script text, file paths, URLs, and data you build and hand to
the script via its return value / `print` output.

---

## Real-world examples

### 1. Inline scoring expression

Run a short Lua expression from a string and use its result directly in
Mutant logic:

```
let score_code = "local risk = 0; if 42 > 40 then risk = risk + 30 end; return tostring(risk)";
let result, err = lua_run_string(score_code);

if (err) {
    putln("[lua error] ", err);
} else if (!result["ok"]) {
    putln("[lua script error] ", result["error"]);
} else {
    let risk_score = result["result"];
    putln("risk score: ", risk_score);
};
```

A scoring function that takes its inputs via a small header built into the
same string works the same way — build the Lua source in Mutant, then run it:

```
let make_scorer = fn(bytes_seen, connections) {
    let header = "local bytes = " + bytes_seen + "; local conns = " + connections + "; ";
    let body = "local score = (bytes / 1024) + (conns * 5); return tostring(score)";
    return header + body;
};

let result, err = lua_run_string(make_scorer(20480, 6));
if (err) {
    putln("[lua error] ", err);
} else if (!result["ok"]) {
    putln("[lua script error] ", result["error"]);
} else {
    putln("score: ", result["result"]);
};
```

### 2. Classification rules from a file

Ship the rules as a `.lua` file next to your Mutant program and load it with
`lua_run_file`. This keeps rule logic editable without recompiling or
re-releasing the Mutant script that drives it:

```
let classify_path = "rules/classify.lua";
let result, err = lua_run_file(classify_path);

if (err) {
    putln("[lua_run_file error] ", err);
} else if (!result["ok"]) {
    putln("[classify.lua error] ", result["error"]);
} else {
    putln("classification: ", result["result"]);
};
```

`rules/classify.lua` can read whatever local input it needs through
`mutant.read_file`, and returns a plain string (build JSON by hand, as
`examples/lua/static_binary_parser.lua` does, if the caller needs structure):

```lua
local data, read_err = mutant.read_file("examples/data/sample.exe")
if not data then
    return "unknown:read_failed"
end

if #data > 1048576 then
    return "large_binary"
end

return "small_binary"
```

See `examples/lua/lua_run_file_example.mut` and
`examples/lua/lua_sample_patch.lua` for a runnable version of this pattern.

### 3. Remote policy via `lua_run_http`

Fetch and run a policy script hosted elsewhere. Treat the endpoint as
untrusted, handle both failure layers, and don't forget the sandbox is what
is actually protecting you here — not trust in the remote server:

```
let policy_url = "https://policy.internal.example.com/current.lua";
let result, err = lua_run_http(policy_url);

if (err) {
    // Transport/DNS/HTTP failure — the endpoint was unreachable or returned
    // an error response.
    putln("[lua_run_http transport error] ", err);
} else if (!result["ok"]) {
    // The fetched script failed to compile or run (or hit the sandbox's
    // 5-second timeout). Sandboxed misbehavior, not a leak — but treat a
    // failing remote script as a signal to fall back to a local default.
    putln("[remote policy error] ", result["error"]);
} else {
    // Sandboxed: no io, no os.execute/exit/remove/rename, no env access,
    // capped at 5s. Still, the policy has mutant.read_file, so only point
    // this at endpoints you trust with local file read.
    putln("policy decision: ", result["result"]);
};
```

A minimal server-side script for the endpoint above (see
`examples/lua/lua_http_server_example.go` for a runnable stub that serves
`examples/lua/lua_sample_patch.lua` this way):

```lua
-- current.lua
return "allow"
```

---

## Environment notes

- **No environment variables.** Every configurable input — script text, file
  path, URL — is an explicit argument to the `lua_*` builtin. There is no
  `os.getenv`-based or process-environment-based configuration on either the
  Mutant or the Lua side, and none should be added.
- **Pure Go, cross-platform.** The Lua runtime (`gopher-lua`) is a pure-Go
  implementation with no cgo and no external interpreter binary to install;
  the same sandbox behavior applies on every platform Mutant runs on.
- **Errors surface through the `(result, err)` pair**, with two layers as
  described above: `err` for failures before the script ever ran (bad
  argument, unreadable file, failed HTTP fetch), and `result["ok"]` /
  `result["error"]` for failures inside the Lua VM (syntax error, runtime
  error, or the 5-second execution timeout). Always check `err` first, then
  `result["ok"]`, before reading `result["result"]`.

---

## Notes & limits

- The sandbox is not a full OS environment. There is no `io` library, no
  `os.execute`/`exit`/`remove`/`rename`/`setenv`/`getenv`/`tmpname`, no
  `require`/`load`/`loadstring`/`dofile`/`loadfile`, and no `debug` or
  `package` library. Lua scripts cannot spawn processes, mutate the
  filesystem, or load further code from within the sandbox.
- The one exception is `mutant.read_file(path)`, a deliberate, unsandboxed
  read-only file API exposed to every script — see "Secure execution
  guidelines" above. It is the only filesystem access Lua code has, and it is
  unrestricted by path, so scope what you point `lua_run_file`/`lua_run_http`
  at accordingly.
- There is no way for a Lua script to call back into Mutant's own builtins
  (networking, graph DB, filesystem parsers, etc.) — it only sees `mutant`'s
  three helper functions and the standard `base`/`math`/`string`/`table`/`os`
  libraries. Do privileged work (network calls, cache/graph access, parsing
  disk images) in Mutant itself, and pass the results into the script as
  plain data via the source string; take the script's plain-string answer
  back out the same way.
- Return values are always flattened to a string. If a script needs to hand
  back structured data, have it serialize (e.g. hand-rolled JSON, as in
  `examples/lua/static_binary_parser.lua`) rather than returning a table.
- The 5-second execution timeout is fixed for all three builtins; there is no
  per-call override. Scripts that need longer should be redesigned to do less
  per invocation rather than relying on a longer deadline.
