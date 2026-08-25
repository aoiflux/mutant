# Mutant Examples

This folder is organized by feature area so examples are easy to discover.

## How to run

`mutant <file>.mut` compiles a source file; it does not run it. Running means
compiling first, then running the `.mu` the compile writes beside the source.
From the repository root:

```bash
mutant gen --src examples/text/text_matching_example.mut --password <password>
mutant examples/text/text_matching_example.mu --dev --password <password>
```

Some examples use fixture files in:

- `examples/data/`
- `examples/data/memory_dump.bin`
- `examples/data/offline_hive.json`

## Sweeping every example

`cmd/sweep` compiles and runs every example through the real CLI. It is the
cheapest end-to-end check in the repository, and it has caught engine defects
that no unit test did.

```bash
go run ./cmd/sweep                       # every example, mutation 0
go run ./cmd/sweep examples/network      # one folder
go run ./cmd/sweep --levels 0,5,10       # also require identical output across
                                         # mutation levels
```

Each example runs in a throwaway copy of this tree, reset before every run, so a
sweep never dirties the repository and one example's output files cannot change
what the next one does.

With more than one level, an example has to produce the same output at each of
them -- the polymorphic engine may rewrite the bytecode, but not what a program
prints. Plenty of examples read a clock, walk a live filesystem or reach the
network, so the sweep first runs the lowest level twice and only compares the
levels of an example that reproduced itself. That is measured rather than
declared: which builtins are pure is not something an example author should have
to track.

### Sweep markers

A few examples cannot be treated as "compile it, run it, expect it to finish":
some serve until interrupted, and some are handed a connection by `net_serve`.
Without a way to say so, a sweep reports them as hangs and failures, and the
next person cannot tell those apart from a program that genuinely broke.

A comment says which:

```
// mutant:sweep server -- binds 127.0.0.1:8140 and serves until interrupted
```

| Mode | What a sweep does | For |
| --- | --- | --- |
| `run` | Compile, run, expect it to finish successfully. | Every example. This is the default and is normally left unwritten. |
| `server` | Start it and require it to be **still running** a few seconds later, then stop it. Exiting early is the failure. | A program that binds a port and serves until interrupted. |
| `serve-handler` | Compile it and stop there. | A program `net_serve` dispatches to, which has no connection of its own to read. |

The reason after `--` is required, because the whole point of the marker is
telling a future reader why this example is not treated like the others.

The mode is checked against what the program actually calls
([`sweep.Check`](../sweep/check.go), enforced by `go test ./sweep`), so a marker
cannot quietly go stale:

- A program that opens a listener or calls `serve_conn()` **must** carry a
  marker. A sweep cannot guess whether it returns, and guessing wrong is what
  makes a timeout unreadable.
- A marker naming `server` or `serve-handler` **must** be backed by code that
  does that. Otherwise it is left over from a rewrite, and it is excluding an
  example that now runs fine.

`run` stays available to any program, with a reason. Not every file that calls
`serve_conn()` is unrunnable -- `examples/project/portscan_service/handler.mut`
checks for null and prints a notice -- and a marker is an instruction to the
sweep, not a category the file belongs to.

## Folder map

- `examples/basics/` language syntax and control flow
- `examples/macros/` quote/unquote and macro expansion patterns
- `examples/text/` text, fuzzy matching, regex pipelines
- `examples/policy/` OPA/Rego policy loading and decisions
- `examples/cache/` cache open/put/get/ttl/stats workflows
- `examples/filesystem/` fs I/O and filesystem forensics
- `examples/network/` http/net and network-forensics style flows
- `examples/binary/` binary/PE parsing and entropy-driven triage
- `examples/registry/` offline registry forensic examples
- `examples/email/` email parsing and phishing triage
- `examples/memory/` memory scanning and shellcode/PE hunting
- `examples/graph/` graph modeling and timeline-style investigation
- `examples/detection/` detection builtins and multi-signal scoring
- `examples/security/` environment diagnostics and anti-analysis status
- `examples/lua/` Lua interop examples and helper scripts
- `examples/bytes/` byte cursor and binary-safe parsing helpers
- `examples/concurrency/` spawn, task_wait, channels, and pmap

## Suggested learning path

1. Start with `examples/basics/`
2. Move to `examples/macros/`, `examples/text/`, and `examples/cache/`
3. Explore `examples/policy/` for policy gates
4. Use forensic folders (`memory`, `registry`, `email`, `network`, `binary`)
5. Finish with `examples/graph/` and `examples/detection/` for correlation
