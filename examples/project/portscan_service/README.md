# portscan_service — a multi-file Mutant project

A minimal, idiomatic example of a Mutant project split across more than one `.mut`
file, using `net_serve` to run a concurrent TCP service.

## Layout

```
portscan_service/
├── main.mut      # entry point: opens the listener, runs the accept loop (net_serve)
├── handler.mut   # per-connection logic, spawned fresh per connection
└── README.md     # this file
```

## How it fits together

Mutant does not have an `import` statement; instead, a program composes other
`.mut` files at runtime through builtins that take a file path. `net_serve` is the
key one here:

- **`main.mut`** opens a listener with `net_listen`, then calls
  `net_serve(listener, "…/handler.mut", banner)`. `net_serve` owns the accept loop
  and, for every accepted connection, compiles `handler.mut` once and runs it on a
  **fresh VM** with its own stack and globals. A bounded pool caps how many handler
  goroutines run at once (backpressure), so a flood of connections cannot exhaust
  memory.
- **`handler.mut`** reads its connection handle via `serve_conn()` and the shared
  argument (the banner string passed as the third argument to `net_serve`) via
  `serve_arg()`. It greets the client, reads a request, replies, and closes the
  connection. Because it is a normal program, it also runs standalone — then
  `serve_conn()` returns null and it prints a notice instead.

This is the same pattern used to build interception proxies and other network
services entirely in Mutant (see [docs/SECURE_NETWORKING.md](../../../docs/SECURE_NETWORKING.md)).

## Running it

From the repository root (so the relative handler path resolves):

```
# Compile then run the entry point (choose any password):
mutant run examples/project/portscan_service/main.mut -pwd mypass
mutant     examples/project/portscan_service/main.mu   -pwd mypass
```

The service listens on `127.0.0.1:8085`. In another terminal:

```
printf 'hello\r\n' | nc 127.0.0.1 8085
```

You will receive the banner and an `OK` response; the server logs the byte count.
Stop the server with Ctrl-C.

> Note: `main.mut` blocks in the accept loop by design (it is a server). The
> handler applies write deadlines so a stalled client cannot hang a handler.
