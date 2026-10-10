# Configuration Policy

**Mutant takes no configuration from environment variables.** Using Mutant must
never require anyone to set, or even think about, an environment variable.

This document states the rule, the reasoning behind it, the narrow set of
environment reads that are permitted and why they are not configuration, and
what replaces the configuration surface that used to be documented here.

The rule is machine-enforced. See [The guard](#5-the-guard) below.

---

## 1. The rule

Three sub-rules, in order of strictness.

**Rule 1 — no Mutant-prefixed variable name may appear in Go source. No
exceptions, no allowlist.**

The guard matches any string literal of the form `MUTANT_` followed by upper-case
letters, digits and underscores. This is the load-bearing rule, because that
prefix is exactly the set of names someone could be told to set. If the name is
not in the binary, no instruction to set it can be true.

**Rule 2 — reading a foreign environment variable is permitted only where the
value is observed, never obeyed.**

Sandbox and VM detection, debugger and injection indicators, and the
`process_env` forensic builtin all read the environment. None of them let the
environment change a decision a user asked for. Each site is allowlisted
individually with a justification. The same holds for the few places the
standard library reads it on Mutant's behalf -- a name the REPL prints, the
temporary directory -- and section 3 lists what the environment can still
change.

**Rule 3 — writing the environment is permitted only when invoking a build-time
child `go build`.**

`GOOS`, `GOARCH` and `CGO_ENABLED` have no command-line equivalent; the Go
toolchain accepts them only through the child process environment. This applies
to `mutant release` cross-target builds and the WASM REPL builder — never to a
Mutant program's own execution.

### The distinguishing test

> **Would a Mutant user ever set this variable in order to change what Mutant
> does?**

If yes, it is prohibited — use a flag.

| A variable that... | Is set by | Verdict |
| --- | --- | --- |
| turns on stage timing | the user, to see where a run spends its time | **Prohibited.** Replaced by `--timing`. |
| selects a protection profile | the user, to weaken or harden checks | **Prohibited.** Removed; the profile is fixed at `standard`. |
| carries a trusted public key in hex | the user, to supply a key | **Prohibited.** Key *material* never belongs in the environment, where it is invisible in the invocation and inherited by every child process. A key *file path* belongs on the command line: `--trusted-key`. |
| overrides the tamper response | the user, to soften a termination | **Prohibited.** Derived from the execution mode instead. |
| `SANDBOXIE` | Sandboxie, when it wraps a process | **Permitted.** Mutant observes it as evidence of where it is running. |
| `LD_PRELOAD` | whoever injected a library | **Permitted.** An indicator of compromise, read and reported. |
| `GOOS` | Mutant, for a child `go build` | **Permitted.** Written, not read; no flag exists. |
| `HOME`, `USERPROFILE` | the shell or the launcher | **Not read.** The keystore once followed them; since 2.6.0 its location comes from the account database. |
| `TMPDIR` | the operating system | **Permitted.** It says where working files sit, never what Mutant reports. |

Every prohibited row above once existed and has been removed. Their names are
not reproduced here: a name in the documentation is exactly what leads someone
to try setting it, and none of them has done anything for some time. The
`HOME` row is not one of them: those variables belong to the system, and
Mutant stopped reading them (M26-DOC3-001).

The test is about *direction of authority*, not about the `os` package. Mutant
reading `SANDBOXIE` is Mutant looking at its surroundings. Mutant obeying a
variable of its own would be the surroundings looking at Mutant.

## 2. Why

**A run must be reproducible from its invocation alone.** Mutant is a forensic
tool. An analyst records the command they ran; that record has to be sufficient
to reproduce the result. An environment variable is an unlogged, invisible
control channel that never appears in that record — two analysts running the
same command line can get different behaviour and have no way to see why.

**The environment is the untrusted thing under examination.** Mutant inspects
processes and the machine it runs on. Taking instructions from the same
environment it is examining inverts the trust relationship.

**Nobody should need a setup step.** Installing Mutant and running a program is
the whole story. There is no variable to export, no shell profile to edit, and
nothing to forget on a second machine.

## 3. What is permitted, and where

Six categories. Every site is listed in `policy.EnvAccessAllowlist`
([policy/env_policy.go](../policy/env_policy.go)) with a line budget, so a new
read added *inside* an already-allowlisted function still fails the guard.

### Detection — Mutant observing where it is running

**Sandbox, VM, container and debugger detection is core Mutant infrastructure
and is not configuration.** Knowing whether the binary is running inside
Sandboxie, Cuckoo, VirtualBox, WSL, Windows Defender Application Guard, the
macOS App Sandbox, or under a debugger with a library injected is a product
capability. The variables it reads are set by that other software, never by a
Mutant user.

| Site | Reads |
| --- | --- |
| `security/sandbox_helpers.go` — `envSet` | the single choke point all sandbox env probing funnels through |
| `security/sandbox_windows.go` — `detectSandboxWindows` | `USERNAME`, `USERPROFILE`, and the Windows sandbox indicator set |
| `security/antidebug_linux.go` — `hasDebuggerEnvironmentMarkers` | `LD_PRELOAD` and Linux debugger markers |
| `security/antidebug_darwin.go` — `hasDebuggerEnvironmentMarkersDarwin` | `DYLD_INSERT_LIBRARIES` and macOS debugger markers |
| `security/antitamper_detectors.go` — `detectFridaPtrace` | Frida instrumentation markers |
| `security/antitamper_windows.go` — `findInjectionEnvMarkers` | Windows injection indicators |

> **Accepted property.** Because detection can halt a secure-mode run, someone
> who can set `SANDBOXIE=1` in Mutant's environment can make Mutant refuse to
> execute. This is inherent to environment-based sandbox detection, it fails
> closed rather than open, and it is accepted rather than treated as a defect.
> It is not a configuration channel: the only outcome it can produce is a
> refusal, and it cannot weaken any check.

### Evidence — Mutant reporting on a subject process

`builtin/system_forensics.go` — `ProcessEnv`, backing the `process_env` builtin.
It returns another process's environment, or its own, as forensic output. The
value is reported, never acted on. This is the product, not a setting.

### Toolchain — build-time `go build`

`generator/release_assets.go` — `buildReleaseRuntimeBinary`,
`cmd/wasmreplserve/main.go` — `ensureWasmBinary`, and
`builtin/fingerprint_builtins_test.go` — `TestImphashOnWindowsPE`. Each appends
`GOOS`/`GOARCH`/`CGO_ENABLED` to a child `go build`'s environment. Removing them
would break cross-target releases and the WASM REPL, and there is no flag
equivalent. `buildReleaseRuntimeBinary` also builds in the temporary directory,
as the scratch sites below do.

### Display — a value Mutant prints

`repl/repl.go` — `welcome`. The REPL greeting prints the account's display
name. Built without cgo on Linux, `os/user` answers for a uid that is not in
`/etc/passwd` from `USER` and `HOME`. That answer has no display name, so the
greeting names no one, and nothing else uses it. With either variable unset
that lookup fails and the REPL panics (M26-TOOL-031).

### Scratch — working files in the temporary directory

`builtin/sqlite_builtins.go` — `withSQLiteCopy`, the copy of a database an
`sqlite_*` builtin queries, so the evidence file is never opened for writing;
`cmd/sweep/main.go` — `resolveMutantBinary` and `newScratch`, the binary and the
copy of the examples the sweep runs. Each creates its files in the operating
system's temporary directory (`TMPDIR`; `TMP`, `TEMP` or `USERPROFILE` on
Windows) and deletes them when the work is done. Where they sit changes no
result.

### Regression tests — proving a variable is not obeyed

`security/key_bootstrap_test.go` — `TestTheKeystoreDoesNotFollowTheEnvironment`
points `HOME` and `USERPROFILE` at two directories in turn and requires the
keystore not to move. Setting a variable to show that nothing follows it is the
rule's own test, and the guard allows it only in a test file.

### What the environment can still change

Mutant reads no variable of its own, and the guard holds every read in its code
to the sites above. What remains is read on Mutant's behalf by the Go runtime,
the standard library and the libraries Mutant links. This is the complete list
for 2.6.0, from a survey on 2026-09-28 of every package linked into `mutant` and
`mlsp` for Windows, Linux and macOS, and the probes that followed it:

| Variables | What they change | Status |
| --- | --- | --- |
| `PATH` (with `PATHEXT` on Windows) | which program runs when Mutant starts one by name: `go` for `mutant release`, the shell `exec_string` and `cmd_run` start, the system tools the sandbox and debugger probes call, `clear` in the REPL | accepted: whoever sets `PATH` already chooses every program the session runs |
| every variable | is inherited by each child process, so the Go toolchain's own variables (`GOFLAGS`, `GOTOOLCHAIN`, `GOPROXY` and the rest) apply to the `go build` that `mutant release` runs | accepted: a child is configured the way that program is configured |
| `TMPDIR` (`TMP`, `TEMP`, `USERPROFILE` on Windows), `SQLITE_TMPDIR` | where working files and SQLite's temporary files go | accepted: see Scratch above |
| `TZ` | the zone local time is in: the offset with which `time_now` and the `fs_*` listings' modification times are printed, and a Rego policy's `"Local"` zone (Linux and macOS); and the zone SQLite's `localtime` modifier converts to (every system, on Windows only in the C library's own form, such as `UTC` or `EST5EDT`) | accepted where a time is printed with its offset, since the instant printed does not change; where it is not -- a Rego clock, SQLite's `localtime` -- open: M26-DAT-031 |
| `ZONEINFO` | the rules of a zone a Rego policy names in `time.format`, `time.date`, `time.clock`, `time.weekday`, `time.add_date` or `time.diff` | defect: M26-DAT-031 |
| `PWD` (Linux and macOS) | how an absolute path Mutant makes from a relative one is spelled, when the working directory was reached through a symbolic link | accepted: Go uses it only when it names the working directory |
| `GODEBUG`, `GOGC`, `GOMEMLIMIT`, `GOMAXPROCS`, `GOTRACEBACK` | the Go runtime's memory, scheduling and crash output, and standard-library defaults, among them TLS, X.509 and archive-path checks | accepted: every Go program reads them before its first line runs |

Three libraries are handed what they would otherwise look up. The `http_*`
builtins and `lua_run_http` send through a transport that names no proxy, so
`HTTP_PROXY`, `HTTPS_PROXY` and `NO_PROXY` go unread (M26-NET-010). On Linux,
`http_*` requests over TLS, `net_tls_connect` and `net_tls_upgrade_client` read
the system's certificate authorities from where Go reads them with
`SSL_CERT_FILE` and `SSL_CERT_DIR` unset, so neither variable decides whom they
trust (M26-NET-010). gopsutil is told that `/proc` is `/proc`, so `HOST_PROC`
and the other `HOST_*` variables no longer decide what the `process_*` builtins
read (M26-NET-025). A Rego policy is not offered the builtins that reach the
network: `http.send`, whose client took its proxy from the environment and its
timeout from `HTTP_SEND_TIMEOUT` (M26-DAT-030), and `json.match_schema` and
`json.verify_schema`, which fetch a schema's remote `$ref` through the same proxy
(M26-DAT-032). OPA still reads `HTTP_SEND_TIMEOUT` when it starts, for a builtin
no policy can call.

Everything else a linked library reads is on a path Mutant does not take, or
changes nothing it reports: Lua's `os.getenv` is removed before a script runs,
the evtx message resolver and the PE parser behind it are never called, gRPC,
protobuf, logrus, SQLite's memory auditor and OPA's WebAssembly compiler read
settings only for features Mutant does not use, and `net/http`'s
`DEBUG_HTTP2_GOROUTINES` turns on internal assertions and nothing else.

The home directory is not on the list. The keystore takes it from the account
database: the token's profile directory on Windows, the directory service on
macOS, `/etc/passwd` on Linux, read directly because `os/user` built without
cgo answers from `HOME` for an account that file does not list. Such an account
-- one only NSS or LDAP knows, or an unnamed container uid -- is refused, not
located through `HOME`.

## 4. What replaces configuration

**Command-line flags, and nothing else.**

A configuration file was considered and rejected. The knobs the removed
environment variables claimed to control no longer exist in the code — a
`mutant.toml` would have almost nothing to put in it, and would reintroduce the
same problem the environment had: behaviour that is not visible in the
invocation. Per-run decisions belong on the command line, where they are
recorded.

Preference order for anything new:

1. **A CLI flag** for a per-run decision.
2. **A file path passed by flag** for anything larger than a flag value — a key
   file, an allowlist, a ruleset. Never the content itself, and **never key
   material**: a path is safe to record in case notes, a private key is not.
3. **A fixed default** if neither fits. Most things belong here.

### Credentials are the exception to rule 1

A password is the one input that must **not** travel as a flag value, and the
policy above is what forces the shape of the alternative.

An environment variable would be the obvious answer and is ruled out here: it is
inherited by every child process, survives in the parent shell, and never
appears in the command line an analyst records. That it is also a configuration
read makes it doubly excluded, but it would be the wrong answer even if the
policy allowed it.

An argv flag is not much better. `--password <value>` is visible in `ps`, Task
Manager, and process-creation EDR telemetry for the whole life of the process,
and it lands in shell history. The command line being *recorded* is exactly the
property this document wants everywhere else, and exactly the property a
credential must not have.

So credentials use rule 1's structure with the value removed:

| Source                   | Shape                                          |
| ------------------------ | ---------------------------------------------- |
| Interactive prompt       | Nothing is recorded anywhere. The default.     |
| `--password-file <path>` | Rule 2: a **path** on argv, content on disk.   |
| `--password-stdin`       | A pipe. Nothing on argv, nothing on disk.      |

A bare `--password` (or `--pwd`) is refused since 2.6.0, as 2.5.0 announced.
`--password-insecure <value>` keeps the argv form for someone who accepts the
exposure and says so on the command line. See `credential/credential.go`.

The `--password-file` permission check is POSIX-only. On Windows the mode bits
`os.FileInfo` reports are synthesised from the read-only attribute rather than
read from the ACL that governs access, so enforcing `0600` there would pass for
a file granted to Everyone and fail for nothing. It is skipped rather than
faked.

### What is not configurable, and why

So a reader does not go looking for a switch that is not there:

| Behaviour | Actual value | Where |
| --- | --- | --- |
| Protection profile | fixed at `standard`; `minimal`/`paranoid` remain only so V3 release trailers can be read back | `security/profile.go` — `ResolveProtectionProfile` |
| Tamper response | derived from mode: `terminate` in secure mode, `warn` in `--compat`/`--dev` | `security/response_policy.go` — `ResolveTamperResponse` |
| Tamper delay | `250` ms constant, and no mode selects the `delay` response it belongs to, so no run waits on it | `security/response_policy.go` — `DefaultTamperDelayMs` |
| Process protection | always on; its five probes run on Windows only, so on Linux and macOS it measures nothing and the run says so on stderr | `runner/runner.go` — `isProcessProtectionEnabled` |
| Process-protection terminate threshold | confidence `80` | `runner/runner.go` — `processProtectionTerminateConfidence` |
| Anti-tamper probe | on by default; the setter exists for tests | `security/antitamper_probe.go` — `antiTamperProbeEnabled` |
| Remote process scan | off; reachable only from tests | `security/processscan_config.go` |
| Capability configuration | **none, and none is planned.** A builtin runs with this process's own permissions; declined 2026-10-10. | no gate exists; the decision is note 1 in [SECURITY_LLD_TRACEABILITY.md](SECURITY_LLD_TRACEABILITY.md) |

Mode selection (`--secure` / `--compat` / `--dev`), signer enforcement
(`--signer-auth` / `--no-signer-auth`), the trusted key file (`--trusted-key`),
security log level (`--security-log-level`) and stage timing (`--timing`) are
all flags. Run `mutant --help` for the current list.

## 5. The guard

`go test ./policy/...`, which runs as part of the ordinary `go test ./...`,
parses every `.go` file in the repository and fails on:

- any string literal that is a Mutant-prefixed variable name (rule 1, no
  allowlist consulted);
- any `Getenv` / `LookupEnv` / `Setenv` / `Unsetenv` / `ExpandEnv` / `Environ` /
  `EnvironWithContext` / `Clearenv` selector outside `policy.EnvAccessAllowlist`;
- a standard-library call that reads the environment inside itself, under
  whatever name the file imports its package by: `os.UserHomeDir`,
  `os.UserCacheDir`, `os.UserConfigDir` and `os.TempDir`; `os.MkdirTemp`,
  `os.CreateTemp`, `ioutil.TempDir` and `ioutil.TempFile` with an empty
  directory; `net/http`'s `DefaultClient`, `DefaultTransport` and
  `ProxyFromEnvironment`, its package-level `Get`, `Head`, `Post` and
  `PostForm`, and an `http.Client` made with no transport of its own, all of
  which send through the proxy the environment names; and, in a file that builds
  for Linux without cgo, `user.Current`, `user.Lookup`, `user.LookupId` and
  `x509.SystemCertPool`;
- a dot-import of `os`, `os/user` or `syscall`;
- an assignment to a `.Env` field, or a `Cmd` composite literal with an `Env:`
  key, outside the allowlist;
- an allowlist entry whose line budget no longer matches, and an allowlist entry
  that matches nothing at all.

It works on the AST rather than on text, which is why it has no false positives
against the ~73 `object.Environment` / `NewEnvironment` occurrences in
`evaluator/`, `vm/`, `repl/` and `webrepl/`. It parses build-tagged files
regardless of the host OS, which matters because most detection code lives
behind `//go:build windows|linux|darwin`.

**Failing the guard is not a defect.** It means either the access does not
belong there — use a flag — or the allowlist needs an entry and the commit needs
to say why.

### Known gaps

The guard is Go-only. The VS Code extension's `.mjs` build scripts are not
machine-checked by it, and since the project runs no CI, nothing checks them on
a schedule either. The extension's own build-target variable was removed in
favour of a `--target` argument, but nothing prevents a new one being added.

The guard sees only the calls it names. A library that reads the environment by
itself -- `net/http`'s proxy default inside another library, gopsutil's
`HOST_PROC` behind a call that names no directory, `crypto/x509`'s store behind
a TLS client that names no certificate authorities, OPA's zone names through
`ZONEINFO` -- is invisible to it, and so is a new dependency that does the same.
The list in [What the environment can still change](#what-the-environment-can-still-change)
is kept by hand (M26-TEST-013).

## 6. Limits

Every value that bounds what Mutant will do -- how much it reads into memory,
how deep it recurses, how long it waits, how many entries it keeps, how many
times it retries -- is a named constant in the package that enforces it,
explained where it is declared, and listed with its value in
[LIMITS_REFERENCE.md](LIMITS_REFERENCE.md), which `go run ./cmd/gendocs`
generates from the source.

A limit is not configuration. None is read from the environment or from a file;
the few a user may change are command-line flags, and the reference names the
flag beside the value.

A limit is declared like this:

```go
// maxArchiveEntries bounds how many members an archive may list before the
// reader stops, so a crafted index cannot exhaust memory.
//
//mutant:limit count
const maxArchiveEntries = 1 << 20
```

The directive names a unit (`bytes`, `kibibytes`, `bits`, `count`, `depth`,
`duration`, `milliseconds`, `microseconds`, `iterations`, `percent`, `ratio` or
`score`) and, when a flag overrides the value, `flag=--name`. A constant that
counts in kibibytes or in whole milliseconds says so, and the reference prints it
as the size or the time it is. The prose above it is required: a limit whose
reason is not written down is the hidden default this section exists to remove.
A value fixed by a file format or a protocol is not a limit; it is marked
`//mutant:format <specification>` and stays out of the reference. The reference
lists the limits of a run first, and after them those of the tools that build,
test and document Mutant, which bound no run.

`go test ./policy/` enforces it (`policy/limit_guard_test.go`, with the rules in
`policy/limitscan`). It fails on a limit written as a bare literal in a shape it
recognises:

| Rule | Shape |
| --- | --- |
| L1 | an allocation of 1024 or more (`make`) |
| L2 | an input/output cap: `Scanner.Buffer`, `LimitReader`, `CopyN`, `New*Size`, `MaxBytesReader` |
| L3 | a duration: `n * time.Second`, `time.Duration(n)` |
| L4 | a comparison with a depth, retry, budget or similar bound, or `len`/`cap` against 1024 or more |
| L5 | a retry loop, or a loop of 1000 or more iterations |
| L6 | a command-line flag default |
| L7 | a limit-named field or variable given a literal |
| L8 | a limit constant declared inside a function |
| L9 | a size passed as an argument: built with `<<` or `*` to 1024 or more, or 65536 or more |
| N1 | a constant named like a limit (`max…`, `…Timeout`, `…Size`) without a directive |

It also fails on a malformed directive. Hexadecimal, octal and binary literals in
a comparison, or given to a limit-named field, are left alone -- that is how this
tree writes format checks and layout tables, such as `len(data) < 0x40` and
`Size: 0x40`.

What was already in the tree when the guard arrived is held in a budget,
`policy/limit_budget.go`, seeded on 2026-09-24 at 174 findings in 82 files. It
lists each finding by its rule, the function it is in and the expression as
written, rather than keeping a count per file, so naming one limit cannot make
room for a new one beside it. It only shrinks: a finding it does not list fails,
and so does an entry no finding answers to, so an entry comes out in the same
change that names its limit.

The guard is a floor, not a proof. It recognises limits by shape and by name, so
a limit in a shape none of the rules describes is not caught. Binary-format
offsets are deliberately not guarded; their bounds are for fuzzing to test, and
the tree has no fuzz targets yet.

---

*This document is the one place in the repository where the prohibited name
prefix appears, because the rule cannot be stated without it. No specific
variable name appears anywhere in the documentation or in Go source.*
