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
individually with a justification.

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

Every prohibited row above once existed and has been removed. Their names are
not reproduced here: a name in the documentation is exactly what leads someone
to try setting it, and none of them has done anything for some time.

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

Three categories. Every site is listed in `policy.EnvAccessAllowlist`
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
equivalent.

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

### What is not configurable, and why

So a reader does not go looking for a switch that is not there:

| Behaviour | Actual value | Where |
| --- | --- | --- |
| Protection profile | fixed at `standard`; `minimal`/`paranoid` remain only so V3 release trailers can be read back | `security/profile.go` — `ResolveProtectionProfile` |
| Tamper response | derived from mode: `terminate` in secure mode, `warn` in `--compat`/`--dev` | `security/response_policy.go` — `ResolveTamperResponse` |
| Tamper delay | `250` ms constant | `security/response_policy.go` — `DefaultTamperDelayMs` |
| Process protection | always on | `runner/runner.go` — `isProcessProtectionEnabled` |
| Process-protection terminate threshold | confidence `80` | `runner/runner.go` — `processProtectionTerminateConfidence` |
| Anti-tamper probe | on by default; the setter exists for tests | `security/antitamper_probe.go` — `antiTamperProbeEnabled` |
| Remote process scan | off; reachable only from tests | `security/processscan_config.go` |
| Capability configuration | **under design.** No interface is specified. | — |

Mode selection (`--secure` / `--compat` / `--dev`), signer enforcement
(`--signer-auth` / `--no-signer-auth`), the trusted key file (`--trusted-key`),
security log level (`--security-log-level`) and stage timing (`--timing`) are
all flags. Run `mutant --help` for the current list.

## 5. The guard

`go test ./policy/...`, which runs as part of the ordinary `go test ./...` in
CI, parses every `.go` file in the repository and fails on:

- any string literal that is a Mutant-prefixed variable name (rule 1, no
  allowlist consulted);
- any `Getenv` / `LookupEnv` / `Setenv` / `Unsetenv` / `ExpandEnv` / `Environ` /
  `Clearenv` selector outside `policy.EnvAccessAllowlist`;
- a dot-import of `os` or `syscall`;
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

### Known gap

The guard is Go-only. The VS Code extension's `.mjs` build scripts are not
machine-checked, and CI runs nothing for the extension today. The extension's
own build-target variable was removed in favour of a `--target` argument, but
nothing prevents a new one being added.

---

*This document is the one place in the repository where the prohibited name
prefix appears, because the rule cannot be stated without it. No specific
variable name appears anywhere in the documentation or in Go source.*
