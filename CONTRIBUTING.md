# Contributing to Mutant

Thanks for looking. This document covers what the project expects of a change,
the two constraints that are not negotiable, and the handful of house rules that
are unusual enough to be worth reading before you write code.

By participating you agree to the [Code of Conduct](CODE_OF_CONDUCT.md).
Security issues do **not** go through the normal issue tracker — see
[SECURITY.md](SECURITY.md).

## Before you write code

- **Small fixes** — typo, obvious bug, missing test — open a pull request
  directly.
- **Anything larger** — a new builtin family, a language feature, a change to
  the bytecode container, an LSP diagnostic — open an issue first. Scope and
  design are the maintainer's call, so saying what you intend before building
  it usually saves a rewrite.

## Getting set up

Go **1.26.2** or newer (the version in `go.mod` is what CI uses). Nothing else.

```bash
git clone https://github.com/aoiflux/mutant
cd mutant
go build ./...
go test ./...
go install            # puts `mutant` on your PATH
```

The language server is a separate module:

```bash
cd lsp && go build ./cmd/mlsp
```

Release packaging uses `scripts/build.sh` (Linux/macOS/WSL) or
`scripts/build.ps1` (Windows). Both are Go-only; no Rust or cgo toolchain is
needed any more.

## The two hard constraints

CI enforces both on every push. A change that breaks either will not be merged,
regardless of what it adds.

1. **Pure Go, no cgo.** The whole module must build and test under
   `CGO_ENABLED=0`. A dependency that pulls in cgo is a dependency the project
   cannot take, however convenient. This is what makes cross-compilation to a
   single static binary work at all.
2. **Cross-platform.** It must build for `linux/amd64`, `linux/arm64`,
   `windows/amd64`, `windows/arm64`, `darwin/amd64` and `darwin/arm64`.
   Platform-specific code goes behind a build tag **with a fallback**, never as
   the only implementation.

Check both locally before you push:

```bash
CGO_ENABLED=0 go build ./... && CGO_ENABLED=0 go test ./...
for t in linux/amd64 linux/arm64 windows/amd64 windows/arm64 darwin/amd64 darwin/arm64; do
  GOOS="${t%/*}" GOARCH="${t#*/}" CGO_ENABLED=0 go build ./... || echo "FAILED $t"
done
```

## Configuration: no environment variables

**Mutant takes no configuration from the environment.** Using it must never
require anyone to set, or think about, a variable. For a forensic tool this is
not a style preference: the environment is part of the untrusted thing under
examination, and an environment switch is an unlogged control channel that does
not appear in the command line an analyst records. A run must be reproducible
from its invocation.

When you need a new knob, the preference order is:

1. a **CLI flag**, for a per-run decision;
2. a **file path passed by flag** for anything larger than a flag value — a key,
   an allowlist, a ruleset. The path, never the content, and **never key
   material**;
3. a **fixed default**. Most things belong here.

Credentials are the exception that proves the rule: a password must not be
recorded, so it travels by interactive prompt, `--password-file <path>` or
`--password-stdin` — never as a flag value.

Reading a foreign environment variable is permitted where the value is
**observed, never obeyed** — sandbox and VM detection, debugger indicators, the
`process_env` forensic builtin. The test is whether a *user* would set the
variable to change what Mutant does. Each such site is individually allowlisted.

This is machine-enforced. `go test ./policy/...` parses every `.go` file in the
repository and fails on a `MUTANT_`-prefixed string literal anywhere, on an
environment read outside the allowlisted functions (each with a pinned line
budget, so a new read inside an already-allowlisted function still fails), and
on an environment write outside a build-time child `go build`. It runs as part
of the ordinary `go test ./...`.

The full rule, the carve-outs, and what is deliberately not configurable are in
[docs/CONFIGURATION_POLICY.md](docs/CONFIGURATION_POLICY.md).

## House rules for particular areas

### Adding or changing a builtin

A builtin is not done when it runs. Register the name in `builtin/names.go` and
the implementation in `builtin/builtin.go`, then declare its contract in
`builtin/metadata.go`: parameter kinds, arity, return shape, and a stability
tier if it is not the default `stable`. Regenerate the catalogue:

```bash
go run ./cmd/gendocs          # rewrites docs/CAPABILITY_REFERENCE.md
go run ./cmd/gendocs -check   # what CI's test asserts
```

`docs/CAPABILITY_REFERENCE.md` is **generated**. Never hand-edit it.

Conformance probes in `builtin/` call every builtin with deliberately wrong
arguments and assert that the metadata matches what the implementation actually
does. If a probe fails on a builtin you did not touch, the metadata was wrong
before you arrived — fix the declaration, don't weaken the probe.

The language server derives hover, completion, signature help and the
`builtinArgType` diagnostic from this metadata. Declaring it accurately is what
makes the editor correct; there is usually nothing to add on the LSP side.

### Changing the language

There are **two engines**: the compiler/VM (`compiler/`, `vm/`) and the
tree-walking evaluator (`evaluator/`), which runs the REPL and macro expansion.
A new operator, operand type or piece of semantics must land in **both**, and
`parity/` compares them on a shared corpus. A feature implemented in one engine
only is an incomplete change, not a follow-up.

Bytecode format changes touch three separate gob registration lists —
`runner/runner.go`, `generator/generate.go` and `compiler/linetable_test.go`.
Missing one means an artifact that fails to round-trip.

### Debug information

Debug facilities — line tables, parameter names, source text — go into
`ByteCode`/`CompiledFunction` **unconditionally**, and get cleared in
`StripDebugInfo()`. Do not gate them behind a flag, a mutation level, or
`--dev`: that couples debuggability to a security downgrade. `mutant release` is
the only place stripping happens. Anything that exposes runtime values must key
its gate on the debug info having survived.

### Documentation

Docs under `docs/` are treated as part of the code. A change that alters
documented behaviour and does not update the document is incomplete — and if a
document describes behaviour the code no longer has, re-derive it rather than
deleting the section.

## Style and tests

- **Go:** `gofmt`. Nothing exotic; the standard tool, standard settings.
- **Mutant source:** `mutant fmt` (`--check` to verify without writing).
- **Comments** explain *why*, not what. The codebase's convention is that a
  comment earns its place by recording a decision, a constraint, or a trap —
  not by narrating the line below it.
- **Tests** live beside the code as `*_test.go`. A bug fix comes with a test
  that fails without it. `mutant test` runs `*_test.mut` files for
  language-level tests.

The full suite must pass:

```bash
go test ./...
cd lsp && go test ./...
```

> **Windows note:** the repository has no `.gitattributes`, so a checkout with
> `core.autocrlf=true` rewrites line endings and makes `gofmt -l ./...` report
> every file. Format the files you touched rather than trusting a repo-wide
> listing, or set `core.autocrlf=input`.

## Pull requests

- Branch from `dev`. `main` tracks releases.
- One logical change per PR. A refactor bundled with a feature is two PRs.
- **Commit messages carry the reasoning.** The subject line is imperative and
  under ~70 characters; the body says what was wrong, what the change does, and
  which alternatives were rejected and why. Read `git log` for the register the
  project uses — this is a real expectation here, not boilerplate.
- CI must be green on Linux, Windows and macOS, plus the cross-compile matrix
  and `go mod verify`.
- Say in the PR description how you tested it. "Tests pass" is not a test plan
  for a parser or a security path.

## Compatibility and stability

**Artifacts.** The bytecode container is versioned (`ByteCode.Version`). A newer
runtime runs older artifacts: the v2.4.0 builtin registry is frozen in
`builtin/legacy_ordinals.go` precisely so pre-v2.5 artifacts keep resolving.
The reverse is not supported and fails loudly by design — an old runtime handed
a new artifact trips a bounds check rather than silently calling the wrong
builtin. Any change to the container needs a version bump and a round-trip test
against an artifact built by the previous release.

**Builtins.** Names are resolved by name, not by registry position, so the
registry is no longer append-only — builtins can be renamed, reordered or
retired. What cannot happen is a silent change: a builtin whose contract is
withdrawn is marked `deprecated` in its metadata, names its replacement, keeps
working, and surfaces as an editor hint. Removal comes in a later major version,
never in a patch. Additions are the normal case and are not breaking.

**The language.** Syntax and semantics are stable within a major version.
Something still moving is marked `experimental` and says so in its documentation.

**The CLI.** Flags are stable within a major version. A flag being retired warns
for at least one minor release first.

## Releases and governance

Releases are cut from `main` and tagged `vMAJOR.MINOR.PATCH`, roughly every
four to eight weeks — cadence follows what is ready, not the calendar, and there
is no fixed release date. Each release updates [CHANGELOG.md](CHANGELOG.md),
which is the canonical record; longer narrative notes live in `plans/`.

Mutant is maintained by [@aoiflux](https://github.com/aoiflux) (Gaurav Gogia),
who has final say on scope, design and merges. There is no formal committee.
Design decisions that shape the project are written down in `docs/` rather than
left in review threads, so a contributor can read the reasoning without having
been present for it.

The project is licensed **AGPL-3.0** ([LICENSE](LICENSE)); contributions are
accepted under the same terms. There is no CLA.

**One area is currently closed to contributions:** capability configuration —
how a Mutant program's access to the host is declared or restricted — is under
design, and no interface is specified. Please don't open a PR proposing a
mechanism for it; it will be closed regardless of quality. Observations and use
cases in an issue are welcome.
