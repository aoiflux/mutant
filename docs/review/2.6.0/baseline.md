# Stage A baseline

This is what the tree did at `07c737a`, before the 2.6.0 review changed anything,
and what the release gate says once Stage A's harness fixes are in. Every later
report measures against these numbers. The ids are rows in
[`findings.jsonl`](findings.jsonl); [the README](README.md) defines the fields.

## Where it was measured

| | |
| --- | --- |
| Commit | `07c737a` on `dev`. The benchmark comparison uses `v2.5.0` (`0dc5cb8`) |
| Toolchain | go1.26.2, the version `go.mod` pins, installed beside 1.27 |
| Windows | Windows 11 Pro 10.0.26200, AMD Ryzen 9 5980HS (16 logical CPUs). gcc is on PATH, so the race detector runs |
| Linux | WSL 2, Ubuntu 24.04, kernel 6.18.33.2-microsoft-standard-WSL2, LF checkout. There is no gcc, so no race detector |
| Method | A clone at the commit on each host, never the working tree. The Windows clone carried the working copy's CRLF bytes. Nothing was written into the repository |

The two hosts ran at the same time on one machine, so durations were measured
under contention, and ns/op figures are indicative only.

## The release gate at 07c737a

The gate is [`scripts/release_gate.ps1`](../../../scripts/release_gate.ps1) on
Windows and [`scripts/release_gate.sh`](../../../scripts/release_gate.sh)
elsewhere. There is no CI; these are local runs.

| Step | Windows | Linux |
| --- | --- | --- |
| toolchain is the pinned one | PASS | PASS |
| gofmt (on LF copies) | **FAIL**: 26 files (M26-TEST-001) | **FAIL**: 25 files; the gate's CR stripping hides the 26th |
| go vet (linux, windows, darwin) | PASS | PASS |
| cross-compile (6 targets × mutant and mlsp, plus wasm) | PASS, 301 s | PASS, 405 s |
| go test ./... | PASS: 34 ok, 10 without tests, 124 s | **FAIL**: cli, parity, sweep (M26-TEST-002, M26-TEST-003) |
| race detector | PASS: 14 packages, no race, 250 s | SKIP: no gcc (M26-TEST-004) |
| fuzz targets | SKIP: no `-FuzzTime`, and there are no fuzz targets yet | SKIP |
| generated docs are current | PASS: 659 builtins, 41 categories | PASS |
| example sweep, golden output, levels 0, 5, 10 | **FAIL**: 3 of 124, 1025 s | **FAIL**: 25 of 124 every run, 2 more on some runs, 349 s |
| go mod verify / tidy | PASS | PASS |
| CHANGELOG date matches the tag | PASS: v2.5.0 and its heading are both 2026-09-17 | PASS |
| govulncheck (`-Vuln`) | **FAIL** (M26-RUN-003, embargoed) | not run |

Every failure was reproduced by a second run. The Windows gate took 31 minutes
and the Linux gate 19.

### Why each failure happened

- **gofmt.** 25 files had real formatting drift in their committed content. The
  26th, `lexer/lexer.go`, ended 119 lines in CR CR LF, which is why git stored it
  as binary.
- **go test on Linux.** Two tests assumed a Windows host: a scratch path rewritten
  with `filepath.ToSlash`, and a drive root. Ten parity subtests ran generated
  bytecode in secure mode, and WSL is a sandbox by the detector's rules.
- **Sweep on Windows.**
  - `worker_pool` prints a runtime error that names the instruction pointer, which
    changes with the mutation level (M26-VM-002).
  - `network_forensics_example` recorded a live certificate and a timing value.
  - `security_quickcheck` prints a microsecond timer, and the sweep read a chance
    agreement as reproducible output (M26-TOOL-008).
- **Sweep on Linux.** Of the 23 golden mismatches, 20 came from how the goldens
  were recorded on Windows: Windows error text, backslashes in source positions,
  and the CRLF bytes of three evidence fixtures (M26-TOOL-007, M26-EX-006). Two
  recorded this machine's sandbox and debugger verdicts (M26-EX-005), one recorded
  a timing value, and one recorded live DNS answers. The Linux run also exposed
  the parent-debugger false positive (M26-TMP-002).

## What Stage A changed, and the gate after it

- **gofmt.** The 26 files were reformatted, each keeping its own line endings.
  The release-assets generator now formats what it writes, so a regenerated index
  stays clean (M26-TEST-001).
- **Goldens.** A golden now reads the same on every host. Normalization rewrites
  only what differs by host and not by program: source-position separators and
  three Windows error texts (M26-TOOL-007). The evidence fixtures in
  `examples/data` are marked `-text` in [`.gitattributes`](../../../.gitattributes),
  so every checkout writes the committed bytes (M26-EX-006).
- **Marked examples.** 33 examples need an image, the network, a passphrase, or
  the host they report on. They are marked `needs-input`: compiled, not run, and
  counted separately (M26-EX-005).
- **Sweep comparisons.** A difference between two levels now counts only if it
  repeats when both levels are run again (M26-TOOL-008).
- **Linux test failures.** The tests that failed on Linux are portable
  (M26-TEST-002, M26-TEST-003).

The quick gate (`-Quick`) on Windows after the gofmt fix passed every step it
runs:

- toolchain;
- gofmt;
- vet on linux, windows and darwin;
- go test (110 s);
- gendocs;
- mod verify and tidy;
- CHANGELOG date.

The full gate after Stage A was run with `-Vuln` on Windows, over the working
copy. On Linux it ran over a clone at `07c737a`, with the same changes laid over
it in their LF form:

| Step | Windows | Linux |
| --- | --- | --- |
| toolchain is the pinned one | PASS | PASS |
| gofmt (on LF copies) | PASS | PASS |
| go vet (linux, windows, darwin) | PASS | PASS |
| cross-compile (6 targets × mutant and mlsp, plus wasm) | PASS, 144 s | PASS, 435 s |
| go test ./... | PASS: 35 ok, 10 without tests, 122 s | PASS, 119 s |
| race detector | PASS: 14 packages, no race, 208 s | SKIP: no gcc (M26-TEST-004) |
| fuzz targets | SKIP: no `-FuzzTime` | SKIP |
| generated docs are current | PASS | PASS |
| example sweep, golden output, levels 0, 5, 10 | **FAIL**: `worker_pool` only (M26-VM-002), 698 s | **FAIL**: `worker_pool` only, 260 s |
| go mod verify / tidy | PASS | PASS |
| CHANGELOG date matches the tag | PASS | PASS |
| govulncheck (`-Vuln`) | **FAIL**: unchanged (M26-RUN-003, embargoed) | not run |

Neither remaining failure comes from the harness. `worker_pool` needs a change in
the runtime (M26-VM-002). The govulncheck failure is M26-RUN-003. The Windows
gate took 22 minutes and the Linux gate 16. The two ran at the same time.

### Re-runs in Stage B

The Windows sweep above was not the binary a release ships. The sweep built
its own `mutant` with the first `go` on the PATH, which on this host is
go1.27.0, and cgo was on because gcc is on the PATH. The gendocs check,
govulncheck and the fuzz-target listing also took the host's cgo default
(M26-TEST-006). The gate now builds the sweep binary itself, with the pinned
toolchain and `CGO_ENABLED=0`, and sets cgo on every command. Re-run on
2026-09-25 that way, the Windows sweep reads as before: **74 of 124 examples
with verified output**, and `worker_pool` is the only failure.

The same re-run showed that the gate must not keep its logs inside the
repository. The gofmt step writes an LF copy of every Go file under the log
directory. `go test ./...`, vet, the limits scan and gendocs then read those
copies as part of the module and failed (M26-TEST-008). The gate now refuses
such a directory. Every step that did not read the copies stood:

- the race detector passed on 14 packages with no race;
- the cross-compiles passed;
- module verification and the CHANGELOG date passed;
- govulncheck failed as before (M26-RUN-003);
- the sweep gave the result above.

A `-Quick` gate with its logs outside the tree then passed toolchain, gofmt,
vet ×3, `go test ./...`, the generated docs, module verification and the
CHANGELOG date.

On Linux, WSL now has gcc and the C headers, so the race detector runs there
too. Its first run over `7aeee5a`, with the cgo fix laid over it, reported no
data race. It failed one timing test, `TestPMapActuallyOverlapsWork`, which
timed its own start-up against a budget meant only for the overlapped work
(M26-TEST-007, fixed). That run's sweep gave 73 of 124: `worker_pool` failed as
on Windows, and `static_bin_analysis` ran past the 60-second limit because nine
audit agents shared the host. On the idle host it takes about 27 seconds
(M26-VM-001).

## Tests and the race detector

At `07c737a`, `go test ./...` passed on Windows: 34 packages ok, 10 without test
files, `builtin` alone taking about 100 s. On Linux 31 were ok and 3 failed, as
described above.

The race step covers these packages and everything under them: vm, builtin,
serve, security, object, runtime, repl, dap, sema, lsp and cli. On Windows all
14 of them that have tests passed with no race reported. On Linux it did not
run in Stage A, because WSL had no gcc. It has run since, with no race reported
(see [Re-runs in Stage B](#re-runs-in-stage-b)).

## Example sweep

There are 124 example programs:

| Kind | Count | What the sweep checks |
| --- | ---: | --- |
| server | 5 | Started, still alive after a moment, then stopped |
| serve-handler | 2 | Compiled only; they need a connection to handle |
| needs-input | 33 | Compiled only; counted apart from the checked examples |
| run | 84 | Run at levels 0, 5 and 10. Output that reproduces is compared across levels, and against a golden where one exists |

Of the 84 run examples, 75 have a golden file. The other nine print something
that changes between runs:

- a generated key, nonce or certificate;
- a file's modification time;
- a timer;
- the host's process table;
- a function's heap address (M26-EVL-002).

Two known problems remain in the run set:

- `worker_pool` still fails the cross-level comparison (M26-VM-002). It stays
  failing until the runtime error stops printing the instruction pointer.
- `static_bin_analysis` needs close to the sweep's 60-second budget, because a
  variable read costs time in proportion to the variable's size (M26-VM-001).

After Stage A, both hosts produce the same sweep. **74 of 124 examples run with
verified output**: they print the same thing at levels 0, 5 and 10, and it
matches their golden. Of the rest:

- 33 are needs-input;
- 7 are servers or handlers;
- 9 vary between runs;
- 1 fails: `worker_pool`.

At `07c737a` the same sweep failed 3 examples on Windows and 25 on Linux.

## Coverage

Statement coverage at `07c737a`, Windows, `CGO_ENABLED=0`. **unit** counts a
package's own tests. **cross** is `-coverpkg=./...`, which also credits every
other package's tests. LOC counts `git ls-files`.

| Package | LOC | Test LOC | Unit | Cross |
| --- | ---: | ---: | ---: | ---: |
| . (mutant) | 2889 | 2366 | 73.7% | 73.7% |
| ast | 1876 | 809 | 62.3% | 84.3% |
| builtin | 65322 | 41653 | 76.1% | 76.5% |
| cli | 2207 | 1430 | 76.6% | 78.5% |
| cmd/covreport | 204 | 0 | 0.0% | 0.0% |
| cmd/gendocs | 891 | 1949 | 62.9% | 62.9% |
| cmd/sweep | 807 | 0 | 0.0% | 0.0% |
| cmd/wasmreplserve | 210 | 0 | 0.0% | 0.0% |
| code | 722 | 615 | 80.6% | 86.5% |
| compiler | 3493 | 4976 | 81.1% | 92.2% |
| credential | 326 | 369 | 80.4% | 81.4% |
| dap | 1210 | 845 | 78.8% | 78.8% |
| errrs | 174 | 99 | 80.4% | 80.4% |
| evaluator | 2133 | 2329 | 69.2% | 81.8% |
| generator | 622 | 463 | 35.3% | 38.2% |
| lexer | 888 | 1055 | 93.1% | 97.5% |
| lsp/api | 163 | 56 | 39.4% | 78.8% |
| lsp/internal/analyzer | 13699 | 7754 | 75.0% | 81.9% |
| lsp/internal/server | 3417 | 9585 | 81.2% | 81.3% |
| lsp/internal/workspace | 568 | 479 | 56.4% | 83.4% |
| module | 644 | 641 | 82.6% | 87.7% |
| mutil | 601 | 427 | 71.7% | 87.3% |
| object | 1886 | 694 | 42.3% | 74.2% |
| parser | 2064 | 2778 | 81.5% | 82.4% |
| policy/limitscan | 1212 | 0 | 0.0% | 88.1% |
| repl | 1147 | 152 | 19.5% | 19.5% |
| runner | 567 | 775 | 72.2% | 81.3% |
| runtime/lua | 631 | 288 | 52.2% | 53.0% |
| security | 7935 | 3715 | 66.0% | 74.4% |
| sema | 3788 | 2661 | 79.1% | 87.8% |
| serve | 145 | 216 | 71.4% | 71.4% |
| sweep | 383 | 446 | 91.3% | 91.3% |
| testkit | 129 | 40 | 85.7% | 85.7% |
| vm | 6123 | 7321 | 80.6% | 84.5% |
| webrepl | 396 | 746 | 88.4% | 88.4% |
| **all** | 130774 | 104000 | **72.7%** | **77.1%** |

Other packages:

- **No statements:** `global`, `parity` (tests only) and `policy`, whose non-test files hold no statements.
- **Under 30 statements:** `cmd/replwasm`, `lsp/cmd/mlsp`, `lsp/internal/protocol`, `releaseassets`, `serialize` and `token`.
- **Not compiled here:** the two `//go:build ignore` helpers under `examples/`.

The weakest areas relative to their weight:

| Package | Unit | Note |
| --- | ---: | --- |
| `repl` | 19.5% | |
| `generator` | 35% | |
| `object` | 42% | Other packages' tests lift it to 74% |
| `runtime/lua` | 52% | |
| `security` | 66% | |
| `cmd/sweep` | 0% | No tests at `07c737a`. Stage A added its first, for M26-TOOL-008 |

Coverage is a measurement here, not a threshold.

## Benchmarks against v2.5.0

Six interleaved rounds per tree, `-benchmem`, compared with benchstat.
Differences are marked only where p < 0.05.

| Benchmark | v2.5.0 | 07c737a | Change |
| --- | ---: | ---: | --- |
| vm MapVsPMap/map, B/op | 1.390 GiB | 1.516 GiB | +9.0% |
| vm MapVsPMap/map, allocs/op | 36.68 M | 38.99 M | +6.3% |
| vm MapVsPMap/pmap, B/op | 1.425 GiB | 1.548 GiB | +8.6% |
| vm GlobalMemoryModeRuntime_IntegerSetGet, B/op | 304 | 320 | +5.3% |
| vm GlobalMemoryModeRuntime_ArraySetGet, B/op | 424 | 440 | +3.8% |
| vm GlobalMemoryModeWrapper_ArraySetGet, B/op | 440 | 456 | +3.6% |
| lsp workspace SymbolIndexUpdateLargeDocumentIndexOnly, sec/op | 905 µs | 840 µs | −7.2% |
| lsp workspace SymbolIndexUpdateLargeDocumentIndexOnly, B/op | 1104 KiB | 904 KiB | −18.1% |
| lsp workspace SymbolIndexUpdateLargeDocument, B/op | 4.683 MiB | 4.487 MiB | −4.2% |

No sec/op regression is significant.

The VM's extra 16 bytes per stored value match the `Classified` field that 2.6
added to encrypted values: a 48-byte object moves into the 64-byte size class.
That is an inference, not yet verified. It is a Stage B performance lead.

30 benchmarks exist only on `07c737a`, including the `sema` package and the
`db_*` builtins. They start their own baseline here.

## Static analysis

All three tools ran under go1.26.2 through `go run pkg@version`, so `go.mod` was
not touched. These are leads for Stage B, not findings until verified.

- **deadcode** (x/tools v0.50.0) finds 63 unreachable functions, 7 of them in test files:
  - `security` 22;
  - `parser` 7, the whole tracer;
  - `object` 6;
  - `builtin` 5;
  - 13 other packages.

  On each OS, that OS's `isDebuggerPresent*` wrapper is unreachable. Detection
  runs through the `detectDebuggerDetails*` functions instead, so this is debt,
  not a missing check.
- **staticcheck** (v0.8.1) reports 63 findings:
  - U1000 (unused) 42;
  - ST1008 7;
  - SA1019 (deprecated APIs: md4, opa v0, `syscall.StringToUTF16Ptr`, `go/parser.ParseDir`) 6;
  - SA4006 3;
  - ST1005 3;
  - SA4016 1;
  - ST1018 1.

  Run for linux and darwin, it adds SA4023: nil-interface comparisons that are
  always true, in `builtin/registry_forensics.go:117` and, on darwin,
  `builtin/system_forensics.go:174` and `:236`.
- **govulncheck** fails. The finding is M26-RUN-003, which stays embargoed until
  it is fixed.

## Limits budget

The limits guard exempts **174 unnamed limits in 82 files**. Each is a numeric
limit written inline instead of as a named, documented constant. The per-file
budget in [`policy/limit_budget.go`](../../../policy/limit_budget.go) may only
shrink. [`docs/LIMITS_REFERENCE.md`](../../LIMITS_REFERENCE.md) lists what is
already named. Stage F takes the budget to zero.

## Findings Stage A added

**Fixed in Stage A:**

- M26-EX-003
- M26-EX-005
- M26-EX-006
- M26-TEST-001
- M26-TEST-002
- M26-TEST-003
- M26-TOOL-007
- M26-TOOL-008

**Open:**

- M26-BLT-002
- M26-EVL-002
- M26-EX-001
- M26-EX-002
- M26-EX-004
- M26-RUN-003
- M26-TEST-004
- M26-TEST-005
- M26-TMP-002
- M26-VM-001
- M26-VM-002
