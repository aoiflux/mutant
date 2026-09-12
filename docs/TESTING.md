# Testing Mutant programs

`mutant test` runs every `*_test.mut` file it finds. A test file is an ordinary
Mutant program — it is compiled and run the way any program is, so it can
`import` the module it is testing — and what it reports comes from a small
family of builtins.

```
mutant test                          # the current directory
mutant test examples/modules         # a directory
mutant test lib/stats_test.mut       # one file
mutant test --cover ./lib            # with line coverage
```

---

## A first test

```mutant
import "stats.mut";

test("sum adds the values", fn() {
    assert_eq(stats.sum([12, 47, 31]), 90);
});

test("mean of nothing is nothing rather than a division by zero", fn() {
    assert_eq(stats.mean([]), 0);
});
```

```
ok    lib/stats_test.mut  (2 tests, 3ms)

1 file | 2 tests  (3ms)
```

A failure names the line it was written on:

```
FAIL  lib/stats_test.mut  (2 tests, 3ms)
      --- FAIL  sum adds the values  (1ms)
          lib/stats_test.mut:4: assert_eq: got 89, want 90

1 file, 1 failed | 2 tests, 1 failed  (3ms)
```

---

## Writing tests

### `test(name, fn)`

Runs `fn` then and there. A test file reads top to bottom like the program it
is, and a `test` declared inside another is a **subtest** of it, reported as
`outer/inner`:

```mutant
test("largest", fn() {
    test("picks the biggest", fn() { assert_eq(stats.largest([1, 9, 3]), 9); });
    test("of a single value", fn() { assert_eq(stats.largest([7]), 7); });
});
```

A parent whose subtest failed has failed, even if it asserted nothing itself.

### The assertions

| Call | Passes when |
| --- | --- |
| `assert(condition, message?)` | `condition` is truthy |
| `assert_eq(got, want, message?)` | the two are equal |
| `assert_ne(got, unwanted, message?)` | the two differ |
| `assert_contains(container, value, message?)` | a substring of a string, an element of an array, or a key of a hash |
| `assert_err(value, substring?)` | `value` is an error, and mentions `substring` if one is given |
| `assert_ok(value, message?)` | `value` is not an error |
| `fail(message)` | never — for the branch a test should not reach |

Scalars compare by value. Arrays, hashes and structs compare by their rendered
form, so two hashes built in a different key order are equal. Strings are shown
quoted in a failure, because half of what a string assertion catches is
whitespace.

The optional trailing message is what the check was *for*, and it leads the
failure line: `counts match: assert_eq: got 3, want 4`.

### Errors

Mutant's failures are values, and [which binding receives one depends on the
builtin](MUTANT_LANGUAGE_REFERENCE.md). `assert_err` and `assert_ok` are how a
test says which it expected:

```mutant
test("a missing file is refused, not invented", fn() {
    let contents, err = fs_read("no/such/path");
    assert_err(err);
});

test("a real file reads", fn() {
    let contents, err = fs_read("testdata/sample.json");
    assert_ok(err);
    assert_contains(contents, "kind");
});
```

### Fixtures

`before_each(fn)` and `after_each(fn)` register a function to run around each
test **declared after them**, at that nesting level and inside it:

```mutant
let rows = [];

before_each(fn() { rows = [1, 2, 3]; });
after_each(fn() { rows = []; });

test("a test sees the rows the fixture laid out", fn() {
	assert_eq(len(rows), 3);
});
```

A fixture applies forwards only. Applying it to a test written above it would
mean setup running after the thing it was meant to prepare.

### A file with no tests

A file that declares no `test(...)` keeps the original contract: it passes
unless running it errored or its last expression was `false`. It is then
reported as one test named after the file.

---

## Options

| Flag | What it does |
| --- | --- |
| `--run PATTERN` | Run only matching tests. Split on `/`, one part per nesting level, the way `go test -run` reads. |
| `-v` | List every test, not only the ones that failed. |
| `--json` | Line-delimited JSON events, for CI. |
| `--fail-fast` | Stop calling tests once one has failed. |
| `--cover` | Report which source lines the tests reached. |
| `--coverprofile FILE` | Write the coverage as LCOV. Implies `--cover`. |
| `--module-path DIR` | Where to look for imported modules. Repeatable, searched in order. |

Nothing is read from an environment variable — see
[CONFIGURATION_POLICY.md](CONFIGURATION_POLICY.md).

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Every file passed. A run that selected no test also passes. |
| `1` | A test failed, or a file would not compile or run. |
| `2` | The command line was wrong. |

---

## Coverage

```
mutant test --cover ./lib
```

```
coverage: 88.2% of 17 lines
       88.2%    15/17  lib/stats.mut
              missing 24-25
```

What is counted is **a line that produced instructions**. Blank lines, comments
and closing braces are not in the denominator: a report that counted them would
be measuring the shape of the file rather than what the tests reached.

Test files are not counted. A test file is not the thing under test, and
including it would answer "did the tests run" — which the report above already
answers — while moving the number every time a test was added.

`--coverprofile` writes [LCOV](https://github.com/linux-test-project/lcov),
which `genhtml`, Codecov and the editor coverage plugins already read. Go's own
cover profile format was the other candidate and was not used: `go tool cover`
resolves paths as Go packages and would not find a `.mut` file. Every hit count
in the profile is `1` or `0` — the recording is "did this instruction run", not
a counter, because a counter on the instruction path would cost every run
something to serve a number nothing reports.

---

## How a test run differs from a normal run

**It is the same build.** Modules are linked, the security-check opcodes are
injected, and the positions are kept — a test that ran a privately-compiled
variant of the program would be testing something that does not ship.

**It is not secure mode.** A test run is a development activity on the machine
writing the code, so the tamper responses are advisory, as under `--dev`. This
is also what makes a dying test survivable: in secure mode nothing may be
caught, because an error reaching the runner could be the security policy
ending the run.

**The first file pays about 1.4 seconds.** That is the anti-sandbox probe, and
it is the same startup cost `mutant prog.mut` pays. The second file measures
0ms.

**On a VM or in a container you will see `[security] event=sandbox_detected
stage=vm-run action=warn`** on stderr, a few lines per file. Outside secure
mode the probe is advisory and says so, and it is the same line any `mutant`
run prints in the same place. The volume is set by where the compiler injected
the checks, not by how long the program runs: a twenty-thousand-iteration loop
still prints one. The report is on stdout, so `--json` and a piped run are
unaffected.

---

## What it deliberately does not do

**A failed assertion does not stop the test.** It is recorded, and the test
carries on. The language has no exceptions and this does not invent one: a test
that needs to stop early `return`s. Every assertion also *returns* its verdict,
so a failure is an ordinary value — `let ok = assert_eq(a, b);` sees it — and a
test file run as a plain program is not silently passing.

**A test that dies is caught, and only that test fails.** The file keeps going.
One division by zero does not cost every test written after it.

**Test files do not run in parallel.** The task registry behind `spawn` is
process-wide, so two files running at once would each wait for the other's
spawned work. Parallelism needs a per-VM registry first, which is a runtime
change rather than a test-runner one.

**There are no benchmarks, no mocking, and no way to assert on a crash.** A
benchmark needs a stable timing harness on a VM that re-derives an encryption
key per run; mocking needs a seam the language does not have; asserting on a
crash needs a catchable fault, which is a language decision.

---

## See also

- [MODULES.md](MODULES.md) — how imports resolve, which is what `--module-path` feeds.
- [DEBUGGING.md](DEBUGGING.md) — when a failing test is easier to watch than to read.
- [CAPABILITY_REFERENCE.md](CAPABILITY_REFERENCE.md#testing) — the generated reference for these builtins.
- `examples/modules/lib/stats_test.mut` — a worked example, tests and all.
