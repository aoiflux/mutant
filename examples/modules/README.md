# Modules Example

One program built from three files: `main.mut` imports `lib/report.mut`, which
imports `lib/stats.mut`.

Run from repository root (compile, then run the bytecode it writes beside the
source):

```bash
mutant gen --src examples/modules/main.mut --dev
mutant examples/modules/main.mu --dev
```

It prints:

```
main.mut
report.mut
LATENCIES: sum=190 mean=38 max=92
largest alone: 92
```

The first two lines are the point: `main.mut` and `lib/report.mut` each declare
`label`, and each file's own declaration is the one it sees.

What the files show:

- `main.mut` — an import with a derived namespace (`report`) and one with an
  alias (`numbers`), and a name that collides with the imported module's.
- `lib/report.mut` — a module importing another module, resolved relative to
  its own directory, plus a builtin namespace (`str.format`).
- `lib/stats.mut` — `_total`, a top-level name beginning with `_`, which is
  private to that file and usable only inside it.
- `lib/stats_test.mut` and `lib/report_test.mut` — tests for the two modules,
  which is the other thing an import is for.

The library files also run on their own, because a module is an ordinary `.mut`
file. They just declare things and finish.

## Tests

```bash
mutant test --cover examples/modules
```

```
ok    lib/report_test.mut  (3 tests, 2ms)
ok    lib/stats_test.mut  (9 tests, 2ms)

2 files | 12 tests  (2ms)

coverage: 100.0% of 21 lines
      100.0%      4/4  lib/report.mut
      100.0%    17/17  lib/stats.mut
```

A test file is an ordinary program, compiled the same way, so it imports what
it tests exactly as `main.mut` does. `report_test.mut` imports `report.mut`,
which brings `stats.mut` with it — the whole chain is compiled once, the same
way running `main.mut` compiles it. See
[docs/TESTING.md](../../docs/TESTING.md).

See [docs/MODULES.md](../../docs/MODULES.md) for the rules.

Scripts:
- main.mut
- lib/report.mut
- lib/stats.mut
