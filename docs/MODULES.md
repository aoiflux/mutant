# Modules

A Mutant program can be more than one file. `import` loads another `.mut` file,
binds it to a namespace, and links it into the same program.

```mutant
import "lib/stats.mut";

putf("%d\n", stats.mean([12, 47, 31]));
```

There is no manifest, no lockfile, no config file and no environment variable.
A program is the entry file plus everything it imports, and the only thing that
can widen the search is a flag you typed on the command line.

## Writing an import

```mutant
import "lib/stats.mut";          // binds the namespace `stats`
import numbers "lib/stats.mut";  // binds the namespace `numbers`
```

The path is a string literal and must include the `.mut` extension — the
extension is not guessed, so the line says exactly which file it opens.

Without an alias the namespace is the file's base name with `.mut` removed:
`lib/net/tls_pool.mut` binds `tls_pool`. Give an alias when that is not the
name you want at the call site, or when two imports would otherwise bind the
same namespace.

`import` is a top-level statement. Inside a function body or any other block it
is an error:

```
import is only allowed at the top level of a file, not inside a block
```

That is not a restriction, it is a description: modules are resolved and linked
before the program runs, so an import inside a body could not mean "load this
when control reaches here".

## What an import does and does not bring in

An import binds **one name**: the namespace. It is not a textual include.

```mutant
import "lib/stats.mut";

stats.mean(values);   // works
mean(values);         // undefined variable: mean
```

Each module has its own top level. Two modules may both declare `label`, or
`helper`, or `main`, and they are two different bindings — the one you write in
a file is always that file's own.

```mutant
// lib/report.mut
let label = "report";

// main.mut
import "lib/report.mut";
let label = "main";

putln(label);         // main
putln(report.label);  // report
```

Builtins are the exception, and deliberately: every module sees the whole
standard library with no import. A module that declares its own `len` shadows
the builtin inside that module only.

## Private names

A top-level name beginning with `_` is private to the file that declares it.

```mutant
// lib/stats.mut
let _total = fn(values) { /* ... */ };   // private
let mean = fn(values) { /* ... */ };     // reachable as stats.mean
```

Reaching for one from another module is a compile error that names both:

```
stats._total is private to lib/stats.mut: a top-level name beginning with _ is
visible only inside the module that declares it
```

The underscore is the whole rule. There is no export list to keep in step with
the code, and the mark travels with every mention of the name instead of living
in one place far away from it. Inside its own module a private name is an
ordinary name.

## Where a path is looked up

In order:

1. The directory of the **importing file**. `lib/report.mut` writing
   `import "stats.mut";` finds `lib/stats.mut`, not `stats.mut` beside whatever
   file imported `report.mut`. A module's imports mean the same thing wherever
   the module is used from.
2. Each `--module-path <dir>` directory, in the order the flags were given.

An absolute path skips both and is used as written.

```bash
mutant gen --src main.mut --module-path ./vendor --module-path ~/mutant/lib
```

The flag repeats rather than taking a separator-joined list, so the search
order is exactly what is on the command line and no path needs escaping.

There is no other source of search paths — see
[CONFIGURATION_POLICY.md](CONFIGURATION_POLICY.md). If an import does not
resolve, the error lists every directory that was tried:

```
main.mut: cannot find module "util.mut"
  searched:
    O:\project\app\util.mut
    O:\project\app\vendor\util.mut
  add a directory to the search with --module-path <dir>
```

## Cycles

A cycle is reported as the chain that closed it, not as the one file that
repeated:

```
import cycle: main.mut -> a.mut -> b.mut -> a.mut
```

A diamond is not a cycle: a file imported by two others is loaded, compiled and
executed exactly once, and both importers see the same bindings.

## Types are program-wide

`struct` and `enum` names are **not** namespaced. One declaration is visible
everywhere, with no qualification:

```mutant
// lib/shapes.mut
struct Point { x, y }

// main.mut
import "lib/shapes.mut";
let p = Point{x: 1, y: 2};   // no `shapes.` needed
```

This is how type names travel in the bytecode — keyed by bare name, resolved by
the VM at runtime — so two modules cannot each declare a `Point`. That is a
compile error naming both files rather than one module silently getting the
other's fields:

```
struct Point is declared in both lib/a.mut and lib/b.mut: struct and enum names
are shared across the whole program, so one of them has to be renamed
```

So: values are per-module, types are per-program.

## Builtin namespaces

The standard library's flat names are also addressable with a dot. `fs.read` is
`fs_read`, `str.upper` is `str_upper`, `base64url.encode` is
`base64url_encode`:

```mutant
let data, err = fs.read("notes.txt");
let shout = str.upper("hello");
```

Nothing is imported and nothing is declared — the flat name is derived by
joining the two halves with `_`, so every family works and both spellings are
one function with one contract, one arity check and one set of diagnostics.

Precedence, in order: an enum type name, then an import namespace, then any
variable, parameter or field in scope, and only then a builtin family. A
program that already has a struct in a variable called `str` keeps meaning what
it meant.

## Execution order

Modules run in dependency order — a module's top-level statements have all run
before any file that imports it runs its own. The entry file is last.

One consequence worth knowing: macros are shared program-wide and filled in the
same order, so a macro a module defines is usable by everything that imports it.

## Tracebacks

Modules are linked into one instruction stream, one constant pool and one global
slot space, because the bytecode format leaves no choice — the polymorphic
engine shuffles the whole constant pool, the opcode permutation ships as one
table for the entire program, and jumps carry absolute offsets.

That is invisible in a failure. Each frame names the file it actually came from
and quotes that file's line:

```
traceback (most recent call first):
	at divide(a=1, b=0) (lib/math.mut:2:9)
	  2 | 	return a / b;
	    | 	       ^^^^^
	at <main> (main.mut:4:14)
	  4 | putf("%d\n", divide(1, 0));
	    |              ^^^^^^^^^^^^
```

The file-to-line map is debug information. `mutant release` and any build with
polymorphic mutation strip it along with the rest, so a released artifact does
not carry the layout of your source tree.

## Editor support

- `ns.` completes that builtin family's members.
- Hovering `import` shows the namespace it bound and the file it came from.
- Ctrl-click on the path opens the file.
- Every builtin diagnostic — arity, argument types, deprecation, the
  `(value, err)` rules, platform support, unclosed resources — treats `fs.read`
  exactly as it treats `fs_read`.
- A file whose top level only declares things is treated as a module, so its
  exported names are not reported as unused declarations.

## What modules are not

- Not available in the REPL. A REPL line is not a file, so there is nothing for
  a relative path to resolve against.
- Not a package manager. `import` names a file on disk; nothing is fetched.
- Not selective. There is no `import { a, b } from ...` — an import binds the
  namespace, and you reach through it.
- Not re-exporting. `a` importing `b` does not give `a`'s importers `b`; each
  file imports what it uses.

## See also

- [examples/modules/](../examples/modules/) — a working three-file program.
- [CONFIGURATION_POLICY.md](CONFIGURATION_POLICY.md) — why the search path is a
  flag and nothing else.
- [MUTANT_LANGUAGE_REFERENCE.md](MUTANT_LANGUAGE_REFERENCE.md) — the rest of the
  language.
