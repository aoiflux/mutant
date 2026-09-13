# Mutant Language Reference

This document is the practical reference for Mutant language features, reserved keywords, and builtins.

Source of truth:
- Keywords: token/token.go
- Builtins registry: builtin/builtin.go
- Builtin names/constants: builtin/names.go
- Builtin teaching metadata/signatures: builtin/metadata.go

Related references:
- [Capability Reference](CAPABILITY_REFERENCE.md) — the full, category-grouped catalog of every builtin, with parameter types (generated from the metadata above by `cmd/gendocs`).
- [Strings](#strings) — interpolation, raw strings, and triple-quoted blocks.
- [Modules](MODULES.md) — `import`, namespaces, the `_` export rule, and where a path is looked up.
- Deep-dive guides: [Secure Networking](SECURE_NETWORKING.md), [Graph Database](GRAPH_DATABASE.md), [Runtime Integration](RUNTIME_INTEGRATION.md), [Structured Data](STRUCTURED_DATA.md).

## Language Features

Mutant supports:
- Variables and assignment with `let`
- Primitive literals: integers, floats, booleans, strings
- Compound literals: arrays, hashes, struct literals
- Prefix operators: `!`, unary `-`, and the bitwise complement `~`
- Infix operators: `+ - * / % < > <= >= == != && ||` and bitwise `& | ^ << >>`
- Assignment: `=`, compound assignment `+= -= *= /= %= &= |= ^= <<= >>=`, and postfix `++` / `--`
- Indexing and field access
- A distinct `bytes` type for binary data, with explicit conversions to and from text
- Conditionals: `if` / `else`
- Loops: the counting `for`, `while`, and `for (item in collection)`, all with `break` and `continue`
- Pattern matching: `match`, an expression whose value is the arm that matched
- First-class functions, closures, and function calls
- Return statements (single and multi-value)
- Macros
- Type declarations: `struct` and `enum`

### Multi-value returns (the `(value, err)` idiom)

Fallible builtins return two values — a result and an error — which you bind together:

```mutant
let load = fn(path) {
    let data, err = fs_read(path);
    if (err) {
        putln("[error] fs_read:", err);
        return "";
    };
    return data;
};

let report = load("report.json");
putln("read", len(report), "bytes");
```

This convention runs through the whole standard library; the [Capability Reference](CAPABILITY_REFERENCE.md) marks which builtins return a pair. (Idiom note: keep `return` inside functions rather than at the top level of a program. A top-level `return` is legal and stops the program there, reporting the value it returned — or nothing at all for a bare `return;` — but a program that reads top to bottom is easier to follow than one with exits scattered through it.)

### Reading an error

An `err` is an object, and its fields read like a struct's — with `.` or with a
string index, which are the same table and cannot disagree:

```mutant
let data, err = fs_read(path);
if (err) {
    putln("failed:", err.message);        // "fs_read: open ...: no such file"
    putln("raised by:", err.context);     // "builtin.fs_read"
    putln("at:", err.file, err.line);     // the source path, and 12
    putln("same thing:", err["message"]);
};
```

| Field | Type | Where it comes from |
| --- | --- | --- |
| `message` | string | the raiser |
| `context` | string | the raiser — which builtin, e.g. `builtin.fs_read` |
| `related` | hash | the raiser: whatever else it knew — a path, an offset, the bytes it actually read |
| `file`, `line`, `column` | string, int, int | stamped by the runtime at the call |
| `end_line`, `end_column` | int | the end of the construct that failed |
| `source_line` | string | the text of that line, copied when the error was stamped |
| `stack` | array of string | the call stack, innermost first |

Three things worth knowing:

- **`related` keeps types.** An offset in it is an integer and a record is a
  `bytes` buffer, not a pre-formatted string — so `err.related["offset"] > 4096`
  works without parsing text back into a number. Today it is empty on every
  builtin error: the field is there, and the builtins that have context worth
  attaching have not been taught to attach it yet.
- **An unknown field is `null`, not a failure** — the same rule a struct
  follows. `err.kind` reads null today rather than stopping the program.
- **The shape never changes with the build.** A binary compiled with debug
  information stripped carries no line table, so `err.line` reads `0` and
  `err.file` reads `""` — but they still read. A program that inspects position
  does not have to know how it was compiled. `message` and `context` come from
  the raiser rather than the line table, so stripping does not touch them.

Errors are read-only: `err.message = "..."` is refused, because the position is
stamped by the runtime and a program that could rewrite it could lie about where
a failure happened.

### Raising your own error

`error(message, context?, related?)` builds one. Your own errors are the same
kind of value a builtin's failure is, so they read the same, print the same, and
travel the same way through `let value, err = ...`.

```mutant
let parse_record = fn(buf, offset) {
    let magic, magic_err = bytes_slice(buf, 0, 2);
    if (len(buf) < offset + 16) {
        return "", error(
            "record is truncated",           // message
            "evidence.parser",               // context: where it went wrong
            {"offset": offset,               // related: facts, keeping their types
             "available": len(buf),
             "magic": magic}
        );
    }
    return bytes_slice(buf, offset, 16);
};

let rec, err = parse_record(buf, 8192);
if (err) {
    putln(err.message);              // "record is truncated"
    putln(err.context);              // "evidence.parser"
    putln(err.related["offset"]);    // 8192 -- an INTEGER, not the text "8192"
    putln(err.line);                 // the line the error() call is on
}
```

- **`context` defaults to `"user"`.** Every error names its origin: a builtin's
  says `builtin.fs_read`, the runtime's says `evaluator`, and yours says `user`
  until you give it something better. Naming the subsystem, as above, is what
  makes a log line tell you where to look.
- **`related` keys must be strings.** Mutant hashes also allow integer and
  boolean keys; those are refused by name rather than quietly rendered, so
  `{1: "a"}` is an error you can see instead of a `{"1": "a"}` you cannot.
- **`related` values keep their types.** An offset stays an `INTEGER` and a
  buffer stays `BYTES`. This is the whole reason to attach a fact rather than
  formatting it into the message: the reader does not have to parse it back out.
  Bind a fallible call to a name first, as the example does with `magic` --
  writing `bytes_slice(...)` directly into the hash stores the whole
  `(value, err)` pair, not the buffer.
- **The position is filled in for you.** `error()` stamps the call that built it,
  exactly as a builtin's error points at the builtin call.
- **It returns one value, not a pair.** `let e, err = error("x")` is a mistake --
  and one the editor reports before you run it.

Two errors are equal when their `message`, `context` and `related` match.
Position is deliberately not compared: the same failure raised from two places is
the same failure, and a program that cares where reads `err.line`.

### Closing what you open (`with_resource`)

Twenty builtin families hand back a handle you are expected to close: the
filesystem and disk-image readers, `zip_open`/`tar_open`, `hive_open`,
`reg_open`, `db_open`, `cache_open`, `hashset_load`, `chan_new`,
`net_connect`/`net_listen`. Those handles live in a store with no eviction, so
one you forget is held until the process exits — invisible in a script that
opens an image and stops, descriptor exhaustion in a loop over a corpus or a
long-running server.

`with_resource(resource, closer, fn)` makes the close happen:

```mutant
let files, err = with_resource(ntfs_open("disk.img"), "ntfs_close", fn(img) {
    let names, list_err = ntfs_list_files(img["handle"], "/");
    if (list_err) { return list_err; }
    return names;
});
```

The closer runs whatever the body does — returns a value, returns an error, or
fails outright. That is the difference between this and remembering to write the
close yourself: there is no path out of the body that skips it.

- **It is transparent to a failed open.** If `ntfs_open` fails, the body never
  runs and you get exactly the error `let img, err = ntfs_open(...)` would have
  given you. Wrapping an existing call changes nothing else about it.
- **The `(value, err)` convention passes through.** A body ending in a fallible
  call hands you its two halves, not a pair to take apart. A body that *returns*
  an error fills the error slot.
- **The closer is a name or a function.** `"ntfs_close"` names the builtin;
  `fn(h) { ... }` is for cleanup that is more than one call. Naming it as a
  string is what lets the editor check the spelling.
- **When the body and the close both fail**, the body's error is the one you
  get, with the close's attached as `err.related["close_error"]`.

The editor reports the handles this does not cover. `unclosedResource` warns
when an opener's result is bound to a name that nothing in the same scope
closes, and stays quiet whenever it cannot see the whole lifetime — a handle
returned to a caller, handed to a helper, or held by a server that runs until
it is interrupted.

### Binding several names at once

`let a, b = ...` binds more than one name from a single expression. What it does
depends on what is on the right:

```mutant
let data, err = fs_read(path);   // a fallible builtin: result, then error
let first, second = [1, 2, 3];   // an array: element by element -- 1 and 2
let value, extra = 42;           // anything else: value goes to the first name,
                                 // extra is null
```

Names past the end are null, and elements past the last name are dropped.

**This is worth knowing before you write `let x, err = ...` out of habit.** A
builtin that cannot fail returns one value, not a pair — and if that value is an
array, the binding takes it apart instead of reporting an error:

```mutant
let items = ["a", "b"];
let updated, err = push(items, "c");   // WRONG: push returns one array
                                       // updated is "a", err is "b"

let updated = push(items, "c");        // right: ["a", "b", "c"]
```

Nothing about this fails at compile time, and `err` is usually falsy, so an
`if (err)` check passes and the program carries on with the wrong value. Check
the [Capability Reference](CAPABILITY_REFERENCE.md) for whether a builtin returns
a pair; `push`, `first`, `last`, `rest` and `len` do not.

**Binding the error is not the same as reading it.** When a fallible call fails
it leaves null in the value beside the error, so a program that never looks at
`err` carries on with nothing and reports success:

```mutant
let report_json, err = json_stringify(report);
let wrote, err = fs_write(path, report_json);   // writes "null" if the first
                                                // call failed
```

`uncheckedError` warns on both lines. The first `err` is replaced before
anything reads it; the second is never read at all. It stays quiet when you read
the error
any way at all -- test it, print it, return it, hand it on -- and when you catch
the failure through the value instead, either by testing the value in an `if`
condition or by using a boolean success flag, which is false whenever the call
failed. When you genuinely mean to ignore a failure, bind `_` and the rule takes
you at your word:

```mutant
let _, _ = fs_write(log_path, line);   // best-effort logging, on purpose
```

### Loops

Three spellings, each its own construct. `break` and `continue` work in all of
them, and mean the same thing in each.

```mutant
// Counting, when the index is the point.
for (let i = 0; i < len(hosts); i++) {
    putln(hosts[i]);
}

// A condition, when the end is not a count.
while (len(queue) > 0) {
    let job = queue[0];
    queue = slice(queue, 1, len(queue));
    run(job);
}

// Over a collection, when the elements are the point.
for (host in hosts) {
    putln(host);
}
```

What `for (item in collection)` binds depends on how many names it binds and
what it is walking:

| Written | Over an array | Over a hash | Over a string or bytes |
| --- | --- | --- | --- |
| `for (v in xs)` | element | **key** | character / byte |
| `for (k, v in xs)` | index, element | key, value | index, character / byte |

A single binding yields the thing the collection is made of, which is why an
array gives elements but a hash gives keys.

A hash is visited in the same order printing it shows. `Hash.Pairs` is a Go map
and its iteration order differs run to run, so both the printer and the loop
sort with the same comparison: a program that prints a hash and a program that
loops over one agree about what order it is in.

There is no range syntax. `range(start, end[, step])` is an ordinary builtin
returning an array, so counting over one is a `for…in` like any other:

```mutant
for (n in range(0, 10)) { putln(n); }
for (n in range(10, 0, -2)) { putln(n); }
```

### Matching (`match`)

`match` is an **expression**: it evaluates to the arm that matched, so it binds,
returns, and nests like any other value.

```mutant
let label = match (code) {
    0         => "clean",
    1 | 2 | 3 => "a few findings",
    -1        => "the scan did not run",
    _         => "many findings",
};
```

Arms are `pattern => value`, separated by commas, tried top to bottom. A trailing
comma after the last arm is allowed.

A pattern is one of:

- a literal — integer, float, string, `true`, `false`
- a negated number — `-1`, `-2.5`
- an enum variant — `Status.Ok`, or `mod.Status.Ok` for an imported enum
- `_`, which matches anything

Alternatives are joined with `|`, which is a *pattern* separator here rather
than the bitwise-or operator: patterns have their own grammar, so `1 | 2 | 3`
means those three values and not the number `3`.

An arm body may be a block, whose value is its last expression:

```mutant
let weight = match (name) {
    "critical" => {
        let base = severity[name];
        base * 10;
    },
    _ => 0,
};
```

The parentheses around the subject are required. `{` is also the opening of a
struct literal (`Point { x: 1 }`), so `match x { ... }` without them parses
cleanly as a struct literal named `x` and means something else entirely.

Because a `match` has to produce a value, a subject that no arm matches is a
**run-time error naming the value**, not `null`:

```mutant
enum Status { Ok, Failed, Pending };

let text = match (status) {
    Status.Ok     => "finished",
    Status.Failed => "raised",
};                                   // raises when status is Status.Pending
```

That is the case the rule exists for: adding a variant to an enum leaves every
existing `match` over it one arm short, and a `null` flowing onward would hide
it. The language server reports the gap before the program runs — see the
`matchExhaustiveness` rule — and writing `_` says the rest is deliberate.

Not in this version: binding patterns (`n => ...`), payload destructuring (enum
variants carry no payload), and guards (`n if n > 3 =>`, which depends on
binding). An interpolated string is rejected as a pattern rather than quietly
accepted, since comparing against something computed at match time is a guard.

### First-class functions and closures

Functions are values: you can bind them, pass them, return them, and capture free variables.

```mutant
let adder = fn(n) {
    return fn(x) { return x + n; };   // closes over n
};
let add10 = adder(10);
putln(add10(5));                       // 15
```

A closure captures its free variables **by reference**, so it can read them and
write them, and the enclosing function sees the writes:

```mutant
let total = fn() {
    let acc = 0;
    each([1, 2, 3], fn(x) { acc = acc + x; });
    return acc;                                  // 6
};
```

There is one storage location per variable per call, shared by the frame and
every closure over it. Two closures over the same variable therefore see each
other's writes, and a closure that outlives the call that made it keeps its
variable alive:

```mutant
let counter = fn() {
    let n = 0;
    return fn() { n = n + 1; return n; };
};
let next = counter();
putln(next());                                   // 1
putln(next());                                   // 2
putln(counter()());                              // 1 -- a separate n
```

A captured variable is scoped to the call, not to the iteration. A closure made
inside a `for` loop shares the loop's variable rather than getting a snapshot of
it, which is the behaviour of `var` in JavaScript and of a Go loop variable
before Go 1.22. Capture the value in a parameter if you want it frozen:

```mutant
let freeze = fn(v) { return fn() { return v; }; };
```

Two things are still not assignable, because neither is storage: a builtin's
name, and the name a function literal was bound to (`f = 1` inside `f`). Both
are refused at compile time.

### Higher-order collection functions

Closures compose with the functional collection builtins `map`, `filter`, `reduce`, `each`, and `sort_by`:

```mutant
let nums = [5, 3, 8, 1];
let doubled = map(nums, fn(x) { return x * 2; });
let big = filter(nums, fn(x) { return x > 3; });
let total = reduce(nums, fn(acc, x) { return acc + x; }, 0);
let sorted = sort_by(nums, fn(x) { return x; });
```

`map`/`filter`/`each` callbacks may also take `(element, index)`.

### Running a callback in parallel (`pmap` / `peach`)

Collection work in this language is usually I/O- or CPU-bound per element --
hashing a directory of files, resolving a list of domains, scanning a range of
ports -- and doing it one element at a time is what makes a collection script
slow. `pmap` is `map` with the elements processed concurrently; `peach` is `each`.

```mutant
// Hash every file in a directory, eight at a time.
let digests = pmap(paths, fn(path) {
    let digest, err = fs_hash(path, "sha256");
    if (err) { return ""; };
    return digest;
}, 8);
```

**Results keep the input's order.** Workers finish out of order, but each result
lands back in its element's position, so `pmap` is a drop-in replacement for
`map` wherever the callback is independent per element.

The third argument caps how many run at once. Omit it and the worker count
follows the machine's CPU count, capped by the array length.

**What the callback may rely on.** Each worker runs on its own VM with a
*snapshot* of globals and its own copy of the callback's captured variables,
taken when the call starts. So a callback can read both, but an assignment to
either stays local to that worker and is lost when it finishes -- unlike the
sequential `each`, where a captured accumulator does reach the caller. Write
callbacks that return their result rather than accumulating; when workers
genuinely need to share state, put it in a `cache_*` or `db_*` store, which is
what `net_serve` handlers already do.

An error raised inside a callback stops the whole call and surfaces, the same as
in `map`.

### Running one function alongside the program (`spawn` / channels)

`pmap` covers the case where the work is an array. When it isn't -- a server
handling connections, a long collection running while the program does something
else -- `spawn` runs a single function on its own VM and hands back a handle:

```mutant
let t, err = spawn(fn(dir) {
    let entries, e = fs_walk(dir);
    return len(entries);
}, "/evidence");

// ... do other work here ...

let count, werr = task_wait(t);
```

`spawn(fn)` calls a function of no parameters and `spawn(fn, arg)` one of a
single parameter. `task_wait(handle)` blocks for the result; `task_wait(handle,
ms)` gives up after a while and leaves the task collectable; `task_done(handle)`
answers without waiting. Whatever stopped a task -- an error, a division by zero
-- comes back in `task_wait`'s error slot rather than taking the program down.
Collecting a task releases its handle, so wait for it once.

**A spawned task follows the same rules as a `pmap` worker**: its own VM, its own
stack, and a *snapshot* of globals and captured variables taken at the spawn. It
can read both; its own writes to either stay local. The way back is the return
value, or a channel.

#### Channels

A channel passes values between concurrently running code, since the pieces
share no variables:

```mutant
let ch, e = chan_new(16);            // 16 values may queue; 0 is unbuffered

let t, se = spawn(fn(c) {
    let entries, err = fs_walk("/evidence");
    for (let i = 0; i < len(entries); i++) {
        let sent, serr = chan_send(c, entries[i]["path"]);
    }
    let closed, cerr = chan_close(c);   // tells the receiver there is no more
}, ch);

for (;;) {
    let r, rerr = chan_recv(ch, 5000);  // wait up to 5s
    if (!r["ok"]) { break; }            // closed, or timed out
    putln(r["value"]);
}
```

`chan_recv` reports `{ok, value, closed, timeout}` rather than returning the
value directly, because `null` is itself a sendable value: `ok` is the only way
to tell "received null" from "received nothing". `chan_try_recv` is the same
without ever waiting. Values already queued survive a close, so a receive loop
drains a closed channel before it sees `closed`.

`chan_send` returns true once the value is handed over and false if its timeout
ran out; sending on a *closed* channel is an error, because the value had
nowhere to go.

**Close every channel you open.** At most 1024 may be open at once, and
`chan_new` reports an error rather than waiting when that is reached -- waiting
would deadlock code that is trying to create the channel a sibling is about to
read. Closing is what releases a channel: the handle stays usable afterwards so
a receiver can drain what was already queued, and is reclaimed once enough other
channels have been closed after it, at which point it reports as unknown. A
server that opens a channel per connection therefore has to close them, not just
stop using them.

#### What happens at exit

The runtime waits for every spawned task before the program ends, so work
started and never collected still finishes. The flip side is that a task which
never returns keeps the program alive -- close the channel it is waiting on, or
give its receive a timeout.

At most 1024 tasks run at once. Past that `spawn` reports an error rather than
blocking, so an accept loop can shed load instead of deadlocking.

### Logical operators

`&&` (and) and `||` (or) combine conditions and **short-circuit** — the right
operand is only evaluated when the left doesn't already decide the result. They
return a strict boolean (using the same truthiness rules as `if`). Precedence:
comparisons bind tighter than `&&`, which binds tighter than `||`.

```mutant
// The right side is skipped when the left decides the outcome.
let has_both = si_frac == 0 && fn_frac > 0;   // both conditions must hold
let ready = configured || force;               // either is enough
```

### Bitwise operators

`&` (and), `|` (or), `^` (xor), `<<` (left shift), `>>` (right shift) and the
prefix `~` (complement) operate on integers. They are the signed 64-bit
operations Go performs, so every result matches Go exactly.

```mutant
let READ  = 1;
let WRITE = 2;
let EXEC  = 4;

let perms = READ | EXEC;                 // 5  -- combine flags
let can_write = (perms & WRITE) != 0;    // false -- test one
perms = perms | WRITE;                   // 7  -- set one
perms = perms & ~EXEC;                   // 3  -- clear one

let b = 240;
b >> 4;                                  // 15 -- the high nibble
b & 15;                                  // 0  -- the low one
```

**Precedence follows Go, not C.** `<< >> &` bind as tightly as `* / %`, and
`| ^` bind as tightly as `+ -`. All of them bind tighter than the comparison
operators, so `flags & MASK == 0` means `(flags & MASK) == 0` — the reading you
wanted. C parses that same line as `flags & (MASK == 0)`, which is why C code
is full of defensive parentheses around masks. Two cases still deserve them,
because Go's answer is not the one most people would guess:

```mutant
1 | 2 + 1;    // 4, not 3: `|` and `+` are the same level, evaluated left to right
1 << 2 + 1;   // 5, not 8: `<<` binds tighter than `+`, so it is (1 << 2) + 1
```

**`>>` is an arithmetic shift.** The operands are signed, so the sign bit is
copied in as the value moves right: `-8 >> 1` is `-4`, and `-1 >> 63` is still
`-1`. There is no unsigned integer type, and therefore no logical shift.

**A shift count of 64 or more is not an error.** The value simply falls off the
end, so `1 << 64` is `0` and `-1 >> 64` is `-1`. A *negative* count is an error:
Go panics on one, and a program that shifts by a computed value can reach a
negative count without anybody having written a minus sign.

**Every operand must be an integer.** A float is refused, not truncated:

```mutant
1.5 & 1;   // error: bitwise operator & requires INTEGER operands, got FLOAT and INTEGER
~1.5;      // error: bitwise complement requires an INTEGER, got FLOAT
```

Rounding to make the expression work would be the same class of plausible wrong
answer the `bytes` type exists to prevent: the bits of a float are not the bits
of the number it spells, so there is no honest result to return.

The compound forms `&= |= ^= <<= >>=` are sugar in exactly the way `+=` is —
`x &= mask` is `x = x & mask`.

> Masks are written in decimal for now: Mutant has no hex literals, so `0xFF`
> does not parse. Write `255`.

### Compound assignment and increment/decrement

`+= -= *= /= %=`, and the bitwise `&= |= ^= <<= >>=`, update a variable in
place using its current value, and postfix `++` / `--` add or subtract one.
They are pure syntactic sugar: `x += y` is exactly
`x = x + y`, and `x++` is exactly `x = x + 1`, so they follow the same operator
semantics (integer vs. float promotion, `+=` concatenating strings, integer
division/modulo-by-zero errors). The target must be an assignable lvalue — a
variable, field, or index — and, like any `=`, the whole expression evaluates to
the newly stored value.

```mutant
let total = 0;
for (let i = 0; i < 5; i++) {   // i++ in the loop's post section
    total += i * 2;             // total = total + i * 2
};

let name = "mut";
name += "ant";                  // string concatenation -> "mutant"

let n = 100;
n -= 30;   n /= 2;   n %= 9;    // chained: 100 -> 70 -> 35 -> 8
```

### Macros (`macro`, `quote`, `unquote`)

A macro is a template the compiler expands before it generates any code. It
receives its arguments as **source**, not as values, and returns source that is
substituted at the call site.

```mutant
let unless = macro(condition, consequence, alternative) {
    quote(if (!(unquote(condition))) { unquote(consequence); } else { unquote(alternative); });
};

unless(1 > 2, putln("smaller"), putln("bigger"));   // prints: smaller
```

- `quote(expr)` captures `expr` as source instead of evaluating it. A macro body
  must end in one; a body that produces an ordinary value is a compile error.
- `unquote(expr)` is only meaningful inside a `quote`. It evaluates `expr` at
  expansion time and splices the result in as source. Only values with a literal
  spelling can make that trip — integers, floats, strings, booleans, and
  already-quoted source. Splicing an array, a hash or a function is a compile
  error.
- Macro parameters arrive already quoted, so `unquote(param)` substitutes the
  **argument's source**, unevaluated. `add(dynamic, 5)` substitutes the
  identifier `dynamic`, not whatever it holds at expansion time.

**Declaration and scope.** Macros are collected from top-level statements only,
and their declarations are removed from the program before compilation. A macro
declared inside a function or a block is never collected, and is reported as
such. A macro is not a value: it cannot be passed to a function, stored in an
array, or called at run time.

**Where calls expand.** Anywhere an expression can appear — as a call argument,
an array element, an index, a `for` header, an assignment's right side, a struct
literal field. A macro may also expand into a call to another macro; expansion
repeats until nothing changes. A macro that expands into a call to itself never
settles and is reported rather than run forever.

**When expansion happens.** During compilation, so `mutant gen` needs no flag
and neither do the examples in [examples/macros/](../examples/macros/). The
interactive REPL only defines macros when started with `-em` /
`--enable-macros`; it then expands and compiles them on the same path the CLI
uses, so the flag does not change what the language means.

### Binary data: the `bytes` type

A `bytes` value is a byte buffer — a disk sector, a PE section, a memory page, a
socket read. It exists because a Go string holds arbitrary bytes perfectly well,
so nothing was ever corrupted at rest, but no builtin could tell binary from
text: `str_reverse` rune-reverses and turns every byte that is not valid UTF-8
into U+FFFD, `str_substr` and `str_char_at` index by rune so their offsets
disagree with `bytes_get`'s, and the `regex_*` family reads invalid bytes as
U+FFFD. None of those fail. They return a plausible wrong answer.

There are no `bytes` literals. A buffer comes from a producer or a conversion:

```
let raw, err = fs_read_bytes("disk.img");   # a native producer
let mz, e2   = string_to_bytes("4d5a", "hex");
let same, e3 = string_to_bytes(fs_read(p), "raw");  # bridges any older producer
```

The conversions are explicit and name an encoding — `"raw"`, `"utf8"`
(validated, not substituted), `"latin1"`, `"hex"`, `"base64"` — because the step
between binary and text is the one worth being deliberate about. There is no
implicit coercion in either direction.

What a buffer supports:

| Operation | Behaviour |
| --------- | --------- |
| `b[i]` | the byte at `i` as an **integer 0-255** (not a one-byte buffer) |
| `b[i] = n` | writes one byte in place; `n` must be 0-255 |
| `a + b` | concatenation, into a fresh buffer |
| `==`, `!=` | by content; a buffer is never equal to a value of another type |
| `len(b)` | the byte count |
| truthiness | an empty buffer is falsy |
| hash key | yes, in a keyspace disjoint from strings |
| `putln(b)` | full lowercase hex, untruncated |

`<` and `>` are not defined on buffers.

**Nothing that returns a string today started returning a buffer.** The type
arrived additively: `fs_read` still returns a string, and `fs_read_bytes` is the
new name. The same holds for `hex_decode_bytes`, `base64_decode_bytes`,
`gunzip_bytes`, `zlib_decompress_bytes`, `aes_decrypt_bytes`,
`net_conn_read_bytes`, `mem_read_bytes`, and the `*_read_file_bytes` /
`*_read_at_bytes` image readers. Consumers went the other way and widened: the whole `bytes_*` family,
`fs_write`, `fs_append`, every `hash_*`, `hmac`, and the encoders accept either
representation, and the `bytes_*` family is shape-preserving — `bytes_slice` of
a buffer is a buffer, of a string a string.

Some builtins predate the type and hex-encode their binary output defensively,
because there was once no other way to carry it. Those are being given direct
routes the same additive way — `mem_read_bytes` alongside `mem_read`, a
`resident_data_bytes` field alongside `fs_deleted`'s hex `resident_data`, and a
`data_bytes` field on the values `reg_get_value`, `reg_enum_values`,
`hive_get_value` and `hive_list_values` return. Recovering a deleted file is
`fs_write(out, e["resident_data_bytes"])` rather than a `string_to_bytes`
statement first, and a REG_BINARY blob is parsed straight out of
`v["data_bytes"]`. The hex fields stay exactly as they were.

`data_bytes` is present exactly when `data` is hex — REG_BINARY, and value
types the reader does not recognise. Other types are already carried faithfully
(a REG_DWORD is an integer, a REG_MULTI_SZ an array), so there is no hex to
undo, and the `type` field beside it says which case you are in. A registry
opened from a hive-JSON file never reports it: that format is a transcription of
a hive rather than the artifact, and has no binary type to transcribe.

`sqlite_query` and `evtx_parse` get a whole second builtin rather than a second
field, because their binary values sit under keys taken from the file being
parsed — column names, BinXML element names — so there is no key we own to hang
an alternative rendering on. `sqlite_query_bytes` and `evtx_parse_bytes` answer
the same questions with the same return shapes; only the binary changes.

`sqlite_query_bytes` also settles a question its older twin has to guess at.
`sqlite_query` asks whether a BLOB happens to be valid UTF-8 and returns a
string if it is and hex if it is not, so one column's type varies row by row
with its content and a BLOB that decoded is indistinguishable from a TEXT that
did not. In `sqlite_query_bytes` a BLOB is a buffer whatever bytes it holds:
the column's type decides, not the value inside it. Other column types are
untouched — an INTEGER is still an integer, a TEXT still a string.

The language server knows the type. Passing a buffer to a text builtin raises
`builtinArgType` before the program runs, and the message names the conversion.

### Modules (`import`)

A program can be more than one file. `import` loads another `.mut` file and
binds it to a namespace; [MODULES.md](MODULES.md) is the full reference.

```mutant
import "lib/stats.mut";          // binds the namespace `stats`
import numbers "lib/stats.mut";  // binds `numbers` instead

putf("%d\n", stats.mean([12, 47, 31]));
```

The rules in brief:

- **Top level only.** An import inside a block is an error: modules are resolved
  and linked before the program runs, so there is no moment at which control
  could "reach" one.
- **An import binds one name.** The imported file's own names are not visible
  unqualified, so two modules may each declare `helper` without collision.
  Builtins are the exception and are visible everywhere with no import.
- **`_` is private.** A top-level name beginning with an underscore is visible
  only inside the file that declares it; `ns._x` is a compile error naming the
  module and the name.
- **Paths resolve relative to the importing file first,** then against each
  `--module-path <dir>` directory in the order given. The extension is written
  out, never guessed. Nothing else contributes to the search — no manifest, no
  config file, no environment variable.
- **Cycles are an error** reported as the chain that closed them. A diamond is
  not a cycle: a shared module is compiled and run exactly once.
- **`struct` and `enum` names are program-wide,** not namespaced. One
  declaration is visible everywhere, and two modules declaring the same type
  name is an error naming both files. Values are per-module, types are
  per-program.
- **Tracebacks name the real file.** Modules link into one instruction stream,
  but each frame reports the file and line it came from and quotes that file's
  source.

Builtin families are addressable the same way with no import at all: `fs.read`
is `fs_read` and `str.upper` is `str_upper`, derived by joining the halves, so
both spellings are one function. A variable or import that already binds the
name wins, so no existing program changes meaning.

Imports are a compiled-program feature. The REPL has no file for a relative
path to resolve against.

### Strings

A string literal has three spellings. All three produce the same kind of value;
they differ only in what the source is allowed to say.

```mutant
let host = "db01";
let port = 5432;

// Ordinary: escapes are decoded, ${...} interpolates.
putln("connecting to ${host}:${port}");

// Raw: nothing is decoded. Every backslash is itself.
let key = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run";

// Triple-quoted: spans lines, and is re-indented to its own left margin.
let report = """
    host: ${host}
    port: ${port}
    """;
```

#### Interpolation

`${` opens a hole and `}` closes it. What is between them is an ordinary
expression -- a call, an index, arithmetic, another string -- evaluated where it
is written:

```mutant
putln("largest: ${ max(values) }");
putln("first: ${ rows[0]["name"] }");
```

A value that is already a string contributes its own text; anything else
contributes what it would print, so `"n=${1 + 1}"` is `"n=2"` and no conversion
has to be written. Nothing is re-scanned afterwards: a `%` in an interpolated
string is a percent sign, not a format directive.

A lone `$` is still a `$`, so `"cost: $5"` and `"$PATH"` are unchanged. Only the
two characters `${` open a hole, and `\${` writes them literally.

A hole holds exactly one expression. `${}` and `${ let x = 1; }` are compile
errors naming the line and column inside the string, and so is anything that
fails to parse there -- a broken hole is reported where it is, not where the
string starts.

#### Raw strings

`r"..."` decodes nothing: there are no escapes and no interpolation, which is
what makes a Windows path or a regex readable.

```mutant
let path = r"C:\Users\Public\Desktop";     // "C:\\Users\\Public\\Desktop"
let stamp = r"\d{4}-\d{2}-\d{2}";
```

A raw string ends at the first `"`, so it cannot contain one. Use an ordinary
string or a raw triple-quoted one when you need a quote inside.

#### Triple-quoted strings

`"""..."""` spans lines. Escapes and interpolation still work; `r"""..."""` is
the raw form of the same thing, and either may contain a lone `"` or `""`.

Three things happen to the text, and all three exist so that a block reads as
the text it is rather than as the text plus the code's indentation:

- A newline immediately after the opening `"""` is dropped.
- The smallest indentation of any non-blank line -- counting the line the
  closing `"""` is on when it is alone on one -- is removed from every line.
  Indentation is counted in characters, so a tab counts as one.
- `\r\n` becomes `\n`. The line endings in a multi-line literal come from
  however the file was checked out, and a program must not mean two different
  things in two clones of the same repository. Write `\r` for a carriage
  return.

Re-indentation applies only when the opening `"""` is alone on its line. A
literal that starts text on the opening line has no indentation to measure, so
it is left exactly as written.

#### Escape sequences

In an ordinary or triple-quoted string: `\n`, `\r`, `\t`, `\"`, `\\`, `\0`, and
`\$`. Anything else is kept as both characters, so `"\d+"` is a usable regex
without doubling -- though `r"\d+"` says so on purpose.

### Notes
- **Semicolons are required to terminate statements** — including statements whose value is a block, e.g. `let f = fn() { ... };` and `if (c) { ... };`. The language server's formatter enforces this canonically (it repairs missing semicolons and removes redundant ones on format), and the `semicolon` diagnostic flags them while you type.

## Reserved Keywords

- break
- continue
- else
- enum
- false
- fn
- for
- if
- import
- in
- let
- macro
- match
- return
- struct
- true
- while

## Builtins

**Total builtins currently registered: 459**, across 34 capability categories.

The complete catalog — every builtin with its typed signature, platform support, and description — lives in the **[Capability Reference](CAPABILITY_REFERENCE.md)**, which is generated directly from `builtin/metadata.go` by `cmd/gendocs` so it never goes stale. Regenerate it with `go run ./cmd/gendocs` after adding or changing a builtin; `go run ./cmd/gendocs -check` (and the `cmd/gendocs` test) fails if it has drifted. The categories are indexed below; each links into that reference.

| Category | Count | What it covers |
| --- | --- | --- |
| [Standard library](CAPABILITY_REFERENCE.md#standard-library-56) | 56 | Core primitives, collection/hash ops, higher-order functions (including parallel `pmap`/`peach`), I/O, introspection |
| [Concurrency](CAPABILITY_REFERENCE.md#concurrency-8) | 8 | Background tasks (`spawn`/`task_wait`) and channels for passing values between them |
| [Strings](CAPABILITY_REFERENCE.md#strings-18) | 18 | Rune-aware string manipulation |
| [Text analysis](CAPABILITY_REFERENCE.md#text-analysis-14) | 14 | Search, split/replace, regex, fuzzy matching |
| [Structured data](CAPABILITY_REFERENCE.md#structured-data-25) | 25 | JSON, encoding, compression, type/base conversion, plist |
| [Math](CAPABILITY_REFERENCE.md#math-5) | 5 | Constants and random helpers |
| [Hashing](CAPABILITY_REFERENCE.md#hashing-11) | 11 | Digests, HMAC, UUID/ID generators |
| [Time](CAPABILITY_REFERENCE.md#time-7) | 7 | Unix timestamps, formatting, parsing, arithmetic |
| [Bytes](CAPABILITY_REFERENCE.md#bytes-30) | 30 | Binary buffer read/write, cursor, slicing |
| [Filesystem](CAPABILITY_REFERENCE.md#filesystem-19) | 19 | Files/dirs plus file-level forensics (hash, entropy, magic, carve, deleted) |
| [Network](CAPABILITY_REFERENCE.md#network-32) | 32 | Sockets, TLS/CA, HTTP inspection, WebSocket, scanning, pcap |
| [Http](CAPABILITY_REFERENCE.md#http-11) | 11 | HTTP client + request/response parse/build |
| [Graph database](CAPABILITY_REFERENCE.md#graph-database-14) | 14 | Nodes/edges/relations, traversal, pathfinding, stats |
| [Cache](CAPABILITY_REFERENCE.md#cache-8) | 8 | In-memory key/value cache with TTLs |
| [Policy](CAPABILITY_REFERENCE.md#policy-5) | 5 | Allow/deny policy evaluation and tracing |
| [Runtime integration](CAPABILITY_REFERENCE.md#runtime-integration-3) | 3 | Sandboxed Lua execution |
| [Command execution](CAPABILITY_REFERENCE.md#command-execution-4) | 4 | Guarded external command execution |
| [Cryptography](CAPABILITY_REFERENCE.md#cryptography-5) | 5 | X.509, JWT, PEM, AES-GCM |
| [Fingerprinting](CAPABILITY_REFERENCE.md#fingerprinting-4) | 4 | imphash, JA3, NT/LM hashes |
| [Network intelligence](CAPABILITY_REFERENCE.md#network-intelligence-11) | 11 | IOC defang/refang, IP/CIDR, domain/eTLD+1, IOC extraction |
| [Detection](CAPABILITY_REFERENCE.md#detection-5) | 5 | Injection, beaconing, persistence, priv-esc, suspicious files |
| [Process forensics](CAPABILITY_REFERENCE.md#process-forensics-9) | 9 | Live process inspection, memory scan, modules |
| [Memory forensics](CAPABILITY_REFERENCE.md#memory-forensics-6) | 6 | Memory-dump analysis, PE/shellcode discovery |
| [Binary analysis](CAPABILITY_REFERENCE.md#binary-analysis-14) | 14 | PE/ELF/Mach-O/DWARF, imports, GoReSym |
| [Registry forensics](CAPABILITY_REFERENCE.md#registry-forensics-15) | 15 | Hive/JSON/live registry, Amcache, Shimcache |
| [Filesystem forensics](CAPABILITY_REFERENCE.md#filesystem-forensics-31) | 31 | NTFS/FAT/exFAT/ext/HFS+/XFS parsers, $MFT |
| [Disk image forensics](CAPABILITY_REFERENCE.md#disk-image-forensics-17) | 17 | Raw/EWF/VHD(X) images, MBR/GPT tables |
| [Windows artifacts](CAPABILITY_REFERENCE.md#windows-artifacts-4) | 4 | Prefetch, EVTX, LNK, Jump Lists |
| [Unix artifacts](CAPABILITY_REFERENCE.md#unix-artifacts-1) | 1 | syslog (RFC 5424 / 3164) |
| [Browser artifacts](CAPABILITY_REFERENCE.md#browser-artifacts-4) | 4 | Chromium/Firefox history/cookies/downloads, SQLite |
| [Forensic timeline](CAPABILITY_REFERENCE.md#forensic-timeline-5) | 5 | Timestamp normalize, merge/sort, bodyfile/mactime |
| [Email forensics](CAPABILITY_REFERENCE.md#email-forensics-5) | 5 | Header/body/attachment parsing, DKIM verification |
| [Hash-set forensics](CAPABILITY_REFERENCE.md#hash-set-forensics-3) | 3 | NSRL-style known-file filtering |

### Platform support

Almost every builtin is pure-Go and cross-platform — the forensic parsers operate on *captured* artifacts, so they run on any host. A few live-system builtins are platform-restricted and fail honestly elsewhere; the language server warns when you call one on an unsupported OS:

- `process_memory_scan` — Windows, Linux
- `process_modules` — Windows, Linux
- `reg_open` — cross-platform for hive-file/JSON inputs; the live-registry path (`HKLM\...`) is Windows-only
- `process_kill` — cross-platform; on Windows only SIGKILL semantics apply

## Quick Example

```mutant
// Read a JSON target list, resolve each host, and print a report.
// Program logic lives in a function so `return` is never used at the top level.
let run = fn() {
    let raw, err = fs_read("targets.json");
    if (err) {
        putln("[error] fs_read:", err);
        return false;
    };

    let targets, parse_err = json_parse(raw);
    if (parse_err) {
        putln("[error] json_parse:", parse_err);
        return false;
    };

    let results = map(targets["hosts"], fn(host) {
        let addrs, resolve_err = net_resolve(host);
        if (resolve_err) {
            return { "host": host, "ok": false, "error": resolve_err };
        };
        return { "host": host, "ok": true, "addresses": addrs };
    });

    let report, stringify_err = json_stringify({ "results": results });
    if (stringify_err) {
        putln("[error] json_stringify:", stringify_err);
        return false;
    };
    putln(report);
    return true;
};

run();
```

## Command-line tooling

Beyond compiling and running, the `mutant` CLI exposes the same formatter and
analyzer the language server uses, so editor and command-line results agree:

- `mutant fmt [--check] [--stdout] <file-or-dir>...` — rewrite source in the
  canonical style in place. `--check` lists files that are not already formatted
  and exits non-zero (for CI) without writing; `--stdout` prints the formatted
  result instead of editing. Formatting is idempotent.
- `mutant lint [--strict] <file-or-dir>...` — print diagnostics as
  `file:line:col: severity: message [source]`; exits non-zero on any error, or on
  any warning with `--strict`.
- `mutant test [options] [file-or-dir]...` — run every `*_test.mut` file, with
  `--run` to select tests by name, `-v`, `--json` for CI, `--fail-fast`, and
  `--cover` / `--coverprofile` for line coverage. With no path it tests the
  current directory. See [TESTING.md](TESTING.md).

Directory arguments are walked recursively (skipping `.git`, `node_modules`, and
`vendor`).

```mutant
// math_test.mut  -> `mutant test .`
let add = fn(a, b) { return a + b; };

test("adds", fn() {
    assert_eq(add(2, 3), 5);
    assert_eq(add(-1, -1), -2);
});
```

A test file is an ordinary program, compiled the same way any program is, so it
can `import` the module it tests. A file that declares no `test` still counts as
one test and keeps the original contract: it **passes** unless running it errors
or its final value is `false`.

### What the linter checks for you

`mutant lint` runs the same rules the editor does. Most of them read a fact the
builtin registry states — how many arguments a builtin takes, what kinds it
accepts, whether it returns a `(value, err)` pair — and are simply right.

Seven more read intent, and those are the ones worth knowing about, because they
are about the work this language is for:

| Rule                      | What it reports                                                                                                    |
| ------------------------- | ------------------------------------------------------------------------------------------------------------------ |
| `evidenceMutation`        | A write, delete or move aimed at a path the same program opened with `raw_open`, `ewf_open`, `ntfs_open` and friends |
| `commandInjection`        | A value spliced into the string `exec_string` gives a shell, a `cmd_add` line, or a `lua_run_string` script          |
| `pathTraversal`           | A path built from `gets`, `serve_arg` or a request, reaching the filesystem with nothing looking at it first         |
| `weakCrypto`              | An MD5, SHA-1 or CRC-32 digest compared against one written into the program — an authenticity check                 |
| `hardcodedSecret`         | A credential written into the source, by name or by a provider's own prefix                                          |
| `tlsVerificationDisabled` | `insecure: true`, or a `min_version` below 1.2                                                                       |
| `unboundedResource`       | A `cidr_hosts` or `range` whose literal arguments exceed what the builtin will return                                |

Each of these has a way to say "I have handled this", and taking it is what
silences the rule — there is no suppression comment:

```mutant
// pathTraversal: look at the value, and the rule takes you at your word.
let leaf, err = serve_arg();
if (text_contains(leaf, "..") == false) {
    let body, rerr = fs_read("/srv/files/" + leaf);
};

// commandInjection: strip what could be syntax, or encode it away.
let out, xerr = exec_string("whois " + text_replace(host, ";", ""));

// weakCrypto: comparing two computed digests is matching, not verifying.
let same = hash_md5(a) == hash_md5(b);

// hardcodedSecret: a value handed to a decoder is a sample, not a credential.
let token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig";
let claims, jerr = jwt_decode(token);
```

They all decline where they cannot be certain, and they all err towards saying
nothing: a false positive on a security rule is how a security rule gets turned
off. Any of them can be set to `off` — or to `error`, for CI — through
`mutant.lint.rules.<name>.severity`.

## Maintenance

When adding or changing language keywords or builtins, update the source definitions first
(`token/token.go`, `builtin/builtin.go`, `builtin/names.go`, `builtin/metadata.go`), then
regenerate [CAPABILITY_REFERENCE.md](CAPABILITY_REFERENCE.md) from the metadata and review this
file. The category counts above and in the capability reference come straight from the registry,
so keep them in sync by regenerating rather than hand-editing.
