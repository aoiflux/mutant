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

### Assigning through a container

A target is a variable, optionally followed by any number of index and field
hops. Every container on the way is written back, so a write through several of
them lands where you wrote it:

```mutant
let counts = {};
for (host in ["a", "b", "a"]) {
    if (!has_key(counts, host)) { counts[host] = {"n": 0}; };
    counts[host]["n"] = counts[host]["n"] + 1;   // {a: {n: 2}, b: {n: 1}}
}

let grid = [[1, 2], [3, 4]];
grid[0][1] = 9;                                  // [[1, 9], [3, 4]]
```

Two targets are refused, and both are compile errors rather than writes that go
nowhere:

- **A target with no variable under it** — `[1, 2][0] = 9`, `f()[0] = 1`. There
  is nothing to store the result in, so the write would land in a value the
  program immediately drops.
- **An index before the last one that is not a name or a literal** —
  `a[f()][0] = 1`. Every hop but the last is loaded again on the way back out,
  so anything with a side effect would run a number of times the source does not
  say. Bind it first: `let k = f(); a[k][0] = 1;`.

The last index is compiled once and is free to be anything, including a call.
The editor reports both refusals where they are written, under the
`assignmentTarget` rule.

**An assignment evaluates to the value assigned**, at any depth and through any
target — the same answer `x = 1`, `p.x = 1` and `x += 1` give:

```mutant
let grid = [[1, 2]];
let stored = (grid[0][1] = 9);   // 9, not [1, 9] and not [[1, 9]]
```

The parts of an assignment are evaluated in the order they are written: the
container, then the index, then the value. A compound assignment reads its
target before its right-hand side, because `x += v` is `x = x + v`.

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

**Total builtins currently registered: 493**, across 38 capability categories.

The complete catalog — every builtin with its typed signature, platform support, and description — lives in the **[Capability Reference](CAPABILITY_REFERENCE.md)**, which is generated directly from `builtin/metadata.go` by `cmd/gendocs` so it never goes stale. Regenerate it with `go run ./cmd/gendocs` after adding or changing a builtin; `go run ./cmd/gendocs -check` (and the `cmd/gendocs` test) fails if it has drifted. The categories are indexed below; each links into that reference.

| Category | Count | What it covers |
| --- | --- | --- |
| [Standard library](CAPABILITY_REFERENCE.md#standard-library-59) | 59 | Core primitives, collection/hash ops, higher-order functions (including parallel `pmap`/`peach`), I/O, introspection |
| [Testing](CAPABILITY_REFERENCE.md#testing-10) | 10 | `test`/`before_each`/`after_each` and the assertions `mutant test` reads |
| [Concurrency](CAPABILITY_REFERENCE.md#concurrency-8) | 8 | Background tasks (`spawn`/`task_wait`) and channels for passing values between them |
| [Strings](CAPABILITY_REFERENCE.md#strings-18) | 18 | Rune-aware string manipulation |
| [Text analysis](CAPABILITY_REFERENCE.md#text-analysis-14) | 14 | Search, split/replace, regex, fuzzy matching |
| [Structured data](CAPABILITY_REFERENCE.md#structured-data-46) | 46 | JSON, encoding, compression, type/base conversion, plist |
| [Math](CAPABILITY_REFERENCE.md#math-5) | 5 | Constants and random helpers |
| [Hashing](CAPABILITY_REFERENCE.md#hashing-11) | 11 | Digests, HMAC, UUID/ID generators |
| [Time](CAPABILITY_REFERENCE.md#time-7) | 7 | Unix timestamps, formatting, parsing, arithmetic |
| [Bytes](CAPABILITY_REFERENCE.md#bytes-31) | 31 | Binary buffer read/write, cursor, slicing |
| [Archives](CAPABILITY_REFERENCE.md#archives-10) | 10 | ZIP and TAR containers: entry listing, reading, and guarded extraction |
| [Filesystem](CAPABILITY_REFERENCE.md#filesystem-20) | 20 | Files/dirs plus file-level forensics (hash, entropy, magic, carve, deleted) |
| [Network](CAPABILITY_REFERENCE.md#network-33) | 33 | Sockets, TLS/CA, HTTP inspection, WebSocket, scanning, pcap |
| [Http](CAPABILITY_REFERENCE.md#http-11) | 11 | HTTP client + request/response parse/build |
| [Graph database](CAPABILITY_REFERENCE.md#graph-database-14) | 14 | Nodes/edges/relations, traversal, pathfinding, stats |
| [Cache](CAPABILITY_REFERENCE.md#cache-8) | 8 | In-memory key/value cache with TTLs |
| [Policy](CAPABILITY_REFERENCE.md#policy-5) | 5 | Allow/deny policy evaluation and tracing |
| [Runtime integration](CAPABILITY_REFERENCE.md#runtime-integration-3) | 3 | Sandboxed Lua execution |
| [Command execution](CAPABILITY_REFERENCE.md#command-execution-4) | 4 | Guarded external command execution |
| [Cryptography](CAPABILITY_REFERENCE.md#cryptography-6) | 6 | X.509, JWT, PEM, AES-GCM |
| [Fingerprinting](CAPABILITY_REFERENCE.md#fingerprinting-4) | 4 | imphash, JA3, NT/LM hashes |
| [Network intelligence](CAPABILITY_REFERENCE.md#network-intelligence-11) | 11 | IOC defang/refang, IP/CIDR, domain/eTLD+1, IOC extraction |
| [Detection](CAPABILITY_REFERENCE.md#detection-5) | 5 | Injection, beaconing, persistence, priv-esc, suspicious files |
| [Process forensics](CAPABILITY_REFERENCE.md#process-forensics-9) | 9 | Live process inspection, memory scan, modules |
| [Memory forensics](CAPABILITY_REFERENCE.md#memory-forensics-7) | 7 | Memory-dump analysis, PE/shellcode discovery |
| [Binary analysis](CAPABILITY_REFERENCE.md#binary-analysis-14) | 14 | PE/ELF/Mach-O/DWARF, imports, GoReSym |
| [Reporting](CAPABILITY_REFERENCE.md#reporting-7) | 7 | Build a report as a value, render it as HTML, Markdown or CSV, write it out with its digest |
| [Chain of custody](CAPABILITY_REFERENCE.md#chain-of-custody-10) | 10 | Case session, evidence record, drift verification, signed manifest, the handover bundle |
| [Registry forensics](CAPABILITY_REFERENCE.md#registry-forensics-15) | 15 | Hive/JSON/live registry, Amcache, Shimcache |
| [Filesystem forensics](CAPABILITY_REFERENCE.md#filesystem-forensics-37) | 37 | NTFS/FAT/exFAT/ext/HFS+/XFS parsers, $MFT |
| [Disk image forensics](CAPABILITY_REFERENCE.md#disk-image-forensics-20) | 20 | Raw/EWF/VHD(X) images, MBR/GPT tables |
| [Windows artifacts](CAPABILITY_REFERENCE.md#windows-artifacts-5) | 5 | Prefetch, EVTX, LNK, Jump Lists |
| [Unix artifacts](CAPABILITY_REFERENCE.md#unix-artifacts-1) | 1 | syslog (RFC 5424 / 3164) |
| [Browser artifacts](CAPABILITY_REFERENCE.md#browser-artifacts-5) | 5 | Chromium/Firefox history/cookies/downloads, SQLite |
| [Forensic timeline](CAPABILITY_REFERENCE.md#forensic-timeline-5) | 5 | Timestamp normalize, merge/sort, bodyfile/mactime |
| [Schema interchange](CAPABILITY_REFERENCE.md#schema-interchange-7) | 7 | One event vocabulary for every artifact, written out as ECS, OCSF or Timesketch/plaso; indicators written out as STIX 2.1 |
| [Email forensics](CAPABILITY_REFERENCE.md#email-forensics-5) | 5 | Header/body/attachment parsing, DKIM verification |
| [Hash-set forensics](CAPABILITY_REFERENCE.md#hash-set-forensics-3) | 3 | NSRL-style known-file filtering |

### Platform support

Almost every builtin is pure-Go and cross-platform — the forensic parsers operate on *captured* artifacts, so they run on any host. A few live-system builtins are platform-restricted and fail honestly elsewhere; the language server warns when you call one on an unsupported OS:

- `process_memory_scan` — Windows, Linux
- `process_modules` — Windows, Linux
- `reg_open` — cross-platform for hive-file/JSON inputs; the live-registry path (`HKLM\...`) is Windows-only
- `process_kill` — cross-platform; on Windows only SIGKILL semantics apply

### When more than one partition table is true

`table_open` answers with one table. Several kinds of media have more than one,
and the difference between them matters enough that the language makes the
script say which answer it wants.

```mutant
let seen, err = table_detect("/evidence/laptop.dd");
putln(seen["table_type"]);                   // "gpt" — what preference order picks
putln(to_string(seen["ambiguous"]));         // true  — it was a choice, not a reading

let tables, err = table_open_all("/evidence/laptop.dd");
for (t in tables) {
  putln(t["table_type"] + ": " + to_string(t["partition_count"]) + " rows");
}
```

**Four openers, because there are four defensible answers.** `table_open`
resolves by a documented preference order and records every candidate it passed
over. `table_open_strict` refuses instead, naming each candidate and the one
preference would have returned. `table_open_as(image, scheme)` forces one of
`mbr`, `gpt`, `bsd`, `sun` or `mac`, which is how an examiner records having
decided rather than accepted a default. `table_open_all` returns a handle per
scheme, and is the one a hybrid disk needs: an MBR that carries both the 0xEE
protective record and real entries describes partitions that GPT does not, and
`table_open` — which must answer with one table — leaves them reachable by no
other route. `table_detect` asks the same question without opening anything, so
a script that only wants to know what an image is has no handle to release.

**A warning is a code, not a sentence.** Every entry in `warnings` carries
`code`, `message` and the `lba` it was found at, and `warning_codes` is the set
of codes without the loop. The codes are `overlap`, `out_of_bounds`,
`block_size_overridden`, `entry_count_truncated`, `hybrid_mbr`, `crc_skipped`,
`backup_used`, `backup_missing`, `backup_mismatch` and `nested`. Branch on the
code. The prose beside it is written for a report and is reworded between
library releases, so a check that matches the prose stops matching without ever
saying that it has stopped.

**`gpt_backup` is a tamper indicator, not a health check.** The two GPT copies
are written together, so `mismatch` — both structurally valid, disagreeing on
the disk GUID, the usable range or the entry-table checksum — means one was
rewritten without the other, which no ordinary partitioning operation does.
`missing` is the secondary being absent or failing its own checks, expected on a
truncated or carved image and not on a full acquisition. `unknown` means the
question did not apply: the table is not GPT, or was itself recovered from the
backup.

**The listing maps the device, not only its volumes.** Every row says what it
is: `allocated` is a partition, `unallocated` is a gap, `meta` and `structure`
are the table's own sectors — the MBR, each EBR, both GPT headers and entry
arrays, a disklabel. A script that hands every row to `fat_open` is handing it
GPT headers and interior gaps. `occupies_space` marks the rows that tile the
device exactly once, so summing `length_byte` over them accounts for every byte
of the image and summing the unallocated ones is summing space that is genuinely
free. Meta rows without `structure` are containers — an MBR extended entry, a
Sun whole-disk backup slice — which span the extents they hold and would
double-count.

**A scheme can live inside a partition of another one.** A BSD disklabel in an
MBR 0xA5 slice is the case that occurs in practice, and it is the partition
table the examiner is actually after; the MBR entry is only the container. Every
parse looks for one, the slice that holds it reports `has_nested` and
`nested_type`, and `table_nested(handle, index)` returns it:

```mutant
let sub, err = table_nested(disk["handle"], 0);
for (p in sub["partitions"]) {
  putln(to_string(p["start_byte"]));   // absolute within the image
}
```

Those offsets are computed by the inner table, which is the only thing that
knows which convention the label was written with: real installers write
disklabel addresses both relative to the slice and absolute on the disk, and the
parse reports through `warnings` when it had to fall back to the second.
Multiplying `start_lba` by `block_size` is correct under neither. A partition
that holds no nested scheme is an error rather than an empty listing, since an
empty listing reads as a container that held nothing — `has_nested` is how to
ask first.

### Opening a partition where it lies

A disk image holds partitions; a filesystem parser wants a volume. Those two
facts used to meet by carving: `table_list_partitions` told you a partition
began at byte 32256, and you wrote a copy of it out before `ntfs_open` could
read it. On a 2 TB image that is a second 2 TB and the hours to write it.

The six filesystem families take the partition directly instead:

```mutant
let disk, err = table_open("/evidence/laptop.dd");
let parts, err = table_list_partitions(disk["handle"]);

let fs, err = ntfs_open("/evidence/laptop.dd", parts[0]);
putln(to_string(fs["volume_offset"]));   // 32256 — where the volume begins
putln(to_string(fs["bounded"]));         // true  — reads stop at its end
```

The second argument is that partition hash, or an explicit byte offset with an
optional length:

```mutant
let fs, err = ntfs_open("/evidence/laptop.dd", 32256, 2147483648);
```

Four things are worth knowing about it.

**Every offset the handle goes on to report is absolute within the image.** The
partition's start is handed to the parsing library as a base offset, and the
library adds it to every offset it reports — a file fragment's location, a
carved record's position, a slack range. So a byte range from
`table_list_partitions` and a byte range from `ntfs_metadata` are in the same
coordinate system, and comparing them needs no arithmetic. This is not a
convenience. The alternative — reading the partition through a window that
starts at its first byte — produces offsets relative to the partition that look
exactly like offsets relative to the image, and intersecting the two succeeds
and is wrong. Four of the six libraries warn about that failure in their own
documentation, independently, which is a good sign that it is the one worth
designing against.

**A partition hash is safer than two integers, and not only shorter.** It
carries `start_byte` and `length_byte` together, so the two cannot be
transposed, the length cannot be forgotten, and no line of the script performs
arithmetic on an offset. Passing a third argument alongside a partition hash is
an error rather than an override: the partition already said how long it is.

**`bounded` is the difference between a volume and a starting point.** An open
with no length reports `bounded: false`, and means it — reads can run past the
end of the partition into whatever follows it on the disk and return those bytes
as this volume's. With a length, they cannot. A report that quotes a file
recovered from a filesystem should be able to say which of the two it was.

**A partition the image does not contain is refused, by name.** A zero-length
entry is a malformed partition table, and opening it unbounded would read the
rest of the disk and attribute it to that partition; a partition that runs past
the end of the file is what a truncated acquisition looks like from the inside.
Both refuse and say both numbers, rather than opening something that fails later
somewhere less informative.

**The case manifest records which volume, not only which file.** Two
partitions of one disk are two volumes and one path, so every open record
carries `volume_offset` and `volume_length` alongside the builtin and the
handle. Both are zero for an opener that reads a whole file, which is every
opener outside these six — the fields are always there, so a report template
that prints them never meets a record that lacks them.

Opening with one argument is unchanged, and is still what a carved partition
image wants: offset zero, no bound, the file is the volume.

### Reading a file that does not fit in memory

`ntfs_read_file_bytes` and its five siblings return the whole file as one
value, so the size of the file is the size of the allocation. That is the right
shape for a registry hive or a log, and the wrong shape for a disk image inside
a disk image. Each of the six families therefore also carries three builtins
that never hold the file at all.

```mutant
let fs, fsErr = ntfs_open(disk, parts[2])

// Written to disk a megabyte at a time, and digested on the way past.
let out, outErr = ntfs_extract_file(fs["handle"], "/Users/j/vault.vhdx", "vault.vhdx")
putln("wrote " + to_string(out["bytes_written"]) + " bytes, sha256 " + out["digest"])

// Or digested where it lies, with nothing written anywhere.
let known, knownErr = ntfs_hash_file(fs["handle"], "/Windows/System32/cmd.exe", "sha256")

// Or just the head of it, to find out what it is.
let magic, magicErr = ntfs_read_file_at(fs["handle"], "/Users/j/vault.vhdx", 0, 512)
```

**The peak allocation has nothing to do with the size of the file.** All three
read in fixed chunks through the random-access API every one of the six
libraries exposes. `*_extract_file` has no size limit at all; `*_read_file_at`
is capped at 32 MiB because that is what the returned value has to fit into, and
the refusal names `*_extract_file` as the way to get the rest.

**`size` and `located_bytes` are two different numbers, and all three builtins
report both.** `size` is what the volume records — the directory entry's field,
or the inode's. `located_bytes` is how many of those bytes the library could
actually find. They come apart on a FAT or exFAT entry whose cluster chain was
broken when the file was deleted: the entry still records the original length,
and only a prefix of it leads anywhere. The clusters after that prefix still
hold bytes; those bytes belong to whatever was written there since.

**So a read stops at `located_bytes`, and `truncated` says that it did.** An
extraction of a broken chain writes the recoverable prefix and reports
`truncated: true` — writing nothing would throw away evidence, and writing the
whole recorded length would return one file's content under another file's name.
A window that begins past what was located is refused, naming both numbers,
because a short buffer or a run of zeroes there is the same call quietly
succeeding.

**The digest covers what was read, never what was claimed.** `*_extract_file`
computes the SHA-256 of the bytes it wrote during the same pass, so nothing has
to read the extracted copy back to obtain one. For a truncated chain that digest
is the digest of the prefix, which will not match a hash set entry for the
intact file. That is the honest answer; `truncated` is what makes it legible
rather than puzzling.

**An extraction never writes over an existing file.** Two files in one image can
carry the same name, and evidence written over by accident does not come back,
so the destination must not exist. A copy that fails part way has its partial
output removed and says so, because a prefix left under the name of the whole
file reads as the whole file to everything downstream.

`*_hash_file` takes `md5`, `sha1` or `sha256` — the same set `case_open`'s
custody policy accepts, so a digest in a manifest and a digest from a script are
never a different shape. An empty string means `sha256`.

### What a filesystem still remembers

Deleting a file destroys different things on different filesystems, and the
`*_deleted` family reports what survived rather than a verdict on whether the
file is recoverable.

```mutant
let fs, err = ntfs_open("/evidence/laptop.dd", parts[2]);
let gone, err = ntfs_deleted(fs["handle"]);

putln(to_string(gone["entry_count"]) + " records, " +
      to_string(gone["unreadable"]) + " unreadable");

for (e in gone["entries"]) {
  if (e["content_state"] == "preserved") {
    putln(e["path"] + ": " + to_string(e["located_bytes"]) +
          " of " + to_string(e["size"]) + " bytes located");
  }
}
```

**Two questions, never one.** Whether something was deleted here and whether
its bytes can be read are independent, and one `recoverable` boolean would
answer neither. Every entry carries `content_state`, the provenance of its byte
map, and that is what a script branches on before it reads anything:

| `content_state` | what it means |
| --- | --- |
| `resident` | the bytes are inside the metadata record itself |
| `preserved` | the filesystem's own map survived the unlink |
| `declared_contiguous` | the volume declared the run contiguous before deletion |
| `first_cluster_only` | only the starting cluster is known; the chain was freed |
| `none` | no map survives -- the file is described and cannot be located |
| `unsupported` | this library offers no content path for this entry |

`preserved` is the NTFS case and it is unusual: NTFS clears the in-use bit on
an MFT record and nothing else, so the run list is the one the filesystem
wrote. `none` is the ext4 case, which zeroes the extent tree on unlink.
`declared_contiguous` happens only on exFAT, where a stream extension carrying
NoFatChain is the volume stating the layout while the file was live -- freeing
the chain took nothing away, so it is a fact and not a hypothesis.
`first_cluster_only` is what FAT and exFAT report otherwise, and `located_bytes`
beside `size` is how much of the claim it covers.

**The two bits, again.** `allocation_checked` and `reallocated` are separate for
the reason `checked` and `passed` are separate in `*_verify`: a cross-reference
that never ran says nothing about the file. NTFS forces the distinction -- it
reports `allocation_checked` false on every entry, because libntfs exposes no
cluster-allocation query and there is no answer to give. `reallocated` false
beside it means nobody looked.

**A name can be partly invented.** `name_source` is `intact`, `reconstructed`,
`synthetic` or `none`. FAT overwrites the first character of a short name on
deletion and brute-forces it back out of the name checksum where it can,
substituting `_` where it cannot; exFAT gives a carved entry with no surviving
name a placeholder derived from its cluster number. Writing either into a
report as a filename is fabricating evidence, which is why the grade travels
with the name.

**An empty warning list is not silence.** `warnings_available` says whether the
library has a warnings channel at all. libext accumulates warnings, libhfs
anomalies, libxfs per-listing anomalies -- libntfs and libfat have none, so a
record they skipped leaves no trace anywhere and their scans report
`warnings_available` false. `complete` and `incomplete_reason` carry the gaps
that could be detected; `examined` and `unreadable` are the denominators,
because a scan that looked at two hundred slots and one that looked at two
million are not the same evidence for the same empty answer.

**`confidence` is the library's own word, not a common scale.** ext grades
`none`/`partial`/`likely`, HFS+ and XFS grade `low`/`medium`/`high`, and NTFS
and FAT grade nothing because they compute nothing to grade. Quoting the parser
is deliberate -- a single invented scale would read as a measurement. The fields
that do mean the same thing on every filesystem are `content_state`,
`allocation_checked`, `reallocated`, `name_source` and `located_bytes`.

**XFS asks two questions and they are different builtins.** `xfs_deleted` takes
a directory path, because libxfs recovers deleted names out of one directory's
blocks and has no volume-wide sweep; scanning the root instead would be a claim
about every directory made from evidence about one. Nothing it finds has
content: XFS clears `di_mode` when it frees an inode and refuses to open an
unallocated one. `xfs_unlinked` is the other question, and it is the only
evidence in any of the six filesystems that the filesystem itself asserts --
an inode reaches an AGI unlinked bucket because it was unlinked while a process
still held it open, so it is still allocated, still readable, and its extents
are live rather than stale. It carries no name, because the directory entry is
already gone.

### Writing the bytes back out

`*_deleted` enumerates; `*_recover_file` writes. They are separate calls rather
than one builtin with a destination argument, because `content_state` is what
decides whether the output is worth anything and a script has to have seen it
before it produces a file somebody will hash and attach.

```mutant
let fs, err = fat_open("/evidence/card.dd", parts[0]);
let gone, err = fat_deleted(fs["handle"]);

for (e in gone["entries"]) {
  if (e["content_state"] == "none") { continue; }

  let out, err = fat_recover_file(fs["handle"], e["index"],
                                  "/out/" + e["name"]);
  if (err) { putln(e["name"] + ": " + err.message); continue; }

  putln(e["name"] + ": " + to_string(out["bytes_written"]) + " of " +
        to_string(out["size"]) + " bytes, sha256 " + out["digest"]);
  for (c in out["caveats"]) { putln("  -- " + c); }
}
```

**An entry is named by its index, not by an identifier.** Each scanned entry now
carries `index`, its position in that scan, and that is the only thing the
recovery builtins take. No identifier these six filesystems keep survives
deletion uniquely: a CNID repeats across records HFS+ carves out of node slack,
and FAT and exFAT keep none at all and report their first cluster, which two
deleted files share the moment it is reused. The index is exactly as stable as
the scan it came from, which is the honest scope of the claim -- and the result
echoes `name`, `path` and `record_id` so a script can assert it recovered what
it meant to.

Recovering before scanning is an error rather than an implicit scan. The
enumeration is where an entry's provenance is established, and an implicit one
would leave no record of it in the manifest.

**Three kinds of zero, counted apart.** `bytes_written` splits into
`located_bytes`, read from the image at a run's offset; `sparse_bytes`, a hole
the filesystem recorded, where the zeros are the file's own content; and
`unlocated_bytes`, ranges no locatable run covers. The last are written -- the
file has to be that long for the offsets after them to land -- and they are
never evidence that the file held zeros there. A single "could not read" number
would let a report present a library's failure to place a run as content.

**The contiguity hypothesis has its own builtin.**
`fat_recover_file_assuming_contiguous` and
`xfat_recover_file_assuming_contiguous` ask the library to synthesise
`ceil(size / cluster)` clusters following the first, which is what recovers a
FAT file whose chain was freed. It is a separate builtin and not a flag so that
a caller has to say the word at the call site. What comes back in `assumed` is
the library's own answer, not the argument that was passed: an entry whose
chain turned out to be walkable, or an exFAT entry that recorded NoFatChain,
needed no hypothesis and reports `assumed` false. When `assumed` is true,
nothing in the filesystem connects those bytes to that file beyond their
position, and `content_state` says `assumed_contiguous` rather than borrowing
one of the six words a scan uses.

**`caveats` is part of the result, not commentary on it.** Every entry in it is
derivable from the other fields, and that is the point -- the prose an examiner
would have to write by hand is the prose that gets left out. It names an
assumed layout, blocks a live file now owns, an allocation nobody checked, the
zeros that are not content, a directory recovered as though it were a file, a
name that was reconstructed or invented, and a write shorter than the size the
record claimed. A report quoting `digest` without `caveats` is quoting a number
out of its scope.

`size_matched` rather than `complete`: one builtin away, on the scan the
entry came from, `complete` says the enumeration was not cut short. A
recovery made entirely of assumed clusters can write exactly as many bytes
as the record claimed, and `complete` beside it would read as a verdict on
the recovery instead of an observation about two numbers.

**What each filesystem can actually give back.** `ntfs_recover_file` reads the
map NTFS itself wrote; a resident value comes from the parsed MFT record and is
never re-read from the image, because the record carries update-sequence fixups
and a resident value crossing a sector boundary read off the disk is quietly
two bytes wrong. A compressed or EFS-encrypted stream is refused rather than
written, since its runs describe compression units or ciphertext.
`ext_recover_file` works only where the extent tree survived, which on ext4
means files unlinked while still open. `hfs_recover_file` uses the eight
extents held in the catalog record and nothing that overflowed into the extents
B-tree. `xfs_recover_file` recovers from an unlinked chain and nothing else --
an entry from `xfs_deleted` reports `unsupported` and is refused.

A destination that already exists is never written over: two deleted entries in
one image can carry the same name, and evidence overwritten by accident is not
recoverable. A write that fails part way has its partial output removed, because
a prefix left under the name of the whole file reads as the whole file.

### What the filesystem wrote down before it did it

Everything above reads a filesystem as a statement about the present. A journal
is the one structure that is a statement about the past, and three of the six
formats keep one.

```mutant
let fs, err = ntfs_open("/evidence/disk.raw", parts[0]);
let usn, err = ntfs_usn_journal(fs["handle"]);

if (!usn["present"]) {
  putln("no change journal on this volume");
}

for (r in usn["entries"]) {
  if (!r["has_timestamp"]) { continue; }
  putln(r["timestamp"] + "  " + r["name"] + "  " + to_string(r["reasons"]));
}
```

| builtin | what it reads |
| --- | --- |
| `ntfs_usn_journal` | the USN change journal: timestamps, filenames, reason flags |
| `ntfs_log_records` | `$LogFile`'s operation stream, by LSN |
| `ntfs_log_transactions` | the same records grouped into transactions |
| `ext_journal` | JBD2's transactions, its superblock and its feature bits |
| `ext_journal_block_copies` | every journalled copy of one filesystem block |
| `ext_journal_inode_versions` | prior on-disk states of one inode |
| `ext_recover_journalled_file` | the bytes a journalled version points at |
| `xfs_log_records` | XLOG's records, by log sequence number |
| `xfs_log_transactions` | the same records grouped into transactions |

FAT, exFAT and HFS+ have none here. libhfs exposes no journal API at all, so
HFS+'s journal is not read even though the format has one -- which is a gap in
the library, not a statement about the format.

**Circularity is the fact everything here turns on.** All three journals are
fixed regions written round and round, so the order records sit in is the order
they happened in only until the writer laps itself. Every scan therefore reports
`ordering`:

- `lsn` -- sorted by log sequence number, which is the order of events
- `stream` -- the order of an append-only stream, which is also the order of
  events, because nothing was overwritten in place
- `physical` -- the order records sit in the region, which is **not** the order
  of events once the region has been written round

and beside it the two bits. `wrap_checked` says whether the scan could look for
the seam; `wrapped` says whether it found one. They are separate for the same
reason `allocation_checked` and `reallocated` are separate: a check that never
ran is not a negative result.

**Where `wrapped` is true and `ordering` is `physical`, the entries array is not
a timeline.** Mutant does not reorder it. An order the library declined to
establish is not one this package gets to assert on its behalf; what it does
instead is say the seam is there and leave the claim unmade.

**libext is where that stops being academic.** Its transaction walk reads the
journal linearly from the first block to the last, parses the superblock's
`Start` and `Sequence` and then uses neither, so a wrapped journal interleaves
stale pre-wrap transactions among new ones. The same wrap creates a second
trap: a transaction whose commit block sits at a *lower* physical block than its
descriptor has its commit processed first, matched against nothing, and
discarded -- so a transaction that did commit is reported as one that never
did. `ext_journal` raises `commit_state_unreliable` when it sees the seam,
because `committed: false` is otherwise read as evidence that an operation
failed to complete.

**`timestamps_available` is per journal, not per format.** USN records carry a
wall-clock time; JBD2 carries one on the commit block, so a transaction that
never committed has none rather than a zero one; `$LogFile` carries none; XLOG
carries none at all. An XFS log can say what happened and in what order, and can
never say when -- a sequence assembled from it is an ordering, and calling it a
timeline is the mistake this field exists to prevent.

**What none of the three can report is what it skipped.** libntfs has no
warnings channel anywhere, and its log page walker drops an entire page -- and
the partial record carried into it -- when the update-sequence fixups fail. A
fixup failure is a torn write, which is the most forensically interesting thing
a log page can hold, and it is discarded with no counter and no error: a
`$LogFile` whose every page failed and a pristine one both produce zero records
and no error. libext reports unreadable journal blocks through a channel capped
at 256 for the life of the handle. libxfs raises a coded anomaly at every
failure point and is the only one of the three that does.
`warnings_available` says which of those three a reader is in, and an empty
warnings list means nothing at all when it is false.

**`ntfs_usn_journal` is the richest timeline artifact on a Windows volume**, and
its blind spot is worth naming. `$J` is a sparse stream appended to and trimmed
from the front, so its surviving records are a contiguous window ending at the
most recent change and `lowest_position`/`highest_position` bound it in USN --
itself a byte offset into the stream. What it cannot see is a journal deleted
and recreated, a classic anti-forensic action: the `$Max` stream holding the
journal's identifier, maximum size and lowest valid USN is one libntfs never
reads, so a wiped journal looks like a volume with a short history.

Version 4 USN records track extents rather than names and carry neither a
timestamp nor a filename. They report `has_timestamp` and `has_name` false
rather than a year-1 date and an empty string, because a zero time rendered into
a timeline sorts before every real event in it.

**`ntfs_log_transactions` reports `committed` and `forgotten` as two bits**, and
neither is the negation of the other. NTFS ends almost every transaction with
`ForgetTransaction` rather than `CommitTransaction`, so a log holding tens of
thousands of records may contain no commit record at all: `committed: false`
across a whole volume is the normal reading rather than a finding, and
`end_state` is the field a report should quote. `start_present` reports whether
a transaction's earliest surviving record names no previous record of its own --
where it is false, the beginning was overwritten by the wrap and `first_lsn` is
merely the oldest surviving part, which the grouping otherwise presents as the
beginning.

### Getting back what ext4 zeroed

`ext_journal_inode_versions` is the one path in the language that can locate an
ext4 file the filesystem itself can no longer locate.

Unlink zeroes the extent tree in the live inode and leaves everything else,
which is why the usual deleted ext4 file comes back from `ext_deleted` fully
described and entirely unfindable, with `content_state` `none`. A journalled
copy of the same inode-table block from before the unlink still carries the
tree.

```mutant
let fs, err = ext_open("/evidence/disk.raw", parts[1]);
let gone, err = ext_deleted(fs["handle"]);

for (e in gone["entries"]) {
  if (e["content_state"] != "none") { continue; }

  let past, err = ext_journal_inode_versions(fs["handle"], e["record_id"]);
  if (err) { continue; }

  for (v in past["entries"]) {
    if (v["content_state"] != "preserved") { continue; }

    let out, err = ext_recover_journalled_file(fs["handle"], e["record_id"],
                                               v["version"], "/out/" + e["name"]);
    if (err) { putln(err.message); continue; }
    putln(e["name"] + ": " + to_string(out["bytes_written"]) + " bytes from " +
          "journal version " + to_string(v["version"]));
    break;
  }
}
```

Each version reports `content_state` in the same vocabulary `*_deleted` uses and
`runs` as image-absolute byte ranges, so a version reporting `preserved` can be
read with `raw_read_at_bytes` or written out with `ext_recover_journalled_file`,
which returns the same result shape the `*_recover_file` family does -- the same
three-way split of `bytes_written`, the same `caveats`, the same digest.

**`version` is an index, not a date.** libext orders the versions newest first,
and that holds only while the journal has not been written round, which is
exactly why `ext_journal_inode_versions` pays for a second journal walk to
establish `wrapped`. Where the seam is present, version 0 is the most recent
*surviving* copy and not necessarily the state just before the deletion, and the
recovery result echoes the version index so that a report cannot quietly become
a claim about when.

`deleted_at_raw` is carried beside `deleted_at` because ext4 reuses the
deletion-time field to hold the next inode number while an inode sits on the
legacy orphan list. Inode 11, read as a date, is a timestamp eleven seconds
after the epoch.

Two limits are worth stating before anything is quoted from a journalled copy.
Revoke records are precisely the statement that a journalled copy must not be
replayed, and libext identifies them without parsing them, so a copy cannot be
shown *not* to have been revoked. And the filesystem reallocated those blocks
freely after the unlink -- nothing here checks whether they still hold the
file's content, which is why the recovery carries that caveat whether or not
anyone reads it.

### The bytes a file owns and never wrote

A file rarely fills its own allocation. The filesystem hands out whole clusters
or blocks, and what the file does not use is still there, still holding what the
last occupant left. Two different things get called slack in this field and
Mutant refuses to merge them, because they are found in different places and
mean different things about what someone did:

| class | where it is | what it means |
| --- | --- | --- |
| `file_slack` | past the recorded size, inside the allocation | the tail of the last unit; the classic slack |
| `unwritten` | inside the recorded size, allocated, never written | space reserved and skipped; reads back as zeros |

```mutant
let img, err = raw_open("/evidence/disk.raw");
let fs, err = ntfs_open("/evidence/disk.raw", parts[0]);
let s, err = ntfs_slack(fs["handle"], "/Users/mal/report.docx");

if (!s["file_slack_checked"]) {
  putln("slack not established: " + s["incomplete_reason"]);
}

// Offsets are into the image, not into the file, so the bytes come back
// through the image handle rather than through the filesystem.
for (r in s["ranges"]) {
  if (r["offset"] < 0) { continue; }
  let bytes, err = raw_read_at_bytes(img["handle"], r["offset"], r["length"]);
  putln(r["class"] + " @ " + to_string(r["offset"]) + "  " + hex_encode(bytes));
}
```

| builtin | what it reports |
| --- | --- |
| `ntfs_slack` | the cluster tail, and the `InitializedSize` gap |
| `fat_slack` | the cluster tail |
| `xfat_slack` | the cluster tail, and the `ValidDataLength` gap |
| `ext_slack` | the blocks past the end of the file, and preallocated extents |
| `hfs_slack` | slack on every extent of the data fork, not only the last |
| `xfs_slack` | the block tail, and unwritten extents |
| `ext_dir_slack` | directory records surviving in a directory's own slack |
| `hfs_unallocated` | the runs of a volume that belong to no live file |

Every range carries its `class`. A valid-data-length gap quoted in a report as
"slack" is a false statement about where the bytes came from, and `class` is
what stops a script making it.

**Two levels of "we did not look", and they answer different questions.**
`classes` and `classes_unavailable` are about the library: FAT records no
valid-data length at all, so `fat_slack` reports `unwritten` as unavailable on
every file, for ever. `file_slack_checked` and `unwritten_checked` are about
*this* file, and where one is false its byte count is `-1` rather than `0`,
because zero is an answer and this is not one.

That second pair exists because of what FAT does. `SlackRange` returns the same
empty result and `false` from five different situations -- a directory, an empty
file, a chain that could not be walked, a file ending exactly on a cluster
boundary, and a tail falling past the end of the volume -- and only the fourth
means the file has no slack. So Mutant walks the chain itself and says which of
the five it is, naming a reallocated first cluster, a broken chain or a loop in
the warnings.

**What these cannot reach.** They address a live file by its path, and a deleted
entry cannot be opened by one -- the listers return its name and the openers
refuse it. The slack of a deleted file is the most valuable slack there is, and
getting at it needs the scan index the `*_deleted` family hands out, which this
family does not take. Four of the six libraries could answer for a deleted entry
if it did: NTFS keeps the whole run list and both sizes through an unlink, exFAT
keeps the layout of an entry it had declared contiguous, libhfs carries fork
extents on a carved catalog record, and an XFS inode on an unlinked chain is
still allocated and still readable. FAT and ext could not -- the chain is freed
and the extent tree zeroed.

Directories divide the two FAT libraries. libxfat reports directory slack and
calls its sibling's refusal a deliberate divergence, because directory cluster
slack is where deleted directory records survive. `fat_slack` therefore reports
a directory as unchecked rather than as empty.

**Two of the six libraries have no slack API at all and are computed here.**
NTFS slack comes from `AllocatedSize`, `RealSize` and `InitializedSize` on the
non-resident `$DATA` attribute, located through its run list -- including the
whole clusters past the end of the stream that `Fragments` drops and a file
truncated in place still owns. It is refused rather than guessed on a compressed
stream, whose runs map compression units rather than stream bytes, and on a
sparse one, whose allocated size is *smaller* than its recorded size so their
difference is not a tail. ext slack is the difference between `Extents`, which
keeps the blocks past the end of the file, and `DataRuns`, which trims to the
recorded size.

Offsets are image-absolute and carry the base offset of the partition the volume
was opened at, so a slack range from a FAT volume and one from an ext volume
elsewhere in the same image are directly comparable. An offset of `-1`, never
`0`, means the range has no location -- and every counted byte still gets a row,
so a total never floats free of the ranges behind it.

#### Two things that are not file slack

`ext_dir_slack` reads a different artifact entirely. Unlinking a file does not
erase its directory record: the preceding record's `rec_len` is extended to
swallow it, leaving the old record intact in the gap. On ext4 that is frequently
the only surviving evidence a name existed, because unlink also zeroes the
inode's extent tree. Each record is reported at two positions -- `dir_offset`
inside the directory's own data stream, which is all libext gives, and `offset`
on the image, which Mutant maps through the directory's data runs because
nothing in libext does and a finding nobody can re-read is not one.

Every name there is a candidate: the record is real, but the inode it names may
since have been reused. Records that duplicate a live entry are kept and flagged
through `shadows_live` rather than dropped -- `ext_deleted` filters them out and
this deliberately does not, because a directory rewrite leaving copies behind is
itself worth seeing. Two limits libext does not report: a record whose inode
field was *cleared*, which is the classic ext2 and ext3 unlink marker, is never
recovered, and a block with an implausible record length is abandoned from that
point on in silence.

`hfs_unallocated` answers a volume-level question rather than a file-level one,
and it is the only free-space traversal available anywhere in these six
libraries -- the others offer a per-cluster or per-block query, a raw bitmap, or
a count the volume merely claims. It reports `free_blocks`, counted bit by bit,
beside `free_blocks_claimed`, which is what the volume header records, because
they are different kinds of statement: `claim_matches` false means the volume
was not unmounted cleanly or its metadata is inconsistent, and that is worth
knowing before anything carved out of that space is relied on. A free block is
not a statement that anything was ever written there. Blocks still claimed by a
deleted file are not free and do not appear -- `hfs_deleted` is what finds
those.

### The content a path does not name

A file's bytes are not all of a file. Every format here lets one carry content
and metadata that its path does not address and that a directory listing does
not show, reached instead by a *pair* -- the path **and** a name. NTFS calls the
content an alternate data stream; HFS+ calls it a resource fork; ext, XFS and
HFS+ all carry labelled values called extended attributes; NTFS carries a
security descriptor and a reparse point besides. A tool that walks a volume by
path alone sees none of it, which is exactly why things get put there.

Two kinds of thing, and they are not merged:

| | What it is | Where it is |
| --- | --- | --- |
| **A named body of bytes** | A second stream of content, with a length and a place on the image. It can be read out and hashed like any file. | `ntfs_streams`, `ntfs_read_stream`, `ntfs_extract_stream`, `hfs_resource_fork` |
| **A label** | A small value attached to a file that asserts something *about* it. It holds no file content. | `ext_xattrs`, `xfs_xattrs`, `hfs_xattrs`, `ntfs_security`, `ntfs_security_descriptors`, `ntfs_reparse` |

The label is frequently the more useful of the two. A `Zone.Identifier` stream
on a downloaded executable records the URL it came from and the security zone
Windows assigned it; `com.apple.quarantine` records the same thing on macOS. No
amount of reading the executable itself produces either.

```mutant
let fs, err = ntfs_open("evidence/c.img")

// what the path addresses, and what it does not
let streams, streamsErr = ntfs_streams(fs["handle"], "/Users/j/Downloads/setup.exe")
putln(to_string(streams["alternate_count"]) + " alternate stream(s)")

for (s in streams["streams"]) {
  if (!s["is_alternate"]) { continue; }
  putln("  " + s["name"] + "  " + to_string(s["size"]) + " bytes")

  // a label is small enough to read in place; a payload is not
  if (s["size"] < 4096) {
    let raw, readErr = ntfs_read_stream(fs["handle"],
      "/Users/j/Downloads/setup.exe", s["name"], 0, s["size"])
    putln("    " + bytes_to_string(raw))
  } else {
    let out, extractErr = ntfs_extract_stream(fs["handle"],
      "/Users/j/Downloads/setup.exe", s["name"], "case/ads-" + s["name"] + ".bin")
    putln("    extracted " + to_string(out["bytes_written"]) + " bytes, sha256 " + out["digest"])
  }
}
```

An empty stream name selects the unnamed stream, which makes `ntfs_read_stream`
a superset of `ntfs_read_file_at`. Names are matched case-insensitively, as NTFS
matches them. A *directory* has no unnamed stream but can still carry named
ones, and `ntfs_streams` warns when it finds one: a directory has no content of
its own, so a stream on one was put there deliberately.

**An access control list is not an access decision.** This is the one place in
the family where rendering the obvious thing inverts the answer. A security
descriptor carrying **no DACL at all** grants *everyone* full access. A
descriptor whose DACL **is present and holds no entries** denies *everyone*.
Rendered as an empty array those two are the same value and mean opposite
things, so `ntfs_security` reports `dacl_present` as a field of its own,
separate from `dacl_ace_count` and from the array, and warns on both cases by
name.

```mutant
let sd, sdErr = ntfs_security(fs["handle"], "/Windows/System32/config/SAM")
if (!sd["dacl_present"]) {
  putln("no DACL: everyone has full access")
} else if (sd["dacl_ace_count"] == 0) {
  putln("empty DACL: nobody has any access")
}
putln("owner " + sd["owner_sid"] + " (" + sd["owner_name"] + ")")
```

No field answers whether a particular account *could* open the file. That needs
group memberships, privilege assignments and an inheritance walk which a disk
image does not contain, and a builtin that appeared to answer it would be
answering something else. `source` says where the descriptor came from, because
one stored on the entry belongs to that file alone while one resolved through
the entry's security ID is shared with every other file carrying that ID --
which matters when the finding is about a single file.
`ntfs_security_descriptors` reads the volume's whole `$Secure:$SDS` in one pass,
which is how you ask *which* descriptors on this image grant what, rather than
asking file by file.

#### Where each format keeps its attributes, and what that costs

`ext_xattrs`, `xfs_xattrs` and `hfs_xattrs` share one envelope, and each
attribute says which storage it came from, because the storage is evidence:
an inline value travels with the metadata record, a block or fork value lives in
allocation blocks and can outlive the record pointing at it.

Reading only one storage is the trap on ext, and libext's own documentation
names it. `GetXAttrs` follows the inode's external attribute block and nothing
else, returning an empty list with no error for an inode that has no such block
-- while `security.selinux` and `system.posix_acl_access` are small enough on a
typical modern system never to need one. A reader that follows only the block
reports a file carrying SELinux labels and POSIX ACLs as having no attributes at
all. `ext_xattrs` consults both and flags a name that appears in each, because
which one the kernel would return is not recorded on disk.

On XFS, libxfs performs no deduplication and says so: two records carrying the
same fully-qualified name both come back, which is an inconsistency in the
attribute fork rather than a rendering artifact, so it is counted and warned on.
XFS is also the one format here whose attribute values carry no location --
`offset` is `-1` throughout, because libxfs exposes the attribute fork's extents
nowhere a per-value offset can be derived from.

On HFS+, `com.apple.decmpfs` and `com.apple.ResourceFork` come back like any
other attribute and are flagged rather than filtered. That flag is the answer to
a question the previous section raises: `hfs_slack` reports a decmpfs-compressed
file's data fork as empty, and `com.apple.decmpfs` is *why*. Where the payload
actually went is `hfs_resource_fork`'s answer -- either that fork, or, when it
is small enough, inline in the attribute itself. The two cases are kept apart:
`holds_compressed_payload` is true only when the file is compressed **and** the
fork is not empty. The bytes are never decompressed on the way out, which is
libhfs's rule and the right one, because the compressed payload as stored is the
artifact.

A value is rendered as hex, capped, with its true length always reported, and
offered as text beside the hex where it is text -- one trailing NUL is trimmed
first, because the most common extended attribute on Linux stores a C string and
refusing to call that text would make the field useless where it is most wanted.
A value past the cap reports its length and, where the format supplies one, its
position, so the bytes stay reachable through `raw_read_at_bytes`. `supported`
is about the volume rather than the file: a filesystem without the attribute
feature, or a classic HFS volume with no attributes B-tree, can never carry one,
and that is a different claim from a file that carries none.

#### Two things a reparse point is not

`ntfs_reparse` decodes a target for the three tags that name one -- symbolic
links, mount points, and WSL symlinks, each with a different layout -- and hands
back the tag-specific bytes as hex for every other tag, which covers
deduplication, cloud placeholders, WOF-compressed files and whatever ships next.

It is **not** a file with no reparse point. `is_reparse_point` distinguishes an
ordinary file from one whose tag names no target this library decodes, and those
are different findings.

It is **not** followed. A directory carrying a reparse point lists its own
index, usually empty, rather than the target's, and whether the target exists is
not checked -- on an image of one volume it frequently cannot be.

### Reporting

An investigation ends in a report, not a stdout dump.

```mutant
let r, err = report_new("Laptop triage", {"examiner": "G. Gogia", "case_id": "IR-2026-0413"});
let r, err = report_text(r, "Two hosts beaconed to the same domain within four minutes.");
let r, err = report_section(r, "Indicators");
let r, err = report_table(r, iocs, {"columns": ["type", "value", "first_seen"]});

let page, err = report_render(r, "html");          // the document as a string
let wrote, err = report_write(r, "case.html");    // or straight to disk
putln(wrote["sha256"]);
```

The report is a plain hash — a title, a `generated` stamp and a list of
sections — so it can be JSON-encoded, stored, diffed against the last one, or
written by hand without going through the builders at all. Every builder returns
a new document rather than changing the one it was given, so a report can be
branched: two summaries over one body of findings do not interfere.

`generated` defaults to now and is the only thing in the document that cannot be
derived from the rest of it, so it is an option. Pin it and two renders of one
investigation are the same bytes — the same rule `stix_bundle`'s `created`
follows, and for the same reason.

**Why the escaping is the interesting part.** Nearly every string in a report
came from the evidence, which is to say it was written by the subject of the
investigation: a filename off a disk image, a registry value, a URL out of a
phishing mail. So the model holds values, and text becomes markup in exactly one
place per format — each escaped for the thing that actually goes wrong in it.

*HTML is the security boundary.* Every string is escaped, the stylesheet is
inlined, and the document contains no script, font, image or link at all. A
report that fetches something tells whoever serves it that the examiner opened
it, and when. Evidence text is never turned into a link either: a report that
makes the attacker's URL clickable is a report that can be clicked.

*Markdown is structural.* A pipe inside a table cell ends the cell and a newline
ends the row, so an unescaped one silently shifts every column after it and the
row reads as evidence it is not. A line-leading `#` or `4.` in a paragraph
becomes a heading or item four. All of that is escaped — but Markdown is escaped
so it reads correctly, not so it is safe to convert. When the output is going to
be looked at in a browser, render HTML.

*CSV is formula injection.* Excel and LibreOffice execute a cell that begins
`=`, `+`, `-` or `@` when the file is opened, so a filename recovered from an
image is code on the examiner's workstation. Such a cell is written with a
leading apostrophe, which spreadsheets strip on display; a value that is simply
a signed number is left alone, since a report whose numbers all gained an
apostrophe is one nobody can sort. `{"formula_guard": false}` turns it off for
output that will be parsed rather than opened.

A CSV file holds one table, so `report_render(r, "csv")` on a report with
several refuses until one is named with `{"table": 1}` or its caption, rather
than stacking two different headers into a file no spreadsheet reads correctly.

**Writing one out.** `report_write(report, path)` renders and writes in one
step, taking the format from the path's extension — `.html`, `.htm`, `.md`,
`.markdown`, `.csv` — or from `{"format": ...}` when the name says nothing. It
hands back `{path, bytes, format, sha256}`.

The digest is the point of it. A report is written to be given to someone, and
the only useful thing to say about a file that has left your hands is what it
hashed to when it left them. So the digest is read back off the disk and checked
against the document that was meant to be there: a short write or a filter that
rewrote the bytes on the way past is a refusal, not a hash of something nobody
can reproduce. And when a case is open, the write becomes a timeline entry
carrying the path and that digest — which is the whole of the link between an
investigation and the documents it produced.

**A block nothing renders is an error, not a gap.** `report_render` validates
the whole document before writing any of it and refuses by section and block
index. A renderer that stepped over what it did not understand would hand back a
report that looks complete and is missing a finding.

### Chain of custody

A forensic answer is only worth what its provenance is worth. `case_open` starts
a session that records the investigation as it happens:

```mutant
let opened, err = case_open("IR-2026-0413", "G. Gogia", {"hash": "sha256"});

let image, err = raw_open("/evidence/laptop.E01");     // recorded: path, size, digest
let header, err = raw_read_at(image["handle"], 0, 2);  // recorded: raw_read_at x1

let drift, err = case_verify();                        // re-measures every source
let written, err = case_write("case.json");            // sealed and signed
let manifest, err = case_close();
```

Four properties are worth knowing before you reach for it.

**Nothing is recorded until `case_open` is called.** The hooks sit in every
evidence opener and every handle resolver, so a program that does not open a case
pays one atomic load and behaves exactly as it did before.

**Hashing is opt-in, and the manifest says which it was.** `{"hash": "sha256"}`
digests each source as it is opened; the default is no digest, because the
alternative is `raw_open` on a 500 GB image silently reading the whole thing
before it hands back a handle. A case without digests records size and
modification time and states `"hash_policy": "none"` — and `case_verify` then
says `"basis": "size and mod time"` per source, so a weaker check is never
mistaken for a stronger one.

**The touch record is aggregated, not logged.** Per source, per builtin: first
touch, last touch, and a count. A program that reads a hundred thousand files
produces a manifest a person can read.

**The seal is checkable by someone else.** `case_write` puts a SHA-256 over every
field except the seal itself, plus an Ed25519 signature over the same bytes and
the public key that verifies it, into the document. `case_manifest_verify(path)`
is then a function of the file alone — it needs neither the case that produced it
nor any key the reader does not already hold. Reformatting the JSON does not
break it; altering a single character does.

**The handover.** `case_report()` renders the case itself as a report value —
the header, the evidence with its digests, what each builtin touched and how
often, the timeline, the integrity statement and the security counters. It is
built from the manifest rather than from the session, so the report and the
manifest cannot disagree about what was examined; and because it is a value, an
examiner's conclusions go in with `report_section` and `report_text` before
anything is rendered.

```mutant
let bundle, err = case_bundle("handover/IR-2026-0413");
putln(bundle["manifest_hash"]);
```

`case_bundle(dir)` writes the four documents somebody else opens:
`manifest.json`, `report.html`, `report.md`, and a `SHA256SUMS` that any
`sha256sum -c` can check.

**Which document vouches for which.** The reports are written first and the
manifest records what they hashed to, so the manifest's seal — the SHA-256 over
every other field, and the Ed25519 signature over the same bytes — covers the
reports too. Edit a byte of `report.html` and it no longer matches the digest
inside a document whose own integrity still verifies. The binding runs one way on
purpose: a report quoting the manifest's hash would have to quote it before the
manifest existed, and would be quoting a document that was about to change.
`SHA256SUMS` is the convenience on top of that, not the guarantee underneath it.

**The security counters have a log behind them.** Every anti-debug, anti-tamper
and command-execution check the runtime performs is recorded in an append-only
hash chain: each entry carries the hash of the one before it, so the chain's
head is a single commitment to every event in order. The counters say a check
tripped eleven times; the chain says at which stage, and in what order relative
to the evidence that was open at the time, which is a question a counter cannot
be asked after the fact.

```mutant
let head, err = audit_head();       // the commitment, and how much is readable
let written, err = audit_write("audit.json");

let manifest, err = case_manifest();
let checked, err = audit_verify("audit.json", manifest["audit"]["head"]);
```

The head is written into the manifest, inside the seal, because a hash chain
nobody kept the head of proves nothing. That is what the second argument to
`audit_verify` is for: without it the log is checked against the head stored
inside the same file, which is a check against a value its own writer chose, and
the result says `anchored: false` rather than quietly passing. What the chain
cannot show — and says so, in a `does_not_cover` field in every document it
writes — is a log deleted or truncated as a whole. An edited entry breaks every
link after it; a missing document breaks nothing, because there is nothing left
to break. The chain keeps the most recent entries in memory and reports how many
it dropped, so a capped log is never mistaken for a short one; the head still
covers the events it can no longer show you.

The manifest also carries a reproducibility record: the tool build, and the path
and digest of the exact `.mu` that produced the document. And it asserts
`integrity.evidence_read_only: true` — a claim backed by a guard that fails the
build if any evidence-reading code asks the operating system to change something.
See [EVIDENCE_HANDLING_POLICY.md](EVIDENCE_HANDLING_POLICY.md) for the rule and
its two reviewed exceptions, and
[`examples/forensics/chain_of_custody.mut`](../examples/forensics/chain_of_custody.mut)
for a program that runs the whole cycle.

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
- `mutant graph export --out <dir> [--module-path DIR] <entry.mut>` — write the
  symbol graph of a whole program to a graph store, for asking questions across
  a codebase that no single file can answer.

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

### Exporting a program's symbol graph

`mutant graph export` walks the entry file's whole import closure and writes
down what every name in it means: a node per module and per declaration
— functions, values, parameters, loop bindings, import aliases, structs, enums,
fields and variants — and an edge per relationship between them.

```
mutant graph export --out ./example_graph_data_symbols examples/modules/main.mut
```

| Edge | From → To | What it says |
| --- | --- | --- |
| `DECLARES` | module → declaration | which file a name is written in |
| `ENCLOSES` | declaration → declaration | which declaration a name is written inside |
| `REFERENCES` | declaration → declaration | one per use, carrying its position and whether it was a call |
| `IMPORTS` | module → module | one per resolved `import` |
| `USES_TYPE` | declaration → struct or enum | a second label on the references that name a type |

Each declaration also carries its kind as a second node label, so counting the
functions in a program is a count rather than a traversal. The label names are
written beside the store, so it stays readable without the `mutant` binary.

Three things are worth knowing before relying on it:

- **It is a snapshot.** The compiler and the editor build their own graph in
  memory and never read this one. An exported store describes the source as it
  was when it was written, and says nothing about the source afterwards.
- **Positions are file-local**, matching the files on disk rather than the
  concatenated source the compiler sees.
- **A program that does not compile still exports.** Rules the program breaks
  are printed as refusals and the graph is written anyway, because a graph of a
  broken program is the one worth having.

The target directory must be empty or absent: a store is written in one pass so
that what is in it describes one program at one moment. `example_graph_data*/`
is already in `.gitignore`, which makes it a convenient place to look around.

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
