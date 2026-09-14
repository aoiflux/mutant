# Changelog

All notable changes to Mutant are recorded here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
What "breaking" means for artifacts, builtins, the language and the CLI is
defined in [CONTRIBUTING.md](CONTRIBUTING.md#compatibility-and-stability).

Entries for v2.4.0 and later are written from the release notes and the commits.
Entries before that are reconstructed from git history and are summaries, not
exhaustive lists.

## [Unreleased]

Nothing yet.

## [2.5.0] — 2026-09-14

The v2.5 line — *trustworthy: structural correctness*. The theme is that every
claim the README makes becomes verifiable.

### Added

- **One event vocabulary across every parser, and three ways out of it.** Five
  of the seven builtins in a new `schema interchange` category.
  `events_from(artifact, kind_or_mapping)` normalizes any parsed artifact into a
  fixed set of event fields and `event_kinds()` reports what each supported
  artifact maps; `ecs_event`, `ocsf_event` and `timesketch_event` write that
  vocabulary out as Elastic Common Schema documents, OCSF events, or the plaso
  records Timesketch ingests.

  The parsers each hand back their own shape, because each artifact *is* its own
  shape -- an `$MFT` record carries eight timestamps, a Prefetch file carries a
  list of run times, a syslog line carries one. That is right for a parser and
  wrong for a timeline, and wrong for anything downstream that wants one row
  format. The alternative to normalizing was a table per (artifact, schema) pair:
  thirteen artifacts and three interchange schemas is thirty-nine tables, each of
  which drifts the moment either side changes. With one hop in between it is
  thirteen plus three, and a new parser reaches every schema by writing one
  mapping.

  Thirteen source kinds are mapped: `mft`, `prefetch`, `evtx`, `lnk`, `amcache`,
  `shimcache`, `jumplist`, `syslog`, `browser_history`, `browser_cookies`,
  `browser_downloads`, `bodyfile` and `mactime`. Every kind produces the same
  shape, so a supertimeline across all of them is a `timeline_merge` of the
  results.

  Three rules keep the output honest. **An unknown field is absent, not empty**
  -- an empty string in a forensic record reads as "the artifact recorded nothing
  here", which is usually a claim the parser never made; a `size` of zero is kept
  because an empty file has a real size of zero. **A zero timestamp produces no
  event**, because these artifacts use 0 for "not recorded" and an `$MFT` has
  plenty; emitting them would bury the real rows under thousands of 1970 ones.
  **`extra` carries the source entry verbatim**, so normalizing is additive and
  nothing the parser found is lost -- a normalized view of evidence that quietly
  drops fields is a view an examiner cannot testify from.

  `severity` is a word (`informational` through `fatal`) rather than a number,
  because the numeric scales disagree about direction: syslog counts down from 0
  Emergency, Windows event Levels count up from 1 Critical. Converting once in
  the source mapping means each downstream schema converts from one known thing.
  Windows Level 0 (`LogAlways`) asserts nothing about severity, so it produces
  none rather than a guessed `informational`.

  `$FILE_NAME` timestamps are described apart from `$STANDARD_INFORMATION` ones,
  because the disagreement between the two sets is the timestomping tell and a
  timeline that merged them would hide it. Amcache and Shimcache are categorised
  as `execution` with the action `present`, not `run`: both record that a program
  was on the host, which is evidence of execution rather than proof of it.

  **The three emitters each take one event or a whole timeline** and hand back
  the same shape, so an `$MFT` normalized and handed to Timesketch is two calls
  and an `ndjson_stringify` rather than a map over three hundred thousand rows
  with a `(value, err)` pair on each. All three take the same options: `host` and
  `user` fill in what an artifact structurally cannot record -- an `$MFT` knows
  every path on the volume and nothing about which host the volume came out of --
  without ever overwriting what the artifact did record; `tags` lands in each
  schema's own tag field; `extra: false` leaves the verbatim source entry out. An
  unknown option key is an error, and so is a hash that did not come out of
  `events_from`: emitting a raw parser entry would produce a document with no
  timestamp and every mapped field missing, which looks like a real document and
  indexes like one.

  **The emitters carry the envelope's honesty into each schema** rather than
  filling required fields with guesses. ECS `event.type` is read off what the
  timestamp records rather than off the artifact's kind, and `event.category` is
  omitted where ECS has no honest value instead of filing a log line under
  something it is not; severity is emitted as both the word (`log.level`) and a
  syslog-direction number (`event.severity`), so nothing downstream has to know
  which way the scale runs. OCSF classes say where a record belongs, not that
  Mutant observed it happen: `execution` stays on the Base Event rather than
  taking 1007 Process Activity, because Amcache records presence and a detection
  written against 1007 would fire on it, and `registry` stays there rather than
  borrowing the `win` extension's uid, which means nothing to a consumer that has
  not loaded it; `severity_id` 0 and `file.type_id` 0 are OCSF's own way of
  saying the source did not report one. Timesketch's three required fields --
  `message`, `datetime` and `timestamp_desc` -- are never left empty, because
  Timesketch drops such a record on ingest rather than flagging it, and a kind
  with no plaso equivalent gets `mutant:<kind>:event` rather than a borrowed
  `data_type` that an analyzer would then run over and report on.

  An artifact Mutant does not parse is described with a mapping hash --
  timestamps, their meanings and formats, and which source field fills which
  event field -- rather than waiting for a source kind to be added. It is the
  same mechanism the built-in kinds use; there is no privileged path. See
  [docs/INTERCHANGE_SCHEMAS.md](docs/INTERCHANGE_SCHEMAS.md).

- **Investigations end in a report.** Seven builtins in a new `reporting`
  category. `report_new` starts one and `report_section`, `report_text`,
  `report_list` and `report_table` fill it in; `report_render` renders it as
  HTML, Markdown or CSV, and `report_write` renders and writes it in one step. The report is a plain hash, so it can be JSON-encoded,
  stored, diffed against the last one or written by hand, and every builder
  returns a new document rather than changing the one it was given. `generated`
  defaults to now and is pinnable, so two renders of one investigation are the
  same bytes.

  **The escaping is the substance of it.** Nearly every string in a report came
  from the evidence, which is to say it was written by the subject of the
  investigation, so the model holds values and each format is escaped for the
  thing that actually goes wrong in it. HTML is the boundary: every string is
  escaped, the stylesheet is inlined, and the document carries no script, font,
  image or link -- a report that fetches something tells whoever serves it that
  the examiner opened it, and evidence text is never made clickable, because a
  report that links to the attacker's URL is one that can be clicked. Markdown
  is escaped for structure, since a pipe in a filename ends a table cell and
  shifts every column after it, and a line-leading `#` turns a finding into a
  heading. CSV is guarded against formula injection: a cell beginning `=`, `+`,
  `-` or `@` is executed by a spreadsheet when the file is opened, so it is
  written with the leading apostrophe spreadsheets strip on display -- unless it
  is simply a signed number, because a report whose numbers all gained an
  apostrophe is one nobody can sort.

  **A block nothing renders is an error rather than a gap.** `report_render`
  validates the whole document before writing any of it and refuses by section
  and block index; a renderer that stepped over what it did not understand would
  hand back a report that looks complete and is missing a finding. A CSV of a
  report with several tables is refused for the same reason until one is named:
  two different headers stacked into one file is not something a spreadsheet
  reads the way it was meant.

- **The handover: `case_report` and `case_bundle`.** `case_report()` renders the
  open case as a report value -- the header, the evidence with its digests, what
  each builtin touched and how often, the timeline, the integrity statement and
  the security counters. It is built from the manifest rather than from the
  session, so the report a person reads and the document a machine verifies
  cannot disagree about what was examined; and because it is a value, an
  examiner's conclusions go in with `report_section` and `report_text` before
  anything is rendered.

  `case_bundle(dir)` writes what actually gets handed over: `manifest.json`,
  `report.html`, `report.md`, and a `SHA256SUMS` any `sha256sum -c` can check.

  **Which document vouches for which, and why it only works one way.** The
  reports are written first and the manifest records what they hashed to, so the
  seal over the manifest -- the SHA-256 over every other field, plus the Ed25519
  signature over the same bytes -- covers the reports as well. Edit one byte of
  `report.html` and it no longer matches a digest inside a document whose own
  integrity still verifies, which is a thing the recipient can establish with the
  file alone. The reverse ordering cannot be made honest: a report quoting the
  manifest's hash would have to quote it before the manifest was written, and
  would be quoting a document that was about to change. `SHA256SUMS` is the
  convenience on top of that, not the guarantee underneath it.

- **`report_write(report, path)`** renders and writes in one step, taking the
  format from the path's extension -- `.html`, `.htm`, `.md`, `.markdown`,
  `.csv` -- or from `{"format": ...}` for a name that says nothing. It returns
  `{path, bytes, format, sha256}`.

  The digest is the reason it exists. A report is written to be given to
  somebody, and the only useful thing to say about a file that has left your
  hands is what it hashed to when it left them. So the digest is read back off
  the disk and checked against the document that was meant to be there: a short
  write, a full disk or a filter driver that rewrote the bytes on the way past is
  a refusal rather than a hash of something nobody can reproduce. When a case is
  open, the write becomes a timeline entry carrying the path and that digest --
  the whole of the link between an investigation and the documents it produced.

- **Indicators out as STIX 2.1.** `stix_bundle` renders indicators as a bundle
  of Cyber-observable Objects, taking `extract_iocs` output directly, and
  `stix_pattern` renders the pattern that matches one of them for a query.
  Addresses, domains, URLs and email addresses each become their own observable;
  each MD5, SHA-1 and SHA-256 digest becomes a file observable carrying that one
  algorithm, because nothing in a list of digests says they describe the same
  file, and merging them on the guess that they do would invent a file nobody
  observed.

  **Every id is derived from the object rather than generated.** An observable's
  id is the UUIDv5 over the canonical form of its identifying properties that
  STIX specifies, so the same indicator is the same object wherever it is seen --
  twice in one case, or here and in someone else's platform. The bundle and the
  indicators get derived ids too, which the specification would let be random: a
  random id is a new id on every run, and two bundles built from one body of
  evidence would then differ in every identifier while describing exactly the
  same findings, which is impossible to diff and impossible to testify from.
  Values are normalized before they are hashed for the same reason -- a digest in
  upper case and the same digest in lower case are one object, not two.

  `indicators: true` adds an Indicator beside each observable, typed `unknown`
  rather than `malicious-activity`: the extraction found a value written in a
  document and concluded nothing about it, and a bundle that says otherwise
  carries that conclusion into every platform it is shared with. The three
  timestamps an Indicator requires come from a `created` option rather than a
  clock, so pinning it to when the case was collected makes the bundle
  byte-identical between runs. A key no indicator type claims is an error, and so
  is a value that is not what its key says: a forty-character digest filed under
  `sha256` would become an observable whose id nothing else computes, and a STIX
  object nothing matches produces no report at all.

- **Chain of custody.** Eight builtins in a new `chain of custody` capability
  category -- `case_open`, `case_note`, `case_evidence`, `case_verify`,
  `case_manifest`, `case_write`, `case_manifest_verify`, `case_close` -- and the
  discipline that ties the pieces this language already had (digests,
  timestamps, a deterministic compiler, Ed25519 signing) to one investigation.

  `case_open(id, examiner)` starts a session. From there every evidence opener
  (`raw_open`, `ewf_open`, `vhdi_open`, the six filesystem parsers, `table_open`,
  `hive_open`, `reg_open`, `zip_open`, `tar_open`) records its source into the
  manifest, and every builtin that reads or closes an evidence handle is counted
  against that source. `case_close` returns a document naming the examiner, the
  tool build, every source with its size and digest, every builtin that touched
  each one, the timeline, and the run's security telemetry.

  Four decisions shape it. **Nothing is recorded until a case is opened** -- the
  hooks sit on the hot path of every forensic program ever written in this
  language, so not using the feature costs one atomic load and changes nothing.
  **Hashing is opt-in and the manifest says which it was**: `{"hash": "sha256"}`
  digests each source as it is opened, and the default is no digest, because the
  alternative is `raw_open` on a 500 GB image silently reading the whole thing
  before it returns a handle. A case without digests records size and
  modification time and states `"hash_policy": "none"`; `case_verify` then
  reports `"basis": "size and mod time"` per source, so a weaker check is never
  mistaken for a stronger one. **The touch record is aggregated, not logged** --
  first touch, last touch and a count per builtin per source -- because a program
  that reads a hundred thousand files must not produce a hundred-thousand-line
  manifest. **The seal is checkable by someone else**: `case_write` puts a
  SHA-256 over every field but the seal, an Ed25519 signature over the same
  bytes, and the public key that verifies it into the document, and
  `case_manifest_verify(path)` is a function of the file alone. Reformatting the
  JSON does not break it; altering a character does.

  The manifest also carries the reproducibility record -- the path and digest of
  the exact `.mu` that produced it, taken by the runner from the signed bytecode
  before any of it executed. Not "a tool wrote this" but "this bytecode wrote
  this".

- **Evidence is read-only, and now provably.** A second machine-checked policy
  in `policy/`, alongside the environment-variable guard.
  `policy/evidence_guard_test.go` parses every file that reads evidence and
  fails the build on any call that asks the operating system to create,
  truncate, rename, delete or chmod anything, or to open a file with a writable
  flag. Two reviewed exceptions, both writing somewhere other than the evidence:
  the temp file libxfat demands, and the temp copy `withSQLiteCopy` takes
  precisely so an evidence database is never opened by something that wants to
  write a journal beside it. Each is pinned to an exact line count, so a new
  write inside an already-permitted function still fails.

  The invariant already held. Writing it down is what lets a manifest assert
  `integrity.evidence_read_only: true` and have that mean something -- a
  manifest that claims what nobody checks is worse than one that stays quiet.
  The rule, its reasoning and what the guard deliberately does not look for are
  in `docs/EVIDENCE_HANDLING_POLICY.md`.

- **Seven security lint rules.** `commandInjection`, `pathTraversal`,
  `weakCrypto`, `tlsVerificationDisabled`, `hardcodedSecret`,
  `evidenceMutation` and `unboundedResource`, each settable through
  `mutant.lint.rules.<name>.severity` like every rule before them. They take
  the editor from 16 rules to 23, and they are the rules only a language that
  knows what a disk image is can write.

  The rules that shipped before these are right by construction: each compares
  a call site against a fact the builtin registry states. These read *intent*,
  which cannot be stated, so each carries its own answer to what makes a
  finding certain enough to interrupt someone. The shared principle is that
  **what the program does with a value decides the finding, not what the value
  looks like** -- and the corpus is what forced it. `examples/` already held
  three literals a textbook secret scanner flags first, all three legitimate
  teaching material, and the one that separates them from a real leak is
  whether the program *uses* the value or takes it apart. A JWT handed to
  `jwt_decode` is a sample; the same string put in an `Authorization` header is
  a credential. `weakCrypto` draws the same line for MD5, which in a forensic
  tool is daily work: matching an artifact against a known-file set wants MD5
  specifically, so the rule reports only a digest compared against one written
  into the program, and never `imphash`, `nt_hash` or `lm_hash`.

  `evidenceMutation` is the one no general-purpose linter has: elsewhere a path
  is a path, but `raw_open` and `ewf_open` say out loud that the file is an
  exhibit, and `fs_write` to that same path is a hash that no longer matches
  the one in the notes. `unboundedResource` turned out not to be about
  unboundedness at all -- `cidr_hosts` refuses more than 20 host bits and
  `range` more than 10,000,000 elements, so `cidr_hosts("10.0.0.0/8")` is not a
  memory risk but a call that reads as a reasonable network sweep and simply
  fails. The rule evaluates exactly the predicate the builtin evaluates.

  Running the rules over the corpus found three real defects in shipped
  examples: `phishing_url_analyzer.mut` and `ioc_fetcher.mut` spliced values --
  one of them an attacker-authored URL -- straight into Lua single-quoted
  strings, where a `'` ends the string and the rest is read as Lua. All three
  are fixed.

- **A real test framework: `mutant test`.** Named tests and subtests,
  assertions that report the file and line they failed on, fixtures, name
  filtering, a `--json` reporter for CI, and line coverage with an LCOV
  profile. The command existed before this and did one thing: run each
  `*_test.mut` and call it passed unless it errored or its last expression was
  `false`. There were no `*_test.mut` files in the repository, which is the
  usual sign.

  The fix underneath all of it: a test file is now compiled through the same
  build every other program goes through. It used to have its own pipeline,
  which never walked the module graph -- so an `import` in a test file resolved
  to nothing and the namespace it bound was an undefined variable. A test
  framework that could not cross a file boundary could not test the feature
  files exist for.

  `test(name, fn)` runs the test where it is written, so a file reads top to
  bottom and a test declared inside another is a subtest. A failed assertion is
  recorded and the test carries on -- the language has no exceptions and this
  does not invent one -- and every assertion also returns its verdict, so a
  failure is an ordinary value. A test that dies of a runtime error is caught
  at its own boundary, so one broken test costs the file no other test.

  Ten builtins: `test`, `before_each`, `after_each`, `assert`, `assert_eq`,
  `assert_ne`, `assert_contains`, `assert_err`, `assert_ok`, `fail`. Deferred
  and said so: parallel test files (the task registry behind `spawn` is
  process-wide), benchmarks, mocking, and asserting on a crash. See
  [docs/TESTING.md](docs/TESTING.md).

- **A debugger: `mutant debug`.** Breakpoints, stepping, the call stack and
  variable inspection, delivered as a Debug Adapter Protocol server, so VS Code
  (press F5 on a `.mut`), Neovim's `nvim-dap` and anything else that speaks DAP
  get it from one implementation. For a language whose programs run for minutes
  over multi-terabyte images, `putln` debugging was not viable.

  It launches rather than attaches: `mutant debug` is the program's own
  process. A Mutant program carries anti-debugging probes that end a
  secure-mode run when an OS debugger is present, so attaching one would have
  meant the language's own tooling tripping its own tamper response.

  Debugging runs from source at mutation level 0. A release artifact has had
  its positions stripped -- there is nothing to step through, and the values
  held by a program that left this machine are not this machine's to render.

  Three things are deliberately absent and say so rather than half-working:
  watch expressions beyond a plain variable name, conditional breakpoints, and
  stepping into `spawn` or `pmap`. Evaluating an expression means compiling it
  in the frame's scope, and a compiled program does not carry its scopes; a
  breakpoint carrying a condition stays armed with a message rather than
  silently never firing. Hit counts do work. See
  [docs/DEBUGGING.md](docs/DEBUGGING.md).

- **`while`, `for (item in collection)` and `match`.** The counting `for` was
  the only loop the language had, and the only way to branch on a value was a
  chain of `if`s.

  `while (c) { ... }` is its own construct rather than sugar for `for (; c; )`,
  so the formatter prints back the loop that was written; `break` and
  `continue` work in it unchanged.

  `for (v in xs)` walks arrays, hashes, strings and bytes. One binding yields
  the thing the collection is made of -- an array's element, but a hash's key
  -- and two bindings yield the index or key alongside the value. A hash is
  visited in the order printing it shows, because both the printer and the loop
  sort with the same comparison: a program that prints a hash and a program
  that loops over one must agree about what order it is in. Iteration is two
  opcodes rather than a desugar to `len()` plus indexing -- a program that
  declared its own `len` would otherwise change what every loop in the file
  means, and a hash has no ordered index to desugar to. There is no range
  syntax: `range(0, 10)` is an ordinary builtin returning an array, and looping
  over it is a `for…in` like any other.

  `match` is an **expression**, so it binds, returns and nests like any other
  value: `let label = match (code) { 0 => "clean", 1 | 2 | 3 => "a few", _ =>
  "many" };`. A pattern is a literal, a negated number, an enum variant such as
  `Status.Ok`, or `_`; alternatives are joined with `|`. Patterns have their
  own grammar rather than going through the expression parser, which is what
  makes `1 | 2 | 3` those three values instead of the number `3` -- `|` is the
  bitwise-or operator everywhere else. An arm body is one expression or a block
  whose value is its last expression, and the parentheses around the subject
  are required, since `match x { ... }` without them is a struct literal.

  Because a match must produce a value, a subject no arm matches is a run-time
  error naming the value rather than a `null` flowing onward. The case that is
  about is adding a variant to an enum, which leaves every existing match over
  it one arm short and nothing else notices; the language server now reports
  that gap before the program runs (`matchExhaustiveness`, settable like every
  other rule), and reports an arm written after `_` as unreachable. All three
  constructs run identically on the tree-walking evaluator and the VM, the
  formatter round-trips them, and editor grammar, snippets, hover help and
  completion cover them. See
  [examples/basics/control_flow.mut](examples/basics/control_flow.mut).

- **String interpolation, raw strings and triple-quoted strings.** `"${...}"`
  puts an expression in a string: `"host=${h}:${p}"` where `h` is a string and
  `p` an integer. A piece that is already a string contributes its own text,
  anything else contributes what it would print, so there is no conversion to
  write and no value a hole cannot take. A hole holds one expression -- a call,
  an index, arithmetic, another interpolated string -- and it is compiled where
  it stands, so nothing is re-scanned at runtime and a `%` in the text is a
  percent sign.

  Only the two characters `${` open a hole. A lone `$` is unchanged, so
  `"cost: $5"` and `"$PATH"` mean what they always meant; `\${` writes the two
  characters literally. A hole is parsed in place: a broken one is reported at
  its own line and column inside the string, a traceback through a call in a
  hole underlines that call, and go-to-definition and every builtin diagnostic
  reach into holes exactly as they reach into any other expression.

  `r"..."` decodes nothing -- no escapes, no interpolation -- so
  `r"C:\Users\Public"` and `r"\d{4}-\d{2}"` say what they look like. It ends at
  the first quote, so it cannot contain one.

  `"""..."""` spans lines, with escapes and interpolation still live;
  `r"""..."""` is its raw form, and either may hold a lone `"` or `""`. A
  newline right after the opening delimiter is dropped and the smallest
  indentation of any non-blank line -- counting the closing delimiter's own
  line -- is removed, so a block reads as the text it is rather than as the
  text plus the surrounding code's indentation. CRLF becomes LF inside one:
  the line endings in a multi-line literal come from how the file was checked
  out, and the same source must not mean two things in two clones.

  A literal with no hole is still an ordinary string token, so nothing in a
  program that does not interpolate changes -- not the AST, not the bytecode.
  Interpolation compiles to its own opcode rather than to a call, so a module
  that declares a name like `str_format` cannot change what every interpolated
  string in the program means. The formatter reprints a raw or triple-quoted
  literal as written instead of re-quoting its value, which would have doubled
  the backslashes it exists to avoid.

- **Modules and imports.** A program can be more than one file. `import
  "lib/stats.mut";` binds the namespace `stats`, and `import s
  "lib/stats.mut";` binds `s` instead; the namespace is otherwise the file's
  base name with the extension removed. An import binds that one name and
  nothing else -- the imported file's own names are not visible unqualified, so
  two modules may each declare `helper` without one silently overwriting the
  other. A top-level name beginning with `_` is private to the file that
  declares it, and reaching for it through a namespace is a compile error
  naming both the module and the name: there is no export list to keep in step
  with the code.

  Paths resolve relative to the importing file's own directory first, then
  against each `--module-path <dir>` directory in the order the flags were
  given. The flag repeats rather than taking a separator-joined list, and it is
  the only thing that widens the search: no manifest, no lockfile, no config
  file, no environment variable (see
  [docs/CONFIGURATION_POLICY.md](docs/CONFIGURATION_POLICY.md)). The extension
  is written out rather than guessed, a cycle is reported as the chain that
  closed it (`main.mut -> a.mut -> b.mut -> a.mut`), a module reached two ways
  is compiled and run once, and a path that names no file lists every directory
  that was tried.

  `struct` and `enum` names stay program-wide, because that is how they travel
  in the bytecode: one declaration is visible from every module with no
  qualification, and two modules declaring the same type name is an error
  naming both files. Values are per-module, types are per-program.

  Modules link into one instruction stream, one constant pool and one global
  slot space -- the bytecode format leaves no choice, since the polymorphic
  engine shuffles the whole constant pool, the opcode permutation ships as one
  table for the entire program, and jumps carry absolute offsets. None of that
  is visible in a failure: each traceback frame names the file it came from and
  quotes that file's line, from a new `ModuleSpans` table that `StripDebugInfo`
  removes with the rest of the debug information, so a released artifact does
  not carry the layout of your source tree. See
  [docs/MODULES.md](docs/MODULES.md) and
  [examples/modules/](examples/modules/).

- **Builtin namespaces.** Every builtin family is now addressable with a dot:
  `fs.read` is `fs_read`, `str.upper` is `str_upper`, `base64url.encode` is
  `base64url_encode`. Nothing is imported and nothing is declared -- the flat
  name is derived by joining the halves with `_`, so all 44 families worked the
  day this landed and none has a list to maintain. Both spellings are one
  function with one contract: one arity check, one argument-type check, one
  deprecation notice, one entry in the traceback. A variable, parameter, field
  or import that already binds the name wins, so no program written before this
  changes meaning. Flat names keep working unchanged.

- **Bitwise operators.** `&`, `|`, `^`, `<<`, `>>` and the prefix complement
  `~`, with the compound forms `&= |= ^= <<= >>=`. A language whose brochure
  leads with disk-image parsing could not express a mask, a flag test or a
  shift; the workaround was arithmetic or a builtin call. Semantics and
  precedence are Go's: `<< >> &` bind as tightly as `* / %` and `| ^` as `+ -`,
  so `flags & MASK == 0` reads as `(flags & MASK) == 0` rather than C's
  `flags & (MASK == 0)`. `>>` is an arithmetic shift over the signed 64-bit
  integers the VM has. Non-integer operands are refused rather than truncated,
  and a negative shift count is a runtime error instead of the panic Go would
  raise. Six new opcodes, appended so existing opcode values are unchanged.
- **A real `bytes` type.** `BYTES` is a first-class object: it indexes to an
  integer 0–255, concatenates with `+`, compares by content, measures with
  `len`, and hashes in a keyspace disjoint from strings. Every disk sector, PE
  section, memory page and socket read previously travelled in a Go string, and
  nothing in the language could tell a binary value from text — so `str_reverse`
  turned every non-UTF-8 byte into U+FFFD and `str_substr` indexed by rune while
  `bytes_get` indexed by byte, both without failing.
- `string_to_bytes(s, encoding)` and `bytes_to_string(b, encoding)`, with
  `"raw"`, `"utf8"` (validated, not substituted), `"latin1"`, `"hex"` and
  `"base64"`. Because every pre-existing producer already returned byte-exact
  data in a string, `string_to_bytes(x, "raw")` bridges all of them losslessly.
- 16 native `*_bytes` producers — `fs_read_bytes`, `hex_decode_bytes`,
  `base64_decode_bytes`, `gunzip_bytes`, `zlib_decompress_bytes`,
  `aes_decrypt_bytes`, `net_conn_read_bytes`, six `*_read_file_bytes` filesystem
  readers and three `*_read_at_bytes` image readers. **Builtin count 409 → 427**
  across 33 categories.
- **Runtime tracebacks with source positions.** A fault used to print one
  sentence with no way back to a line. The VM now prints every frame with the
  arguments it received, the line it is on, and an underline beneath the failing
  span; deep recursion collapses to "N frames repeated M more times". Positions
  ride in a delta-encoded line table costing single-digit percent of the
  instruction stream it annotates, and the program's source text travels with
  the artifact so a failing `.mu` can quote the line it died on.
- **Builtin stability tiers.** Metadata declares `stable` (the unwritten
  default), `experimental` or `deprecated`; a deprecated builtin names its
  replacement. Surfaced as an LSP hover footer and a new `builtinDeprecated`
  diagnostic.
- `--timing` for stage timing, `--trusted-key <path>` for the verification key,
  and `--target` for release cross-builds — replacing the environment variables
  that used to carry them.
- Credential handling that never records the secret: interactive prompt (the
  default), `--password-file <path>`, and `--password-stdin`.
- **A documentation path from nothing to a shipped binary.**
  `docs/TUTORIAL_30_MIN.md` ("Mutant in 30 minutes") goes from install to a
  signed standalone executable; `docs/COOKBOOK.md` is fourteen complete
  programs organised by investigation rather than by builtin category, ending
  with the traps that actually bit while writing them; `docs/COMPARISON.md`
  places Mutant against Python+plaso, Velociraptor, osquery and YARA+Sigma,
  including a section naming eight cases where it is the wrong tool. Every
  command and output in the tutorial and the cookbook was run against a binary
  built from this tree.
- `docs/CONFIGURATION_POLICY.md`, `docs/WHAT_IS_MUTANT.md`,
  `docs/WASM_REPL_REFERENCE.md`, and this file, plus
  [SECURITY.md](SECURITY.md), [CONTRIBUTING.md](CONTRIBUTING.md) and
  [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
- `examples/data/autoruns_hive.json` and `examples/data/phish.eml` — synthetic
  fixtures so two of the cookbook recipes run unchanged.

- **`docs/EXECUTION_MODES.md`** — the definitive statement of what each mode
  changes, every row traced to the code that implements it. The distinction it
  exists to write down is that **`--compat` weakens the response and `--dev`
  weakens the key**: compat still requires your password and still verifies the
  artifact, while an artifact built or run under `--dev` has no confidentiality
  at all, because the development key is a compile-time constant shared by every
  Mutant binary. That sentence was in no help text and no document.

- **`mlsp --version`** — the language server now says which release it was built
  from and how many builtins it linked (`mlsp 2.5.0 (493 builtins)`). It ships
  as a binary inside the editor extension, built from a checkout that can be
  older than the language it is asked to teach, and until now nothing it
  reported distinguished a current server from one cut months earlier. Both
  numbers are read from the same source as everything else: `global.Version` and
  `builtin.Builtins`.

### Changed

- **Enum equality is typed rather than textual.** Comparing an enum value with
  anything that was not an enum fell through to comparing what the two would
  print, and an enum prints as `Status.Ok(0)` -- so `Status.Ok ==
  "Status.Ok(0)"` answered **true**, in both engines. Bytes and errors each
  already had a typed comparison arm for exactly this class of accident; enums
  never did, and `match` made it reachable in a way plain `==` rarely was. Two
  enum values are now equal when they share a type and a variant, and an enum
  is equal to nothing else. A program that relied on the old answer changes
  behaviour.

- **Contradictory mode flags are an error instead of a silent resolution.**
  `--secure --compat`, `--secure --dev` and `--signer-auth --no-signer-auth`
  each exit non-zero naming both flags and why they conflict. Every flag scanner
  was last-flag-wins, and `--dev` did not even need to come last — it forced
  compatibility mode wherever it appeared — so `mutant prog.mu --dev --secure`
  ran unsecured having been asked in the same breath to run secured, and said
  nothing about it. `--dev --compat` is still accepted: dev mode implies compat
  mode, so naming both is redundant rather than contradictory, and repeating a
  flag stays harmless. Validation runs before any other work, so the embedded
  standalone path and the CLI reject the same command line identically.
- **A terminating security event says what fired and what to do about it.** The
  run used to stop on one sentence — `sandbox detected, execution halted for
  security` — that named no probe, no reason and no way forward, on a check
  that fires on ordinary containers, VMs and CI runners, which is where forensic
  tooling normally runs. It now prints the detector, its classification and
  confidence, the signals behind it, and the remedy. `--compat` is named for the
  host-probe events and deliberately **not** for a failed signature or a failed
  integrity check: those are statements about the artifact, and offering
  `--compat` there would be advice to run a modified file anyway. The VM's
  security opcodes return their error directly rather than through the response
  policy, so they call the same explainer.
- Help text for the modes was rewritten: `--dev` now says the fallback key is a
  compile-time constant shared by every Mutant binary, `--signer-auth` says it
  upgrades verification rather than enabling it, and the compat-weakens-response
  versus dev-weakens-key distinction is stated in the help itself.
- **Builtins resolve by name, not by registry ordinal.** `OpGetBuiltin` carried
  an index into the global registry, which made that registry append-only
  forever — nothing could be renamed, retired or reordered without silently
  repointing every artifact ever compiled. The compiler now interns the builtins
  a program references and ships that table in the artifact; the VM binds every
  name before an instruction runs, so a missing builtin fails by name at load.
  `ByteCode.Version` is **2**.
- Binary-accepting builtins widen rather than fork: the whole `bytes_*` family,
  the hash and encoding families, `fs_write`, `fs_append` and `net_conn_write`
  take `BYTES` **or** `STRING` and hand back the representation they were given.
  No existing builtin changed its return type — the `bytes` work is additive,
  and every `.mut` program written before it behaves identically.
- Debug information is unconditional in development artifacts and stripped only
  by `mutant release`, rather than being gated on a mode flag. Gating would have
  coupled debuggability to a security downgrade.
- The polymorphic engine carries line tables through the offset remap it already
  builds for jump targets, so mutated builds keep their positions.
- **The editor's builtin highlighting is generated from the registry.** The
  TextMate grammar carried a hand-copied list of builtin names, and a
  hand-copied list of 490 names is a list that falls behind: it had 76 of them,
  missing every `report_*`, `case_*`, `stix_*`, `ocsf_*` and `ecs_*` builtin
  along with 25 of the 26 `net_*`. `cmd/gendocs` now writes that one rule from
  `builtin.Builtins`, and `TestGrammarHighlightsEveryBuiltin` fails when the
  grammar and the registry disagree — because a generator nobody runs is the
  same drift one step further away. Only the builtin rule is generated; the
  rest of the grammar stays hand-written.

  Hover, completion, signature help and every diagnostic already covered all
  490, since those come from the language server and it derives them from
  `builtin/metadata.go`. What was actually wrong was narrower and still worth
  fixing: a `report_new` call read as an unknown identifier next to a
  highlighted `putln`, which tells the reader the wrong thing about what the
  language knows.
- `cmd/gendocs` writes each document with the line endings the file already
  had, instead of always writing LF into a tree checked out with CRLF.
- **The staleness check on the shipped language server was looking in the wrong
  place, and nothing ran it.** `check:lsp-bins` compared the staged `mlsp`
  binaries against the Go files under `lsp/` — but the analyzer derives arity,
  parameter kinds, result types and deprecation from `builtin/metadata.go` in
  the parent module, so registering a builtin changes what the server teaches
  and leaves every file under `lsp/` untouched. A server could fall a release
  behind the language and the check would call it current. It now compares
  against the whole module, requires all six binaries rather than passing on
  whichever ones happen to be present, and — for the one target the machine
  running it can execute — asks the binary for `--version` and compares that
  with what the sources build, because mtimes lie after a fresh clone. The check
  had also never been wired into anything; `scripts/package-targets.mjs`, which
  stages from `lsp/dist` without building, now runs it before it publishes.

### Removed

- **All environment-variable configuration.** Mutant takes no configuration from
  the environment, in code or in documentation: the environment is part of the
  untrusted thing a forensic tool examines, and an environment switch is an
  unlogged control channel absent from the command line an analyst records.
  Ten dead exported `*Env` constants across five files were deleted and 16
  documents purged of the variables they described — several of which named
  knobs the code had already collapsed to constants.
- The environment-driven builtin capability allowlist. *Capability
  configuration is under design; no interface is specified.*

### Fixed

- **The debugger refused to run on a virtual machine.** A debug session built
  its VM in secure mode, so the injected sandbox probe fired on launch and the
  security policy ended the session before the first line could be stepped.
  Every CI runner is a virtual machine and so is every malware-analysis
  workstation, which is to say the debugger stopped exactly where a forensic
  tool is most likely to be pointed at something.

  A session now runs in the posture `--compat` gives a run, the same one
  `mutant test` already used: the probes are still compiled into the bytecode
  being stepped and still execute, but a hit warns instead of terminating.
  `VM.SecureMode()` reports which posture a machine was built with, so a caller
  that chose the advisory one can say so rather than imply it.

- **A frame's unassigned local slots held the previous call's values.** The
  calling convention never cleared the region between a new frame's arguments
  and the end of its locals, so those slots held whatever the last call left on
  the stack. No program could see it -- every local is assigned before it is
  read -- but a debugger reads them all, and would have shown a dead value from
  an unrelated frame under the name of a variable whose declaration had not run
  yet. The slots are cleared when a debugger is attached, so no ordinary run
  pays for it.

- **An `if` used as a value left the stack wrong in two cases.** The compiler
  decided whether a branch had produced a value by looking at the last
  instruction it had emitted. A branch ending in a `let` emits no pop, so that
  branch pushed nothing where its sibling pushed one and the VM underflowed; a
  branch ending in a `for (v in xs)` ends in the pop that drops the loop
  *cursor*, which looks identical to a value being discarded, so that pop was
  removed and the cursor became the branch's value -- `if (true) { for (v in
  []) {} } else { 4 }` evaluated to `<iterator>`. Both branches now decide from
  the syntax, the same rule `match` arms use.

- `docs/SECURITY_LLD.md` claimed in two places that the VM forced
  `secureMode=true` for integrity failures, making integrity the one check no
  mode could downgrade. It does not: `vm.secureMode` carries the launch mode
  into both integrity checks, so under `--compat` and `--dev` a mismatch warns
  and the run continues. The documents now state what the code does. Whether
  integrity *should* be the exception to the mode rule -- "the host looks
  suspicious" is a guess about the environment, "this bytecode is not what was
  signed" is not -- is recorded as an open question rather than settled here.
- The test helpers that capture stdout and stderr wrote everything before
  reading anything, so they deadlocked once the captured output outgrew the pipe
  buffer (4 KiB on Windows). `mutant --help` crossed that line when the mode
  section was rewritten. They now drain concurrently.
- **Assignment to a captured variable corrupted the frame.** The compiler
  branched on two of `SymbolScope`'s five values at its three assignment sites,
  so a write to a free variable was emitted as `OpSetLocal` against the *free*
  index -- a position in the closure's capture list, not a frame slot. Writing
  free 0 landed on local 0, which is usually the first parameter:
  `fn(x) { let acc = 0; let inner = fn(p) { acc = 7; return p; }; return inner(x); }`
  called with 42 answered **7**, and two captures over two parameters answered
  `[777, 888]` for `(10, 20)`. Silent argument corruption, with no diagnostic
  from any stage. The tree-walking evaluator was correct throughout, so this was
  a defect against a reference implementation rather than a semantics question.

  A captured local now lives in a cell that the frame slot and every closure over
  it point at, so a write through any of them is a write all of them see. An
  accumulator over a callback works, a counter outlives the frame that made it,
  and two closures over one variable agree about its value. Adding `OpSetFree`
  over the existing by-value capture list was rejected rather than deferred: it
  would have stopped the corruption and left the accumulator answering 0, trading
  a findable bug for a quiet one.

  Five new opcodes, appended so existing opcode values are unchanged. Bytecode
  compiled before this runs unchanged, including its by-value capture.
  `pmap`, `peach` and `spawn` hand each worker its own copy of the captured
  cells, so a callback's writes stay local -- the rule those builtins already
  documented for globals, and without which the sharing would be a data race.
  Assigning to a builtin's name or to the name a function literal was bound to
  is still refused at compile time; neither is storage.
- **The VM skipped opcodes it did not recognise.** The dispatch switch had no
  default arm, so bytecode built by a newer toolchain ran to completion and
  answered with nonsense: the unknown instruction matched nothing, the
  instruction pointer advanced by one, and its operand bytes were executed as
  opcodes. It now stops and names the opcode. Opcodes are append-only, so this
  is the only direction that can fail -- old bytecode has always run on a new
  runtime, and still does.
- `mutil.EncryptObject`'s default arm returns an error both call sites discard,
  so an object type without an explicit arm travelled **unencrypted with nothing
  said**. `BYTES` has arms in both directions, with a test asserting the sealed
  type rather than trusting the suite.
- The parameter-kind conformance probe drew from a fixed candidate list that
  never exercised the new kind. Making it reachable immediately caught **15
  under-declared builtins**, including `len` and `json_stringify`, that a hand
  audit had missed.
- The evaluator has never indexed strings while the VM has. Bytes indexing was
  implemented in **both** engines so the new type does not inherit the
  divergence.
- A missing or malformed trusted-key file now fails hard instead of silently
  falling back to the local keystore.
- LSP: the type lattice, the function-parameter solver, inlay hints and
  signature help all know `bytes`; `builtinArgType` reports binary passed into a
  text builtin and names the conversion.
- `email_urls` declared `[]STRING` elements over an implementation that returns
  a `{host, scheme, url}` hash per link, so the published signature, the hover
  and the argument-type diagnostic were all confidently wrong about
  `u["host"]`. The contract now matches the code. **The conformance probe could
  not have caught it:** it checked only the top-level returned kind, never the
  declared element kind. It now checks both, verified by mis-declaring
  `text_split` and watching it fail.
- The generated `docs/CAPABILITY_REFERENCE.md` still told every reader that
  Mutant "has no separate bytes type" — untrue since `BYTES` shipped, and
  contradicted by a signature on the same page. Fixed in `cmd/gendocs`, which
  is where generated prose lives.

### Security

- `go test ./policy/...` — an AST guard, part of the ordinary `go test ./...` —
  fails the build on a `MUTANT_`-prefixed string literal anywhere in the module,
  on an environment read outside ten allowlisted functions with pinned line
  budgets, and on an environment write outside a build-time child `go build`.
  Sandbox, VM and debugger detection is unchanged: those probes read variables
  set by Sandboxie, WSL, a debugger or an injector — never by a Mutant user —
  and the only outcome they can produce is a refusal to run.
- `SecureStack.clearObject`'s `*String` arm zeroes `[]byte(v.Value)`, a copy Go
  makes at the conversion, so it has never wiped anything and cannot: Go strings
  are immutable. It is documented in place. Key material belongs in a `bytes`,
  whose backing array `Zero()` genuinely clears.

## [2.4.0] — 2026-08-25 — "Legion"

One compiled program, many minds running it.

### Added

- **Concurrency.** The unit is a whole VM, not a goroutine sharing one: a worker
  gets its own stack and frames and a *snapshot* of the globals over the same
  bytecode, so nothing is shared and nothing needs a lock. `spawn`, channels,
  and `pmap`/`peach`, up to 1024 workers. 10 new builtins; **399 → 409**.
- Compound assignment operators.
- Struct and enum hover in the language server; SSA-based analysis and ghost-code
  resolution in the extension.

### Changed

- **The polymorphic engine went live.** Previously 1 of 5 transforms, active only
  at level ≥ 6; now 4 of 4 from level 1.
- Execution engines reduced from three to two — the separate WASM REPL
  interpreter was deleted rather than kept in sync.
- LSP diagnostics 7 → 12. The VS Code extension moved to 0.1.0 with per-platform
  packaging.
- **A failing run now exits non-zero.** It previously exited `0`.

### Fixed

- Hash literal and LSP formatter fixes; operator parity between the two engines;
  nopsled and polymorphic correctness fixes.

## [2.3.0] — 2026-08-11

### Added

- The forensic suite in depth: MFT, prefetch, registry, `fs_deleted`, syslog,
  SQLite and regex builtins, link builtins, process listing, and process
  injection detection.
- Higher-order collection functions; `&&` and `||` operators.
- Workshop functions and example programs.

### Changed

- Parser, formatter and extension updates; SQLite excluded from the WASM build.

## [2.2.0] — 2026-07-14

### Added

- Interactive REPL tab completion with context-aware ranking; shared help docs
  across the REPL and web surfaces.
- The WASM REPL and automatic WASM builds; LSP build scripts and extension
  packaging.

### Changed

- Compiled bytecode is compressed. Multi-value returns were reworked, and `len`
  returns a single object.
- Sandbox detection updated; macro fixes.
- Moved to the `aoiflux` domain and the AGPL-3.0 licence.

### Removed

- An earlier round of environment variables, and large files from the tree.

## [2.1.0] — 2026-06-28

### Added

- The polymorphic bytecode engine; sandbox, VM and debugger detection; deep
  binary protection and randomised in-code security checks.
- Sandboxed Lua: a bytecode integration, an executor with timeouts and scrubbed
  errors, and pre-VM Lua patch execution under tamper policy.
- Structs, enums, loops, float types and the modulo operator; encrypted structs
  and enums; command execution; many builtins.
- Dynamic stack size, global size and frame limits.

### Changed

- Moved to a pure-Go implementation; improved runtime encryption and security
  logging.

## [2.0.1] — 2022-06-26

### Added

- Graceful exit handling.

### Changed

- Go version upgrade.

## [2.0.0] — 2021-06-02

### Added

- `mutant release` — standalone compiled binaries for multiple platforms, with
  per-platform binary formats and extensions.
- A basic CLI with help and argument validation.

## [1.0.1] — 2021-03-29

Documentation only.

## [1.0.0] — 2021-03-22

Initial release: the language, the compiler, the VM, and encrypted bytecode.

[Unreleased]: https://github.com/aoiflux/mutant/compare/v2.5.0...HEAD
[2.5.0]: https://github.com/aoiflux/mutant/compare/v2.4.0...v2.5.0
[2.4.0]: https://github.com/aoiflux/mutant/compare/v2.3.0...v2.4.0
[2.3.0]: https://github.com/aoiflux/mutant/compare/v2.2.0...v2.3.0
[2.2.0]: https://github.com/aoiflux/mutant/compare/v2.1.0...v2.2.0
[2.1.0]: https://github.com/aoiflux/mutant/compare/v2.0.1...v2.1.0
[2.0.1]: https://github.com/aoiflux/mutant/compare/v2.0.0...v2.0.1
[2.0.0]: https://github.com/aoiflux/mutant/compare/v1.0.1...v2.0.0
[1.0.1]: https://github.com/aoiflux/mutant/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/aoiflux/mutant/releases/tag/v1.0.0
