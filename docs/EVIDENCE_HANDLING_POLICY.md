# Evidence Handling Policy

**Mutant does not modify evidence.** An image, volume, partition table, registry
hive, archive or captured artifact opened by a Mutant program is read and never
written, and the chain-of-custody manifest states that as a fact about the tool
rather than as a promise about the program.

This document states the rule, why it is worth writing down when it already
held, which writes are permitted and why, and how the rule is checked.

The rule is machine-enforced. See [The guard](#4-the-guard) below.

---

## 1. The rule

**No code that reads evidence may ask the operating system to change anything on
disk**, except at a reviewed site that touches somewhere other than the evidence.

Every backend opens its source with `os.Open`, which is a read-only handle: the
kernel itself refuses a write through it. That is the mechanism. The policy is
the guarantee that it stays that way.

### Why write it down if it already holds

Because "we checked and it looked fine" is not something an examiner can testify
to, and because the invariant is one careless patch away from ending. A forensic
tool's read-only claim is load-bearing in a way that most correctness claims are
not: the thing it protects — the original — cannot be restored if the claim turns
out to be false.

There is a second reason. `case_manifest()` (F-1) writes
`integrity.evidence_read_only: true` into a document that may be handed to a
court. A manifest that asserts something nobody verifies is worse than a manifest
that says nothing, because it looks like verification. The guard is what makes
the assertion true.

That sentence was once worth less than it reads. The guard checks the files it is
given, and for a time it was given a list that twelve evidence files had been
added without -- among them the one holding the `os.Open` behind every `*_open`
family, and the one that writes recovered files. The manifest kept asserting
`evidence_read_only: true` the whole while. The list is now derived for the image
and filesystem family, so an omission there fails the build; section 4 says
exactly how far that reaches and what is still a judgement (M26-TEST-009).

## 2. What counts as evidence-reading code

The list is a declaration in source —
[`policy.EvidenceReadOnlyFiles`](../policy/evidence_policy.go) — because "this
file reads evidence" is a judgement about what the code is for. For one family it
is no longer only a judgement: see **the derived half** below.

It covers disk images and volumes (`raw`, `ewf`, `vhdi`, `ntfs`, `fat`, `xfat`,
`ext`, `hfs`, `xfs`, partition tables) and their extent, capability, deleted,
journal, slack, verify, xattr and report surfaces; the two seams every one of
those goes through, which are `fsRegion` for the part of a file a filesystem
occupies and `fsFileReader` for reading a file out of one; deleted-file recovery,
including the write that puts a recovered file where the examiner asked for it;
type identification on a path the examiner named; registry hives (`hive_*`,
`reg_*`, Amcache, Shimcache); archives (`zip_*`, `tar_*`); the Windows execution
artifacts (MFT, EVTX, Prefetch, LNK, Jump Lists); browser and SQLite artifacts;
bodyfiles, plists, syslog and email; and live process memory. It also covers the
custody builtins (`evidence_intake`, `evidence_accept` and the rest), which open
the file an exhibit is taken in or handed over as only to hash it, and the place
an open is recorded against the exhibit it was made on.

### The derived half

A file that reads a disk image or a filesystem can be recognised from its source
without anyone deciding to add it, by three facts:

- it imports an aoiflux `lib*` or `partition` package -- the readers for ewf,
  vhdi, ntfs, fat, xfat, ext, hfs, xfs and partition tables;
- it uses the `fsRegion` type, which every `*_open` family goes through;
- it uses the `fsFileReader` type, which every streaming read goes through.

`TestEveryImageReaderIsUnderTheGuard` fails when a file with one of those is
absent from the list. When it was written it named twelve.

What it cannot recognise is a parser of a captured artifact -- an EVTX log, a
LNK, a plist. Those open a path and read bytes, with nothing in the source to
tell them apart from most of the standard library, so they are still a judgement
and leaving one off is still caught by nothing. That is the soft edge of this
policy, and it is narrower than it was: the judgement is no longer load-bearing
for the family the policy was written for.

### Custody is recorded, and deletes nothing

An exhibit taken into a case with `evidence_intake` is held by the examiner who
took it in; `evidence_release` puts it in transit to another examiner the case
assigns, and `evidence_accept` records them taking it after hashing what they
were handed. `evidence_return` returns it out of the case; if it comes back,
`evidence_intake` takes it in again under its own name and hashes what came back
against what was first taken in, so a returned exhibit is never taken back on
trust. `evidence_dispose` ends its custody. Each step is written to the case's
ledger -- a hand-off by the person the ledger says holds the exhibit, an accept
by the person it was released to -- and every reader refuses a history that
forks, skips a step, or has either recorded by anybody else. **A disposal is a
statement.** It deletes nothing -- not the file the exhibit was taken in from,
and not any copy -- and says so in its result. It is refused while the case is
under a legal hold placed with `retention_hold`, until `retention_release`
lifts it. A case is disposed of the same way: `case_transition(ledger,
"disposed", reason)` records it and deletes nothing, and only once no hold is in
force, the retention period has run, every exhibit is returned or disposed of,
and the case key is erased. `record_erase` and `case_key_erase` do write: they
overwrite a record's key in one copy of the record, and the case key in its key
file. Both are the case's own files and not evidence -- the evidence a record
was sealed from is not touched -- and both are refused under a legal hold too.

**A new evidence family belongs on that list.** Leaving it off is the one soft
edge of this policy: nothing catches an omission automatically, which is why the
list is short, grouped and commented.

## 3. The permitted writes

Each writes somewhere other than the evidence. That is the bar.

| Site | What it writes | Why |
| --- | --- | --- |
| `withSQLiteCopy` / `copyFileContents` | `os.MkdirTemp`, `os.Create`, `os.RemoveAll` | This one is the policy in action rather than an exception to it. SQLite wants to write a journal beside any database it opens, so an evidence database is **copied** into a temp directory and queried there. The copy is not on its own what keeps the original safe, and M26-DAT-001 is why: the copy is opened read-only and the connection may attach no database at all, so ATTACH and VACUUM INTO are refused and no statement reaches a file other than the copy. |
| `fsWriteEvidenceFile` | `os.OpenFile` with `O_WRONLY\|O_CREATE\|O_EXCL`, and `os.Remove` | Recovery writes the file it recovered, which is the point of recovering it. The destination is a path the examiner named for output and never the image. `O_EXCL` means it refuses to write over anything already there, and the `os.Remove` only undoes a destination this function created moments earlier and then failed to fill. Neither line can reach the evidence, which is open read-only in another handle entirely. |

They are recorded in
[`policy.EvidenceWriteAllowlist`](../policy/evidence_policy.go) with an exact
line count, so a new write added inside an already-permitted function still fails
the guard.

There were two. `realXFATSession.ReadFile` wrote an exFAT file's content to
`os.CreateTemp` and read it straight back, because extracting to a path was the
only way libxfat would part with content. libxfat v1.3.0 added a reading API and
the exception was retired rather than rewritten -- the guard reported it as a
hole the moment the write went away, which is the behaviour this list is for.

### The distinguishing test

> **Which bytes does this write touch — the examiner's, or the evidence's?**

A temp file, a working copy, an output report the program was asked to produce:
the examiner's. Anything reachable from the path a `*_open` builtin was handed:
the evidence's, and it does not belong in this code at all.

## 4. The guard

[`policy/evidence_guard_test.go`](../policy/evidence_guard_test.go) parses every
file in the list and fails on any call that mutates the filesystem outside the
allowlist. It runs as part of an ordinary `go test ./...`.

Six checks:

1. **`TestEvidenceCodeNeverWrites`** — the policy itself, plus the pinned line
   counts.
2. **`TestEveryImageReaderIsUnderTheGuard`** — every file that reads a disk image
   or a filesystem is in the list, derived from its source rather than taken on
   trust. It also fails if no file carries any of the three markers, because a
   check that finds nothing would otherwise agree with whatever the list said.
3. **`TestTheMutatorRuleSeesEveryWayToOpenForWriting`** — the rule is run against
   source written for the purpose, which pins both the calls it must report and
   the ones it must not.
4. **`TestEvidenceWriteAllowlistHasNoStaleEntries`** — a renamed or deleted
   function must not leave a permanent hole.
5. **`TestEvidenceWriteAllowlistEntriesAreWellFormed`** — every exception is
   justified in prose.
6. **`TestEvidencePolicyNamesFilesThatExist`** — the guard can see what it
   guards.

### What the guard looks for

`Create`, `CreateTemp`, `WriteFile`, `Remove`, `RemoveAll`, `Rename`,
`Truncate`, `Chmod`, `Chown`, `Lchown`, `Chtimes`, `Mkdir`, `MkdirAll`,
`MkdirTemp`, `Symlink`, `Link` and `NewFile`, matched on the selector rather than
the package qualifier, which catches an aliased import and a method on an
`*os.File` with one rule. `NewFile` is there because it hands back a writable
`*os.File` for a descriptor opened somewhere the guard cannot see.

Three opens do not say in their name which way they go, so they are judged on
their flag argument instead: `os.OpenFile`, `syscall.Open` and `unix.Open`
(anything but exactly `os.O_RDONLY` counts as writable), and
`windows.CreateFile`, whose second argument is a desired-access mask and never
`O_RDONLY`, so it always reports and always needs an entry with a reason. Only
`OpenFile` was judged for a time, which let `syscall.Open` with `O_RDWR` through
(M26-TEST-009). `os.Open` is not judged and never reports: it takes one argument
and is read-only by definition.

These three are matched on the package behind the receiver, resolved through the
file's own import list, and not on the selector. `Open` is the commonest method
name in forensics -- `backend.Open(volumePath, region)` opens an NTFS volume
read-only in seven `*_open` builtins -- and matching the name reported ten
read-only opens as writable. Resolving the import also means an aliased
`zsys "syscall"` is judged exactly as `syscall` is.

### What it deliberately does not look for

`Write` and `WriteString`. Writing to a file needs a handle opened for writing,
and every way to obtain one is already on the list above — so catching the
*opening* catches the writing, and the guard never has to decide whether a bare
`.Write(...)` is going to a file, a hash or a string builder. A rule that cannot
produce a false positive is a rule nobody switches off.

That last sentence used to be a claim this guard did not meet. Matching a
mutator's name wherever it appeared, and not only where it is called, read
`entry.Link` in a filesystem report -- a struct field whose name collides with
`os.Link` -- as a filesystem mutation. It went unseen because the file holding it
was one of the twelve missing from the list. A mutator is now reported where it
is called, or where it is taken as a value from an identifier the file imports as
a package; a field read is neither. What that gives up is a method value taken
from a file handle rather than from a package, which nothing here does and which
no longer costs a false report to catch.

### What it cannot check

A third-party library that writes through a handle Mutant gave it. Mutant's
defence there is the handle itself: the backends pass `os.Open` results, so a
write attempt fails at the operating system rather than at a lint rule.

## 5. What this is not

This policy governs code that **reads** evidence. It says nothing about
`fs_write`, `fs_delete`, `fs_move` or the report-writing builtins, which exist to
modify files and are the analyst's own tools. The language server's
`evidenceMutation` rule (T-2) is the check that those are not aimed at a path the
same program opened as evidence — a different question, asked of the program
rather than of Mutant.

## 6. See also

- [`docs/CONFIGURATION_POLICY.md`](CONFIGURATION_POLICY.md) — the other
  machine-checked policy in `policy/`.
- [`docs/CAPABILITY_REFERENCE.md`](CAPABILITY_REFERENCE.md) — the chain-of-custody
  builtins (`case_open`, `case_evidence`, `case_verify`, `case_manifest`).
