# Evidence Handling Policy

**Mutant does not modify evidence.** An image, volume, partition table, registry
hive, archive or captured artifact opened by a Mutant program is read and never
written, and the chain-of-custody manifest states that as a fact about the tool
rather than as a promise about the program.

This document states the rule, why it is worth writing down when it already
held, what the two permitted exceptions are, and how the rule is checked.

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

## 2. What counts as evidence-reading code

The list is a declaration in source —
[`policy.EvidenceReadOnlyFiles`](../policy/evidence_policy.go) — rather than a
pattern match on file names, because "this file reads evidence" is a judgement
about what the code is for.

It currently covers disk images and volumes (`raw`, `ewf`, `vhdi`, `ntfs`, `fat`,
`xfat`, `ext`, `hfs`, `xfs`, partition tables), registry hives (`hive_*`,
`reg_*`, Amcache, Shimcache), archives (`zip_*`, `tar_*`), the Windows execution
artifacts (MFT, EVTX, Prefetch, LNK, Jump Lists), browser and SQLite artifacts,
bodyfiles, plists, syslog, email, deleted-file recovery, and live process memory.

**A new evidence family belongs on that list.** Leaving it off is the one soft
edge of this policy: nothing catches an omission automatically, which is why the
list is short, grouped and commented.

## 3. The one exception

It writes somewhere other than the evidence. That is the bar.

| Site | What it writes | Why |
| --- | --- | --- |
| `withSQLiteCopy` / `copyFileContents` | `os.MkdirTemp`, `os.Create`, `os.RemoveAll` | This one is the policy in action rather than an exception to it. SQLite wants to write a journal beside any database it opens, so an evidence database is **copied** into a temp directory and queried there — which is exactly why the original is never opened by something that would modify it. |

It is recorded in
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

Four checks:

1. **`TestEvidenceCodeNeverWrites`** — the policy itself, plus the pinned line
   counts.
2. **`TestEvidenceWriteAllowlistHasNoStaleEntries`** — a renamed or deleted
   function must not leave a permanent hole.
3. **`TestEvidenceWriteAllowlistEntriesAreWellFormed`** — every exception is
   justified in prose.
4. **`TestEvidencePolicyNamesFilesThatExist`** — the guard can see what it
   guards.

### What the guard looks for

`Create`, `CreateTemp`, `WriteFile`, `Remove`, `RemoveAll`, `Rename`,
`Truncate`, `Chmod`, `Chown`, `Lchown`, `Chtimes`, `Mkdir`, `MkdirAll`,
`MkdirTemp`, `Symlink`, `Link`, and `OpenFile` with any flag other than
`os.O_RDONLY`. Matching the selector rather than the package qualifier catches an
aliased import and a method on an `*os.File` with the same rule.

### What it deliberately does not look for

`Write` and `WriteString`. Writing to a file needs a handle opened for writing,
and every way to obtain one is already on the list above — so catching the
*opening* catches the writing, and the guard never has to decide whether a bare
`.Write(...)` is going to a file, a hash or a string builder. A rule that cannot
produce a false positive is a rule nobody switches off.

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
