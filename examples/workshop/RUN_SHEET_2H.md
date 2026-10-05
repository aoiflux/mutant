# QUILLDROP — two-hour run sheet

Ten beats, about ten minutes each, with a break after six. Every beat has the
same shape:

- **2 min** — ask the question, out loud, before anyone opens an editor.
- **5 min** — they write it. The file is under eighteen lines; they can.
- **3 min** — run it, and read the one line that is not what they expected.

The files are deliberately comment-free. The teaching is in the question you
ask before they type, and in the output afterwards. Do not read the code to
them.

## Before anyone arrives

1. `go install github.com/aoiflux/fsagen@v0.1.0` — the version, not `@latest`,
   which is now v0.2.0 — and run
   `.\examples\workshop\evidence\build_evidence.ps1` on your own machine.
   Confirm it finishes and check the file count against
   [evidence/README.md](evidence/README.md): **98 files, 131 timeline rows**.
   Generate on **NTFS**. On a volume with no birth time the script still
   produces a corpus, but the timeline has no creation times and beat 6's
   central finding cannot fire. Measured on WSL ext4; **APFS is unmeasured and
   may well keep it**, so do not tell a Mac attendee they have lost the beat --
   the script checks the timeline it just wrote and says so when it happens.
   Where it does, hand that attendee the pre-built corpus instead: what it is,
   and how they check it, is *Where the pre-built corpus comes from* in
   [evidence/README.md](evidence/README.md).
2. **Add a Defender exclusion for the corpus folder**, and generate somewhere
   Windows Search does not index. Defender's ML detection refuses writes of
   generated PE files and its verdict is not stable across runs; Windows Search
   adds an `OECustomProperty` stream to `.eml` files in indexed folders within
   seconds, which would corrupt beat 3.
3. Build or download **v2.5.0**. The story uses only v2.5.0 builtins; running it
   on a newer build is fine, but the release is what attendees will have.
4. Decide the password story. `--dev` is simplest and is what the README
   teaches; if you want them to feel the key material, use `--password-stdin`.
5. Tell everyone: **PowerShell or cmd, never Git Bash.** The sandbox detector
   scores Git Bash on Windows as WSL at confidence 90 and halts.

---

## 0:00 — 0:10  Cold open

Read [CASE_QUILLDROP.md](CASE_QUILLDROP.md) aloud. Ninety seconds.

Then run `10_seal.mut` on your own prepared case and let the two `true`s land.
"That is where we finish. Nothing between here and there is longer than
eighteen lines."

Then everyone runs `build_evidence.ps1` and `run.ps1 01_scene`.

## 0:10 — 0:20  Beat 1 — the scene

**Ask:** you have a folder. Before you open anything, what can you say about it?

`fs_walk` gives you every object. `fs_entropy` gives you one number per file.

**The twist:** the archive in `Temp` scores as high as the scrambled
spreadsheets. Compression and encryption look identical to entropy. Entropy
found you something; it did not tell you what.

## 0:20 — 0:30  Beat 2 — the lure

**Ask:** who wrote to this person, and what did they want them to do?

`email_parse` on the `.eml`. Then `extract_iocs` on the body — one call, every
URL.

**The twist:** the attachment's name has two extensions. Write it down; it is
the first line of the next file.

## 0:30 — 0:40  Beat 3 — the download

**Ask:** is that file what its name says it is, and how did it get here?

Three artifacts, three independent answers: `fs_magic` reads the header,
`fs_read(path + ":Zone.Identifier")` reads the alternate data stream Windows
attached when it was downloaded, and `sqlite_query` reads Chrome's history.

**The twist:** all three agree, and the host in the ADS is the host in the
email from beat 2. That is corroboration, and it is what turns a finding into a
conclusion.

*NTFS only.* On ext4 or APFS the ADS is not there and that line reports
nothing, which is the honest answer.

## 0:40 — 0:50  Beat 4 — the binary

**Ask:** what is the thing in AppData?

`bin_pe_parse`, then `timestamp_normalize` on the field it returns, then
`imphash`.

**The twist:** it was built on **1 January 1970**. The PE's `TimeDateStamp` is
zero — scrubbed. The absence of a build date is itself a finding, and the
imphash still clusters it against anything else built from the same imports.

## 0:50 — 1:00  Beat 5 — the day

**Ask:** what happened, and in what order?

`bodyfile_parse` gives you four times per object. `mactime` collapses them into
one row per distinct instant with a MACB flag string.

**The twist:** count the rows against the moments. Four timestamps per file
does not mean four events — most files were born, written and read in the same
second, and `mactime` says so with `macb`.

## 1:00 — 1:10  Beat 6 — the contradictions

**Ask:** which of those times cannot be true?

Two tests, one loop. `mtime < crtime` — a file modified before it existed.
`fs_exists` false on a path the timeline names — something that was there and
is not.

**The twist:** the archive claims 2024. The staging folder claims to have
existed at all. Both claims came from the same person, and they cannot both be
managed by deleting things: the deletion is what left the second one visible.

## 1:10 — 1:15  Break

## 1:15 — 1:25  Beat 7 — the inventory

**Ask:** what left, and can you answer without opening the archive?

`zip_open` reads the central directory only. `zip_entries` gives you every
member's name, size, CRC-32 and date. Nothing is decompressed — the script
prints `never decompressed` and it is literally true.

**The twist:** the member dates predate the archive. Whoever made it did not
create these files; they collected them.

## 1:25 — 1:35  Beat 8 — the rules

**Ask:** what does somebody else's detection library say about your timeline?

`events_from(rows, "bodyfile")` normalizes your bodyfile into the interchange
vocabulary. `sigma_scan` runs [quilldrop.sigma.yaml](quilldrop.sigma.yaml) over
it, and reports per rule.

**The twist:** the critical rule fired **zero** times, and the last line says
why: `fields no event carried: [CommandLine]`. A bodyfile has no command lines.
That rule did not clear the host — it never ran. A detection stack that reports
"0 alerts" without reporting that is telling you nothing.

## 1:35 — 1:50  Beat 9 — the verdict

**Ask:** hand this to a lawyer. What has to be in the envelope?

`case_open` with a hash policy, `case_evidence` per exhibit, `case_note` for
your conclusion, `case_bundle` to write it out, `case_close`.

**The twist:** compare exhibit digests across the room. They match — the
evidence is the same bytes everywhere. Now compare the manifest hash. It does
not match, and it must not: it records when *you* opened the case. Reproducible
evidence, singular custody.

## 1:50 — 2:00  Beat 10 — the seal

**Ask:** can a reader tell if you changed the report after you signed it?

`case_manifest_verify` on the manifest alone — no key the reader does not
already have, no case still open.

**The closer, do this live:** open `handover/report.md`, change one word, save.
Re-run `10_seal.mut`.

`hash_matches` is still `true` and `signature_valid` is still `true` — the
manifest verifies itself and nobody touched the manifest. But the `report.md`
digest on the last line has moved, and it no longer matches what the manifest
recorded when the bundle was written. The seal did not catch the edit; the
*digest the seal covers* did. That difference is the whole of what chain of
custody buys you. Put the word back and run it once more.

---

## If you have thirty more minutes

- Write a fourth Sigma rule against a field the bodyfile *does* carry
  (`path`, `size`, `ts_desc`) and watch it fire.
- Point `06_lies.mut` at a timeline you generated with a different seed.
- Open [lib/quilldrop.mut](lib/quilldrop.mut) and ask why `ready()` returns a
  boolean instead of raising.
- Pick anything from the snippets table in [README.md](README.md).
