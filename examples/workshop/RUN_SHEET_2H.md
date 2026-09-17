# QUILLDROP — 2-hour run sheet

A minute-by-minute plan for the hands-on session. **No slides required.** The
only things on screen are a terminal and a text editor.

Read [CASE_QUILLDROP.md](CASE_QUILLDROP.md) first — it is the story everything
hangs on. Build the evidence before the room arrives (see
[evidence/README.md](evidence/README.md)).

---

## The shape of it

Six tools, one case, each answering the question the previous one raised. Every
block is the same rhythm:

| | |
|---|---|
| **5 min** | *I build it.* You type, they watch. Talk while you type. |
| **10 min** | *They build it.* They type. You walk the room. |
| **5 min** | *The twist.* Run it, something surprising happens, explain why. |

Cut any block and the rest still works. If you are running short, cut **12** and
shorten **10**. Never cut **13** (it earns everything else) or **11** (it is the
ending).

---

## 0:00 – 0:10 — Cold open

Do **not** introduce the language. Do not show a feature list.

1. Read the client brief from `CASE_QUILLDROP.md` out loud. 90 seconds.
2. Run `11_verdict.mut`. Let the finished, signed case report scroll past.
3. Say: *"That is where we finish. Everything between here and there, you write."*
4. Close it. Do not explain it yet.

Then the two housekeeping facts, and only these two:

```
mutant run tool.mut        # compiles .mut -> .mu
mutant     tool.mu         # runs it
```

> **Run from PowerShell or cmd, not Git Bash or WSL.** Mutant's secure mode
> detects an analysis-sandbox-looking host and halts before executing. Under Git
> Bash it sees WSL indicators and stops with `sandbox detected, execution
> halted`. Either use a native shell, or pass `--compat` (which only downgrades
> the response to a warning — the password and artifact verification still
> apply). **Test this on the room's machines beforehand.**

---

## 0:10 – 0:20 — Setup, together

Everyone runs the evidence builder. Everyone ends up with **byte-identical
evidence**, because it is generated from a seed.

```
.\examples\workshop\evidence\build_evidence.ps1      # Windows
sh   examples/workshop/evidence/build_evidence.sh    # Linux/macOS
```

Say why this matters now, not later: *"Your evidence and mine are the same
bytes. So at the end, your report and my report will have the same SHA-256. If
they don't, one of us made a mistake, and we'll be able to tell which."*

Sanity check everyone is alive:

```
mutant run examples/workshop/ioc_extract.mut
mutant     examples/workshop/ioc_extract.mu
```

---

## 0:20 – 0:40 — **13_hexeye.mut** — "be the parser"

**This is the hook. Do it first, even though it is numbered last.**

- **5 min** — Write the `hexdump` function live. It is ~15 lines and it is a
  *real* hex editor. Point it at `sample_win.exe`. Let them see `4D 5A` and the
  `MZ` in the ASCII column, and tell them whose initials those are.
- **10 min** — They walk the header by hand: byte at `0x00`, pointer at `0x3C`,
  follow it, `PE\0\0`, then machine / section count / **TimeDateStamp**.
- **5 min** — The twist: the timestamp reads `0` → *1970*. Somebody scrubbed
  the build time, and that is itself a finding. Then run `bin_pe_parse`,
  `bin_sections`, `imphash`, `go_symbols` and show the hand-read numbers match
  exactly.

**Land this line:** *"There is no step in any forensic tool harder than: read a
byte, read a pointer, follow it, read a table. There are only more offsets."*

Best moment: `go_symbols` recovering 21 function names out of a **stripped** Go
binary. Go's runtime needs the symbol table for stack traces, so stripping
cannot remove it.

---

## 0:40 – 1:00 — **07_dropzone.mut** — how did it get in?

- **5 min** — Magic-vs-extension. A `.pdf` whose first two bytes are `MZ`.
- **10 min** — They add the **Mark-of-the-Web** reader. This is the moment:
  `fs_read(path + ":Zone.Identifier")` — no special builtin, just an NTFS
  alternate data stream addressed by appending to the path. Out falls the exact
  URL the file was downloaded from.
- **5 min** — The correlation. That URL's domain also appears in the phishing
  email on the same disk. Two artifacts, written by two programs that never
  spoke to each other, agreeing. *That* is a finding; a suspicious file is not.

Then show `detect_suspicious_files()` doing the scoring in one call — **after**
they wrote it themselves, never before. *"You cannot defend a finding you got
from a function you can't explain."*

**Watch for:** non-NTFS filesystems have no MoTW. The tool says so honestly
rather than reporting nothing found. Use that: "found nothing" and "cannot look"
are different answers.

---

## 1:00 – 1:20 — **08_supertimeline.mut** — in what order?

- **5 min** — `bodyfile_parse` + `mactime`. Four timestamps per file; the live
  filesystem only gives you one.
- **10 min** — `events_from(rows, "bodyfile")`, then merge in the email's `Date:`
  header and the implant's own log. One vocabulary, three source families.
- **5 min** — **Sigma.** Paste in four YAML rules and run `sigma_scan` over the
  timeline. Real detection rules, executing in the language, no SIEM.

Two things to point at:

1. `unmatched_fields` — the fields **no event carried**. A rule that could not
   have fired is not a host that came back clean. No coverage report tells you
   this.
2. **The twist, and it is free:** three of the hits are dated **2024** — before
   the email that delivered them. Sigma is not wrong. The bodyfile is not wrong.
   The *filesystem* is repeating what the attacker told it.

Hold the silence there. That is the setup for the next block.

---

## 1:20 – 1:25 — Break

---

## 1:25 – 1:45 — **09_revenant.mut** — where did they lie?

Open with the line on the board:

> **You cannot delete a fact. You can only create a contradiction.**

- **5 min** — TELL 1: `mtime < crtime`. Modified before it was born. One
  `filter`, and it is not "unusual", it is *impossible*.
- **10 min** — TELL 2, which is the real one: **`ctime` long after `mtime`**.
  Setting a timestamp *is* a metadata change, so the kernel stamps the moment of
  the lie onto the record. The attacker picked the mtime; they did not get to
  pick the ctime. It reads `12 March 00:10` — that is *when they did it*.
- **5 min** — TELL 3 (four files sharing one exact second: a script, not a
  person) and TELL 4 (`seq 60 → 97`: 36 beacons cut out of a log whose own
  counter kept score).

**If you built the NTFS image** (`evidence/make_ntfs_image.ps1`, admin, once,
beforehand), set `MFT_PATH` and run TELL 6 for the real thing: NTFS stores every
timestamp **twice**, and `$FILE_NAME` is kernel-written and unreachable from the
ordinary API. Four independent tells, scored together. See the notes at the end
of this sheet.

---

## 1:45 – 2:00 — **10_quarry** (short) then **11_verdict** (the ending)

Run `10_quarry.mut` rather than building it — you are short on time, and its
payoff is in the output.

- The zip is opened and **never extracted**. Only the central directory is read.
- Each member's stored **CRC-32** is compared against the CRC-32 of the original
  still sitting in `Documents`. 18 documents proven **byte-identical**, without
  decompressing anything. *"The attacker wrote you an inventory list and called
  it a zip."*
- 6 of them are HR records. That is a notification clock starting.
- Then the beacon detector says **nothing found** — because the log tampering
  left one enormous gap that wrecks the variance. Split the series at the hole
  09_revenant found, re-run, and it comes back **CV 0.00, score 100, confidence
  high**. *Anti-forensics is not a wall. It is a signpost.*

Finish with `11_verdict.mut`:

> **Analysis is what you did. Evidence is what you can prove you did.**

`case_open` → evidence registered with digests → every builtin that touched each
source counted → findings written → sealed with SHA-256 + Ed25519 → `case_bundle`
writes a handover anybody can check with `sha256sum -c`.

**The closer:** the tool edits one phrase in its own report and re-checks the
digest. It fails. The signature still verifies — and now *proves* the report
beside it is not the report that was produced. Then it restores the file.

Last line: *"Regenerate the evidence from the seed, re-run these tools, and you
get the same digests. That is the difference between an opinion and a result."*

---

## If you have 30 more minutes

- **12_imposter / deeper binary triage** — `imphash` for family clustering,
  `go_types`, `bin_yara_scan`, `mem_find_shellcode`.
- **Registry** — `hive_open` / `amcache_parse` / `shimcache_parse`, or
  `reg_open` against the student's own live registry.
- **Let them write one Sigma rule** for something they noticed in tool 7 and
  watch it fire without touching any other file.

---

## Language gotchas — put this on a card on every desk

Every one of these was hit while writing these tools. They cost minutes each if
you have not seen them.

| Gotcha | What happens | Fix |
|---|---|---|
| Fallible builtins return `(value, err)` | Nesting one passes the *pair*: `got MULTI_VALUE` | `let v, e = f(x);` then use `v` |
| No `null` literal | `undefined variable: null` | a bare `return;` yields null; test with `is_null()` |
| No string literal inside `${...}` | parser error naming the line **inside** the string | bind a local first, then `${local}` |
| Builtins are not values | `map(xs, defang)` fails | `map(xs, fn(d) { return defang(d); })` |
| **`while` / C-style `for` inside a `for…in`** | `loop cursor was replaced on the stack` | use `for (i in range(a, b))`, which nests fine |
| `regex_find_all(p, s, 0)` | returns nothing — `0` is a limit | omit the third argument |
| Semicolons after block statements | parse error | `if (c) { … };` and `let f = fn(){ … };` |
| Git Bash / WSL | `sandbox detected, execution halted` | run in PowerShell/cmd, or pass `--compat` |
| `-pwd` flag | deprecation warning on every run | omit it and be prompted, or `--password-stdin` |

---

## Facilitator prep checklist

- [ ] `fsagen` installed; `build_evidence` run once and the output checked in or
      on a USB stick, so a student with no Go toolchain is not stuck
- [ ] Validate the playbook against `fsagen --generate-schema .` (fsagen moves;
      the `.mut` tools depend on the **paths**, not the YAML)
- [ ] Every tool compiled once on the room's OS — `07` and `13` touch NTFS
      features and behave differently on ext4/APFS (honestly, but differently)
- [ ] `mutant.exe` on PATH, or tell them the full path
- [ ] **Optional but worth it:** `evidence/make_ntfs_image.ps1` run once, as
      admin, to produce a real `$MFT` with a real timestomp in it. Ship the
      exported `case_quilldrop.mft` and students need no admin at all.
- [ ] Decide the password story: everyone types the same one (`workshop`), or
      everyone is prompted. Do not let people improvise at minute 12.
