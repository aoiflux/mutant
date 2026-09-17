# Forensic Tooling Workshop (in Mutant)

A build-it-from-first-principles walkthrough of writing forensic and security
tools. Every file is a small, standalone `.mut` program you can read, run, and
live-code in a couple of minutes.

The methodology is language-agnostic; Mutant is just the vehicle. The four core
ideas — **artifact modeling**, **timestamp normalization**, **timeline
construction**, and **custom analysis logic** — are the same in any language.

## The core sequence (read in order)

| # | File | Teaches | Input |
|---|------|---------|-------|
| 1 | [01_artifact_modeling.mut](01_artifact_modeling.mut) | Model entities + relationships as a graph | none |
| 2 | [02_timestamp_normalization.mut](02_timestamp_normalization.mut) | Turn any epoch (FILETIME/WebKit/unix/ISO) into a common form | none |
| 3 | [03_timeline_construction.mut](03_timeline_construction.mut) | Merge multi-source events into one ordered supertimeline | none |
| 4 | [04_custom_analysis_logic.mut](04_custom_analysis_logic.mut) | Score/flag artifacts with your own rules (map/filter) | none |
| 5 | [05_timestomp_detection.mut](05_timestomp_detection.mut) | Detect NTFS timestomping (SI vs FN timestamps) | **an NTFS `$MFT`** |
| 6 | [06_malvertising_chain.mut](06_malvertising_chain.mut) | Cross-check two artifacts against each other: reconstruct redirect chains from history, then find the hosts that set a cookie without ever appearing in it | two shipped fixtures |

---

## Case QUILLDROP — the 2-hour hands-on workshop (7–13)

The files above teach the *method* one idea at a time. The files below apply all
of it to **one intrusion**, start to finish, as a 2-hour build-it-yourself
session. Each tool answers the question the previous one raised.

- **[CASE_QUILLDROP.md](CASE_QUILLDROP.md)** — the story. Read it first.
- **[RUN_SHEET_2H.md](RUN_SHEET_2H.md)** — minute-by-minute plan, no slides.
- **[evidence/README.md](evidence/README.md)** — generating the evidence with
  [`fsagen`](https://github.com/aoiflux/fsagen), seeded so every student's
  evidence — and therefore every student's report digest — is identical.

| # | File | The question it answers | Headline move |
|---|------|------------------------|---------------|
| 13 | [13_hexeye.mut](13_hexeye.mut) | *What is actually in this file?* | Write a hex editor, walk a PE header by hand, then check yourself against `bin_pe_parse`. **Run this first** — it earns everything else. |
| 7 | [07_dropzone.mut](07_dropzone.mut) | *How did it get in?* | Read the NTFS **Mark-of-the-Web** stream — the download's origin URL — and match it to the phishing email. |
| 8 | [08_supertimeline.mut](08_supertimeline.mut) | *What happened, in what order?* | `bodyfile` → `mactime` → `events_from` → **Sigma rules running in the language**, then out as Timesketch/ECS/OCSF. |
| 9 | [09_revenant.mut](09_revenant.mut) | *Where did they lie to me?* | Six anti-forensics tells, including SI-vs-FN `$MFT` analysis at 100 ns resolution. |
| 10 | [10_quarry.mut](10_quarry.mut) | *What did they take?* | Prove 18 documents were stolen by **CRC-32**, without ever extracting the archive. Then beat the beacon detector's blind spot. |
| 11 | [11_verdict.mut](11_verdict.mut) | *Will this survive a lawyer?* | Chain of custody, Ed25519-signed manifest, and a live tamper test that fails on purpose. |

Supporting files under `evidence/`:

| File | What it does |
|---|---|
| `quilldrop.playbook.yaml` | the fsagen playbook that synthesizes the intrusion |
| `build_evidence.ps1` / `.sh` | one command to produce the corpus + bodyfile |
| `make_ntfs_image.ps1` | facilitator-only, admin, once: builds a **real** NTFS volume with a **real** timestomp, for genuine `$MFT` analysis |
| `export_mft.mut` | reads an NTFS boot sector and carves out the `$MFT` by hand — five integer reads and a filesystem appears |

### The three lines the workshop is built on

1. **You cannot delete a fact. You can only create a contradiction.** (tool 9)
2. **The attacker wrote you an inventory list and called it a zip.** (tool 10)
3. **Analysis is what you did. Evidence is what you can prove you did.** (tool 11)

---

## More examples to pick from (each self-contained, ~15–25 lines)

Short, standalone snippets — great for "here's a thing Mutant makes easy" moments.
All run with **no input**.

| File | "Mutant makes it easy to…" |
|------|----------------------------|
| [ioc_extract.mut](ioc_extract.mut) | pull every IP / domain / URL / email / hash out of a blob of text in one call, then defang it |
| [typosquat.mut](typosquat.mut) | flag look-alike domains (`paypa1.com`) with string-similarity scoring |
| [decode_payload.mut](decode_payload.mut) | peel encoding layers off an obfuscated payload (base64 / hex) |
| [jwt_inspect.mut](jwt_inspect.mut) | decode a JWT's header and claims |
| [top_talkers.mut](top_talkers.mut) | count connections per source IP and rank the top talkers |
| [cert_inspect.mut](cert_inspect.mut) | generate a CA cert and read its subject / validity / fingerprint |
| [ip_triage.mut](ip_triage.mut) | tell internal vs external IPs, test CIDR membership, expand a CIDR |
| [log_parse.mut](log_parse.mut) | turn unstructured log lines into structured fields with one regex |

## Running a file

Mutant compiles a `.mut` to a `.mu`, then executes the `.mu`:

```
# from the repository root:
mutant run examples/workshop/ioc_extract.mut -pwd mypass
mutant     examples/workshop/ioc_extract.mu   -pwd mypass
```

(Use any password you like; the same one for both commands. `-pwd` is deprecated
because it puts the credential in the process table — omit it and be prompted,
or use `--password-stdin`.)

**Run from PowerShell/cmd, not Git Bash or WSL.** Secure mode halts when the
host looks like an analysis sandbox, and Git Bash trips the WSL detector:
`sandbox detected, execution halted for security`. Use a native shell, or pass
`--compat` to downgrade that to a warning.

### Language gotchas worth knowing before you start

| Gotcha | What you see | Fix |
|---|---|---|
| Fallible builtins return `(value, err)` | nesting one passes the pair: `got MULTI_VALUE` | `let v, e = f(x);` |
| There is no `null` literal | `undefined variable: null` | a bare `return;` yields null; test with `is_null()` |
| No string literal inside `${...}` | parse error naming the line *inside* the string | bind a local, then `${local}` |
| Builtins are not first-class values | `map(xs, defang)` fails | `map(xs, fn(d) { return defang(d); })` |
| `while` / C-style `for` inside a `for…in` | `loop cursor was replaced on the stack` | use `for (i in range(a, b))` — `for…in` nests fine |
| `regex_find_all(p, s, 0)` | no matches — `0` is the result *limit* | omit the third argument |

## Input for step 5

`05_timestomp_detection.mut` is the only file that needs a real artifact — an NTFS
Master File Table. Open the file and set `MFT_PATH` to either:

- a **standalone `$MFT`** file — export one with KAPE, FTK Imager, or The Sleuth
  Kit's `icat` (`icat image.dd 0 > MFT`), or
- an **NTFS volume image** — a raw/`dd` image of a single NTFS partition.

`mft_parse` auto-detects which of the two you gave it. With no file present, the
program prints exactly what to provide and exits — it never fabricates a result.

## How timestomping detection works (step 5)

Windows stores **two** creation times per file:

- **`$STANDARD_INFORMATION` (SI)** — what Explorer shows; anti-forensic tools edit it.
- **`$FILE_NAME` (FN)** — set by the OS at file birth; tools rarely touch it.

So the single clearest tell is: **SI created is earlier than FN created** — which is
physically impossible, because a file can't be "created" before it was born. `mft_parse`
exposes both as `si_created` / `fn_created` (and the full MAC set), so the whole
detector is one `filter`.

**Want to go further?** `mft_parse` also exposes the sub-second fraction
(`si_created_ns` / `fn_created_ns`, at NTFS 100 ns resolution). A second tell: SI times
that all land on whole seconds (`_ns == 0`) while FN times don't — the fingerprint of
tools that set whole-second timestamps.
