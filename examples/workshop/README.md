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

(Use any password you like; the same one for both commands.)

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
