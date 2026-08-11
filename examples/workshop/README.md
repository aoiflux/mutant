# Forensic Tooling Workshop (in Mutant)

A five-step, build-it-from-first-principles walkthrough of writing forensic
analysis tools. Each step is a small, standalone `.mut` program. Read them in
order — they build toward the timestomping detector in step 5.

The methodology is language-agnostic; Mutant is just the vehicle. The four core
ideas — **artifact modeling**, **timestamp normalization**, **timeline
construction**, and **custom analysis logic** — are the same in any language.

## The steps

| # | File | Teaches | Input needed |
|---|------|---------|--------------|
| 1 | [01_artifact_modeling.mut](01_artifact_modeling.mut) | Model entities + relationships as a graph | none (sample data) |
| 2 | [02_timestamp_normalization.mut](02_timestamp_normalization.mut) | Turn any epoch (FILETIME/WebKit/unix/ISO) into a common form | none (sample data) |
| 3 | [03_timeline_construction.mut](03_timeline_construction.mut) | Merge multi-source events into one ordered supertimeline | none (sample data) |
| 4 | [04_custom_analysis_logic.mut](04_custom_analysis_logic.mut) | Score/flag artifacts with your own rules (closures + map/filter) | none (sample data) |
| 5 | [05_timestomp_detection.mut](05_timestomp_detection.mut) | Detect NTFS timestomping via SI-vs-FN timestamps | **an NTFS `$MFT`** (see below) |

Steps 1–4 run with **no input** — they use small built-in sample datasets so you
can focus on the technique. Step 5 needs a real artifact.

## Input for step 5

`05_timestomp_detection.mut` needs an NTFS Master File Table. Open the file and
set `MFT_PATH` (top of the file) to either:

- a **standalone `$MFT`** file — export one with KAPE, FTK Imager, or The Sleuth
  Kit's `icat` (`icat image.dd 0 > MFT`), or
- an **NTFS volume image** — a raw/`dd` image of a single NTFS partition.

`mft_parse` auto-detects which of the two you gave it. If the path is missing or
unreadable, the program prints exactly what to provide and exits cleanly — it
never fabricates a result. (For a *full, partitioned* disk image, first locate the
NTFS partition with `table_open`, then point `MFT_PATH` at that partition.)

## Running a step

Mutant compiles a `.mut` to a `.mu`, then executes the `.mu`:

```
# from the repository root:
mutant run examples/workshop/01_artifact_modeling.mut -pwd mypass
mutant     examples/workshop/01_artifact_modeling.mu   -pwd mypass
```

(Use any password you like; the same one for both commands.)

## How timestomping detection works (step 5)

Each NTFS file record carries two timestamp sets:

- **`$STANDARD_INFORMATION` (SI)** — what Explorer and most tools display. This is
  what anti-forensic tools rewrite.
- **`$FILE_NAME` (FN)** — written by the OS when the file is created, and rarely
  altered by stomping tools.

`mft_parse` exposes both as `si_*` and `fn_*` fields (created/modified/accessed/
mft_modified), each with unix seconds, a sub-second fraction (`si_*_ns` / `fn_*_ns`,
at NTFS 100 ns resolution), and an RFC3339Nano `_iso` string. The detector flags an
entry when:

- **SI creation is earlier than FN creation** — not physically plausible, since FN
  is set at file birth (the strongest single indicator),
- **SI "created" is later than SI "modified"** — an ordering anomaly, or
- **SI times land on whole seconds (`_ns == 0`) while FN times don't** — the
  sub-second zeroing left behind by tools that set whole-second timestamps.

The program prints which of the three tells fired for each suspect.
