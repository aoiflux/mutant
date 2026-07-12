# Remaining Work Checklist

This checklist focuses on what is still incomplete in the current repo state. It
is organized by subsystem and grounded in the current implementation guide and
summary docs.

## Dependency Check

- [x] No new external libraries are currently required for the implemented
      filesystem, image, DB, policy, or Lua features.
- [ ] Revisit dependencies only if the process-scan manager or future
      platform-specific probes need an OS-level package that is not already
      covered.

## Planned Builtin Functions (Next Wave)

### Binary Analysis Builtins

- [x] `bin_pe_parse` (library target: `github.com/saferwall/pe`)
- [x] `bin_elf_parse` (library target: `debug/elf`)
- [x] `bin_dwarf_parse` (library target: `debug/dwarf`)
- [x] `bin_strings` (library target: custom implementation)
- [x] `bin_entropy` (library target: custom implementation)
- [ ] `bin_yara_scan` (library target pending; `github.com/VirusTotal/yara-x/go`
      requires native `yara_x_capi` not available in current environment)
- [x] `bin_imports` (library targets: `github.com/saferwall/pe`, `debug/elf`)
- [x] `bin_sections` (library targets: `github.com/saferwall/pe`, `debug/elf`)

### Partition Table Builtins

- [x] `table_open` (library target: `github.com/aoiflux/libtable`)
- [x] `table_list_partitions` (library target: `github.com/aoiflux/libtable`)
- [x] `table_partition_info` (library target: `github.com/aoiflux/libtable`)
- [x] `table_close` (library target: `github.com/aoiflux/libtable`)

### Dependency Follow-up for Planned Builtins

- [x] Add and pin `github.com/saferwall/pe`.
- [ ] Add and pin a usable YARA engine dependency (blocked:
      `github.com/sansec/yargo` unavailable; `github.com/VirusTotal/yara-x/go`
      requires native `yara_x_capi` on this machine).
- [x] Add and pin `github.com/aoiflux/libtable`.
- [x] Validate compatibility of `debug/elf` and `debug/dwarf` usage paths with
      current Go version.

## Security / Runner

- [x] Add the optional remote process scan manager in observe mode first.
- [x] Define a normalized signal schema for cross-process evidence.
- [x] Add a weighted correlator and risk-band classification for
      process-protection results.
- [x] Add coverage for probe-gate combinations so the probe/profile/env matrix
      is explicit.
- [x] Add runbook examples for common policy and environment combinations.
- [x] Keep security docs aligned to the LLD source-of-truth docs.

## Compiler / Polymorphic Bytecode

- [x] Enable safe polymorphic transform stages incrementally.
- [x] Add strict semantic-equivalence tests for polymorphic output.
- [x] Add reproducibility tests by seed.
- [x] Preserve a fast rollback path if a transform changes runtime
      compatibility.

## VM / Memory Hardening

- [x] Define the wrapper-usage strategy and policy gate for memory hardening.
- [x] Benchmark the wrapper path against the current VM object path.
- [x] Keep the default path performance-safe.
- [x] Decide whether any additional secure-memory helpers are actually needed
      beyond the current runtime encryption path.

## Runtime Diagnostics

- [x] Add source-anchored runtime error metadata so VM failures can be tied back
      to a precise instruction or source location.
- [x] Keep builtin error context consistent and specific across subsystems.
- [ ] Continue improving top-level error handling so early exits do not degrade
      into secondary VM failures.

## Examples / UX

- [ ] Keep example console output line-oriented and easy to scan.
- [ ] Standardize example error printing so builtin errors render cleanly
      without string concatenation mishaps.
- [ ] Make example scripts exit cleanly on expected data misses instead of
      falling into noisy runtime paths.

## Documentation

- [ ] Remove or rewrite any docs that imply unsupported CLI flags or
      capabilities.
- [ ] Mark partial features as partial, not complete.
- [ ] Keep runner and builtin probe scope differences documented.
- [ ] Maintain the student reading order and summary docs so they match the
      actual codebase state.

## Suggested Order

1. Security / Runner
2. Compiler / Polymorphic Bytecode
3. VM / Memory Hardening
4. Runtime Diagnostics
5. Examples / UX
6. Documentation
