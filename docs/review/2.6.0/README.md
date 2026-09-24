# Mutant 2.6.0 engineering review

This directory holds the release review for Mutant 2.6.0: one ledger of
findings and the reports written from it. Nothing in a report is a finding
unless the ledger holds it, and `go test ./cmd/gendocs/` fails when a report
cites an id the ledger does not.

## The ledger

[`findings.jsonl`](findings.jsonl) holds one finding per line, as a JSON
object, so a finding is one line in a diff.

| Field | Meaning |
| --- | --- |
| `id` | `M26-<AREA>-<NNN>`; the area is the part of the tree it was found in |
| `category` | correctness, reliability, security, docs, debt, perf, test, limit, arch, readability |
| `severity` | how bad it is if nothing is done (below) |
| `priority` | when it is fixed (below) |
| `status` | OPEN, FIXED, WONTFIX, DUPLICATE (with `duplicate_of`) |
| `verification` | CONFIRMED: a reproduction ran and failed as predicted. PLAUSIBLE: the reasoning holds but nothing has been run. REFUTED: checked and wrong; kept, left out of the reports. UNVERIFIED: not yet looked at |
| `audited_commit`, `location` | where it was found, at that commit |
| `claim`, `evidence`, `repro`, `impact`, `fix_proposal` | what is wrong, why we believe it, how to see it, what it costs, what to do |
| `regression_test` | required once FIXED: the test that failed before the fix |
| `fix_commit` | filled in by the owner when the fix lands |

### Severity

| | |
| --- | --- |
| **S1** | A silent break of an evidence or confidentiality promise: sealed data readable without a grant, a verify that passes a tampered artifact, evidence modified, code execution from parsing evidence |
| **S2** | A crash, hang or unbounded memory from hostile evidence, network input or an exchanged artifact; a wrong forensic result with no error; lost ledger or case data |
| **S3** | Wrong behaviour that shows an error or has a workaround; a document that would mislead an examiner's procedure; a missing cap on a trusted input |
| **S4** | Minor or cosmetic; a stale document with no procedural effect |
| **S5** | Technical debt |

### Priority

| | |
| --- | --- |
| **P0** | Blocks 2.6.0 |
| **P1** | Ships in 2.6.0 |
| **P2** | 2.6.x or 2.7 |
| **P3** | Backlog |

### Embargo

A security finding is written up in full only once it is fixed. Until then
its row carries its id, area, severity, priority, status and verification and
nothing else, and the detail is kept outside the repository, in
`plans/review-2.6.0/embargo/`, a gitignored directory. The ledger test fails if
an unfixed security row is not embargoed or an embargoed row carries detail.

## The reports

Written from the ledger, the measurements and the coverage manifests once the
audit and the fixes are done. Until then this list is the plan.

1. Architecture assessment
2. Correctness audit
3. Reliability audit
4. Security audit (full write-ups for fixed findings only)
5. Documentation audit
6. aoiflux integration report
7. Graphene architecture review
8. Byte-level redaction architecture review
9. Case management review
10. Technical debt report
11. Hardcoded values elimination report
12. Performance report
13. Test coverage report
14. 2.6.0 readiness report
15. Prioritized remediation roadmap
