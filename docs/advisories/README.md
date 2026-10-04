# Mutant advisories

Mutant is not a CVE Numbering Authority and cannot assign a CVE. A
vulnerability that this project confirms is published here under an
identifier in its own namespace:

**MVF-2026-0001** — _Mutant Vulnerabilities & Fixtures_, the year it was
assigned, and a four-digit serial.

The rules for assigning one are in [SECURITY.md](../../SECURITY.md). The two
that matter when reading this page:

- **An identifier is assigned when an advisory is written, not when the bug is
  found.** It records a disclosure, so it never changes, and it is never
  reused. The serials are not in severity order and not in discovery order.
- **Every published advisory names a fixture**: the test in this repository
  that fails on the unfixed code and passes on the fixed code. An advisory
  with no fixture is not published, because nothing would hold the fix in
  place. `go test ./cmd/gendocs/` checks that each one names a test that
  exists.

Gaps in the serials carry no information. An identifier is allocated one at a
time, when its fix is ready to publish, so the number of issues not yet fixed
cannot be read off this page.

## Published

Severity is Mutant's own S1–S5 scale, not CVSS; `SECURITY.md` defines it.
"Fixed in" names every release that carries the fix: four of these are
backported to the 2.5.1 patch release as well as fixed on the 2.6.0 line.
"Affected" is the range checked by source at each tag — where a row says a
family was not released, the builtins it concerns did not exist in any
published version.

| Identifier                        | Sev | Affected          | Fixed in        | What it was                                                                   |
| --------------------------------- | --- | ----------------- | --------------- | ----------------------------------------------------------------------------- |
| [MVF-2026-0001](MVF-2026-0001.md) | S1  | 2.2.0 – 2.5.0     | 2.5.1 and 2.6.0 | Compiling a program ran whatever builtins its macros called                   |
| MVF-2026-0002                     | S2  | none released     | 2.6.0           | The disclosure ledger's own records could be redacted, undoing a withdrawal   |
| MVF-2026-0003                     | S2  | none released     | 2.6.0           | An audit log with its first entries deleted verified as intact                |
| MVF-2026-0004                     | S2  | none released     | 2.6.0           | An audit entry with no sequence number ended the walk as though intact        |
| MVF-2026-0005                     | S2  | all through 2.5.0 | 2.5.1 and 2.6.0 | Two strings sharing one 64-bit digest were one hash entry                     |
| MVF-2026-0006                     | S2  | none released     | 2.6.0           | A relabelled disclosure package verified against the genuine root             |
| MVF-2026-0007                     | S1  | 2.3.0 – 2.5.0     | 2.5.1 and 2.6.0 | A SQL query the documentation called read-only could modify evidence          |
| MVF-2026-0008                     | S2  | none released     | 2.6.0           | A classified buffer put in a report table was rendered to hex and written out |
| MVF-2026-0009                     | S3  | 2.1.0 – 2.5.0     | 2.5.1 and 2.6.0 | An inherited environment variable chose the signing key and the trust anchor  |
| MVF-2026-0010                     | S3  | extension only    | 2.6.0           | The editor extension's release task passed the password in the argument list  |
| MVF-2026-0011                     | S3  | none released     | 2.6.0           | A ledger redacted by an older build could have lost a withdrawal silently     |

Until an advisory has its own page, its account is the entry in the Security
section of [CHANGELOG.md](../../CHANGELOG.md), which names the identifier and
the internal row. MVF-2026-0005, MVF-2026-0007 and MVF-2026-0009 reached a
published release and are owed a page of their own before 2.6.0 ships; the
rest concern code that no released version contained, so there is no version
to tell an operator to upgrade from.

## Not assigned an identifier

Two fixes in the 2.6.0 Security section deliberately have no MVF, because
giving one to everything in that section would make the namespace mean
"changed something in security" rather than "was a vulnerability".

- **The toolchain's own standard-library vulnerabilities** (internal row
  M26-RUN-003). These are upstream defects that already have upstream
  identifiers, and this project does not rename other people's
  vulnerabilities. The fix was to move the pinned toolchain; `govulncheck`
  names each one.
- **A refusal that came later than the policy promised** (internal row
  M26-REC-001). A disclosure the ledger would refuse derived key material and
  prompted for a passphrase before the refusal was checked. The refusal still
  came and nothing was ever issued, so no security property was broken — the
  documented order was. That is a conformance fix, and it is recorded as one.

## Relationship to CVE and GHSA

An MVF is Mutant's own name for an issue and never replaces an identifier
somebody else assigned. If a report also receives a CVE or a GitHub advisory
(GHSA), the advisory page records all of them and they refer to the same
issue. A vulnerability in a dependency keeps that project's identifier.

## Reporting

Use GitHub private vulnerability reporting, as described in
[SECURITY.md](../../SECURITY.md). Reporters are credited in the advisory
unless they ask not to be.
