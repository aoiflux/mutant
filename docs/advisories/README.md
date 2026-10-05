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

**Every identifier has a page of its own, and the serials run from 0001 with no
hole.** An identifier is assigned when its advisory is written, so one cannot be
allocated and then left with nothing behind it, and `go test ./cmd/gendocs/`
fails if a serial is missing from the sequence or if a listed advisory has no
page. A reader following a citation never has to work out, from the absence of a
page, whether one was owed.

What cannot be read off this page is how many issues are not yet fixed. An
advisory appears when its fix is ready to publish, not when the defect is found.

## Published

Severity is Mutant's own S1–S5 scale, not CVSS; `SECURITY.md` defines it.
"Fixed in" names every release that carries the fix: four of these are
backported to the 2.5.1 patch release as well as fixed on the 2.6.0 line.
"Affected" is the range checked by source at each tag — where a row says a
family was not released, the builtins it concerns did not exist in any
published version.

| Identifier                        | Sev | Affected                | Fixed in              | What it was                                                                   |
| --------------------------------- | --- | ----------------------- | --------------------- | ----------------------------------------------------------------------------- |
| [MVF-2026-0001](MVF-2026-0001.md) | S1  | 2.2.0 – 2.5.0           | 2.5.1 and 2.6.0       | Compiling a program ran whatever builtins its macros called                   |
| [MVF-2026-0002](MVF-2026-0002.md) | S2  | none released           | 2.6.0                 | The disclosure ledger's own records could be redacted, undoing a withdrawal   |
| [MVF-2026-0003](MVF-2026-0003.md) | S2  | none released           | 2.6.0                 | An audit log with its first entries deleted verified as intact                |
| [MVF-2026-0004](MVF-2026-0004.md) | S2  | none released           | 2.6.0                 | An audit entry with no sequence number ended the walk as though intact        |
| [MVF-2026-0005](MVF-2026-0005.md) | S2  | all through 2.5.0       | 2.5.1 and 2.6.0       | Two strings sharing one 64-bit digest were one hash entry                     |
| [MVF-2026-0006](MVF-2026-0006.md) | S2  | none released           | 2.6.0                 | A relabelled disclosure package verified against the genuine root             |
| [MVF-2026-0007](MVF-2026-0007.md) | S1  | 2.3.0 – 2.5.0           | 2.5.1 and 2.6.0       | A SQL query the documentation called read-only could modify evidence          |
| [MVF-2026-0008](MVF-2026-0008.md) | S2  | none released           | 2.6.0                 | A classified buffer put in a report table was rendered to hex and written out |
| [MVF-2026-0009](MVF-2026-0009.md) | S3  | 2.1.0 – 2.5.0           | 2.5.1 and 2.6.0       | An inherited environment variable chose the signing key and the trust anchor  |
| [MVF-2026-0010](MVF-2026-0010.md) | S3  | extension 0.1.0 - 0.2.0 | extension: unreleased | The editor extension's release task passed the password in the argument list  |
| [MVF-2026-0011](MVF-2026-0011.md) | S3  | none released           | 2.6.0                 | A ledger redacted by an older build could have lost a withdrawal silently     |
| [MVF-2026-0012](MVF-2026-0012.md) | S2  | 2.3.0 – 2.5.0           | 2.6.0                 | A header count sized an allocation before the bytes it promised were there    |
| [MVF-2026-0013](MVF-2026-0013.md) | S2  | 2.3.0 – 2.5.0           | 2.6.0                 | A binary plist sharing its containers expanded exponentially when parsed      |

Every row above links to a page, and each page names the fixture that holds its
fix. Six of the thirteen -- MVF-2026-0002, -0003, -0004, -0006, -0008 and -0011
-- concern code that no released version contained. They have a page anyway, and
it says so in its own first section, because "no release is affected" is an
answer an operator deserves to be given rather than left to infer; each one
proves it at the tag rather than asserting it, and names the development window
in which the defect was live.

MVF-2026-0010 is the one row whose versions are not the language's: the editor
extension versions its own releases, so its page carries both numbers, and it is
the one advisory here whose fix has not been released in any version of the
component it concerns.

## Severity vectors

Every identifier carries both a CVSS:3.1 and a CVSS:4.0 base vector, including
the ones with no page of their own. **These are this project's own assessment,
not a numbering authority's.** Mutant's S1-S5 scale, which `SECURITY.md`
defines, is what the project actually triages by; the vectors are here so a
reader who works in CVSS can compare these issues with others, and so they can
be argued with rather than guessed at.

| Identifier                        | Row          | CVSS:3.1                                       | CVSS:4.0                                                          |
| --------------------------------- | ------------ | ---------------------------------------------- | ----------------------------------------------------------------- |
| [MVF-2026-0001](MVF-2026-0001.md) | M26-EVL-012  | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` | `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N` |
| [MVF-2026-0002](MVF-2026-0002.md) | M26-CUS-001  | `CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N` | `CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N` |
| [MVF-2026-0003](MVF-2026-0003.md) | M26-CUS-005  | `CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N` | `CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N` |
| [MVF-2026-0004](MVF-2026-0004.md) | M26-CUS-006  | `CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N` | `CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N` |
| [MVF-2026-0005](MVF-2026-0005.md) | M26-EVL-003  | `CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:H/A:N` | `CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:P/VC:L/VI:H/VA:N/SC:N/SI:N/SA:N` |
| [MVF-2026-0006](MVF-2026-0006.md) | M26-REC-005  | `CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:N` | `CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:P/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N` |
| [MVF-2026-0007](MVF-2026-0007.md) | M26-DAT-001  | `CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:H/A:H` | `CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:A/VC:L/VI:H/VA:H/SC:N/SI:N/SA:N` |
| [MVF-2026-0008](MVF-2026-0008.md) | M26-DAT-002  | `CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N` | `CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:A/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N` |
| [MVF-2026-0009](MVF-2026-0009.md) | M26-DOC3-001 | `CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N` | `CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N` |
| [MVF-2026-0010](MVF-2026-0010.md) | M26-LSP-017  | `CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` | `CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N` |
| [MVF-2026-0011](MVF-2026-0011.md) | M26-CUS-021  | `CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:L/A:N` | `CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N` |
| [MVF-2026-0012](MVF-2026-0012.md) | M26-ART-005  | `CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H` | `CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:A/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N` |
| [MVF-2026-0013](MVF-2026-0013.md) | M26-ART-008  | `CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H` | `CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:A/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N` |

Three things to know before reading a row.

**4.0 is not a re-encoding of 3.1 and the two disagree on purpose in places.**
4.0 splits 3.1's Attack Complexity into AC, how hard the attack is, and AT, what
has to already be true. MVF-2026-0011 is the clear case: it needs a ledger that
an older build had already redacted, which is a precondition and not difficulty,
so its 3.1 is `AC:H` and its 4.0 is `AC:L/AT:P`. 4.0 also replaces
`UI:N`/`UI:R` with none, Passive and Active, which splits "the victim is using
the tool normally" from "the victim has to run this particular thing".

**MVF-2026-0001's 3.1 vector is the one published with its advisory and is
unchanged here, `UI:N` included.** Compiling is an action the victim takes, so
3.1 would normally score `UI:R`, and its 4.0 vector accordingly says `UI:A`.
A published vector is not quietly rewritten; the disagreement is recorded here
instead.

**Subsequent-system metrics are `N` throughout.** What several of these damage
-- the evidence, the audit log, the case record -- is the vulnerable system's
own data in 4.0's terms rather than a separate system downstream of it. Scoring
it as subsequent impact as well would count it twice.

## Not assigned an identifier

Four fixes in the 2.6.0 Security section deliberately have no MVF, because
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
- **A code-signature encoder and decoder that nothing called** (internal
  row M26-SEC-009). `CodeSignature.Encode` wrote the timestamp through
  `string(rune(...))`, which is a code point and not a number, so every real
  timestamp was destroyed before it was written; `DecodeSignature` read one
  byte of that and returned 239 for all of them, and indexed an empty slice
  when the field was absent. Both halves are real and both are fixed. Neither
  is reachable: the pair had no caller anywhere in the toolchain, so it fails
  the third test above -- reachable in a published release, or on a path a
  release would reach. The custody seal, which is the one thing that does
  carry a signature, writes its fields separately and was never affected.

- **A key-derivation branch that ignored the password** (internal row
  M26-SEC-009 as well -- the same row, a different defect in it).
  `ReconstructKey` switched on an algorithm name stored beside the data, and
  its `hkdf-sha256` arm derived the key from that stored salt as both the
  secret and the salt without reading the password at all, so data naming
  that algorithm would have opened under any passphrase, an empty one
  included. It is refused now. It was never reachable: the one caller writes
  `argon2id` into the parameters itself and never takes the algorithm from
  the data, and `DecodeParams`, which is what would have read an algorithm
  name out of a stored blob, has no callers and cannot parse what its own
  encoder writes. So it fails the third test above as well, and closing it
  was closing a trap for the next caller rather than a hole for this one.

## Relationship to CVE and GHSA

An MVF is Mutant's own name for an issue and never replaces an identifier
somebody else assigned. If a report also receives a CVE or a GitHub advisory
(GHSA), the advisory page records all of them and they refer to the same
issue. A vulnerability in a dependency keeps that project's identifier.

## Reporting

Use GitHub private vulnerability reporting, as described in
[SECURITY.md](../../SECURITY.md). Reporters are credited in the advisory
unless they ask not to be.
