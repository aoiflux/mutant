# Disclosure Policy

**A disclosure grants a key, not a copy.** The encrypted record a recipient
receives is byte-identical to the one under custody, and what distinguishes one
recipient from another is the set of segment keys they were given. Nothing is
re-encrypted per recipient, because a per-recipient ciphertext has a different
digest from the original and leaves no document able to tie any copy back to the
evidence it came from.

This document states what a disclosure is, what a recipient can and cannot
verify with one, and the things this design refuses to promise. Every refusal
here is load-bearing: each one names a claim a reader would otherwise reasonably
infer from the words on a report.

It is a companion to
[`docs/EVIDENCE_HANDLING_POLICY.md`](EVIDENCE_HANDLING_POLICY.md), which governs
the original. This one governs what leaves.

---

## 0. What exists, and what this document is ahead of

This policy is written before all of the code it describes. That is deliberate —
the refusals below shaped the design — but it makes the document itself subject
to the rule it exists to enforce, so the split is stated first and plainly.

| | Status |
| --- | --- |
| The key schedule: case key, record key, per-segment keys and nonces, the segment AAD, and the seal-once rule of [Section 4](#a-forged-segment-is-also-a-decryption-oracle-for-the-real-one) | **In force.** [`security/record_crypto.go`](../security/record_crypto.go) |
| `case_key_create`, `case_key_open`, `case_key_rotate`, `case_key_fingerprint` | **In force.** [`builtin/case_key.go`](../builtin/case_key.go) |
| `class_define`, `class_list`, and the manifest's classification block | **In force.** [`builtin/class.go`](../builtin/class.go), [`builtin/custody.go`](../builtin/custody.go) |
| The `.mrec` container, its header, its footer signature, and the `record_*` family | **In force.** [`security/record_file.go`](../security/record_file.go), [`builtin/record.go`](../builtin/record.go) |
| `view_*`, `disclose_*`, and the disclosure package | Designed, not yet built |
| The graphene disclosure ledger | Designed, not yet built |
| `object.Bytes.Classified` and the sink checks | Designed, not yet built |
| The machine guard, [Section 10](#10-the-guard) | Designed, not yet built |

A section below that describes unbuilt code says so in its first sentence. No
claim in this document is carried into a manifest, a return field or a report
until the code behind it exists.

## 1. What a recipient can verify

Three things, and the third is the one worth having.

1. **The record is intact and signed**, checkable with **no key at all**. The
   signature covers the header as stored, so a recipient who was granted nothing
   can still establish that the file they hold is the file that was sealed. This
   is the property `case_manifest_verify` already has, for the same reason.
2. **Each key they were granted opens its segment**, with the Poly1305 tag
   holding. A key that does not open what it was said to open is a failure the
   recipient sees, not one they have to be told about.
3. **Complete as authorised.** The signed `withheld` list names, run for run, the
   segments the recipient cannot decrypt. Matching that list against what
   actually fails to open is the check that the disclosure is complete *to the
   extent it was authorised* — that nothing was quietly dropped on the way.

## 2. What a recipient cannot verify, and must be told

Two things, and both lie outside what any cryptography can reach:

- **That the classification was correct.** Whether a span should have been
  withheld at all is a legal judgement made by a person. The record proves a
  label was applied; it cannot prove the label was right.
- **That the record is all the evidence there is.** A disclosure is complete with
  respect to *one record*. Nothing in it speaks to what was never sealed.

The manifest states both in a `does_not_cover` field. The field is not optional
and is not a footnote: a document that verifies is read as a document that
vouches, and these two sentences are the difference.

## 3. Revocation is not offered

Once a recipient holds the ciphertext and the segment keys, **both halves are
theirs.** No key deletion, ledger entry or re-encryption reaches their copy.

So no builtin is named `*_revoke`, and no return field or report heading carries
the word. The verb is `disclose_withdraw`, and it returns
`bytes_recoverable: false` as a first-class field rather than as a caveat.

What withdrawal does achieve is worth stating in full, because it is not nothing:

- **Future grants stop.** The withdrawal is checked before any new key is issued.
- **The withdrawal is attributed.** Who withdrew what, when, and on whose
  authority, in an append-only ledger.
- **Crypto-erasure is available.** Destroying the record key means you can no
  longer open the record. That is a claim about your own storage and nothing
  more; it is not cryptographic evidence that anyone else's copy is gone.

The honest substitute for revocation is a question the schema is built to answer:
**which recipients hold segments whose classification has since been raised?**
That is why re-classification is append-only — a new record plus a `SUPERSEDES`
edge, never an in-place update. Graphene keeps no history, and the next
compaction would erase the prior value along with the ability to ask.

## 4. A key grants writing as well as reading

A segment key is symmetric. A recipient holding one can seal a segment of their
own choosing under it, and the examiner's `OpenSegment` will accept it: the tag
holds, the AAD binds, everything verifies. A disclosure is therefore a grant to
**write** the disclosed span as much as to read it.

**The record footer narrows this. It does not remove it.** `record_seal` folds
every segment's digest into a root, and the Ed25519 signature covers that root
together with the header exactly as stored. A segment re-sealed by anybody makes
the record stop folding to the root its own footer names, so `record_verify`
reports `signature_valid: false` and `record_prove_segment` reports
`root_matches: false`. A per-segment tag could never have caught that — each
surviving segment is individually valid, which is the point of per-segment
authentication and also its blind spot — and a root over all of them catches it,
along with a dropped trailing segment and two transposed ones.

What the footer does not reach is the identity problem, which is
[Section 9](#9-the-signature-authenticates-the-document-not-the-names-in-it) and
is not cryptographic. A forger can re-fold the root and re-sign under a keypair
of their own, and the result verifies — as a record signed by *that* keypair,
which is all a signature ever says. So the check is worth exactly what the
comparison behind it is worth. A recipient who does not compare `public_key`
against a key they already had reason to trust has established that a record is
internally consistent, which is not the same as establishing who made it.

### A forged segment is also a decryption oracle for the real one

The same fact reaches further than authenticity, and this is the part that is
easy to miss.

A segment's key and nonce are derived from its descriptor, and a descriptor
names the **position** and not the content. The keystream at a position is
therefore fixed, and two ciphertexts at one position recover each other: XOR
them and what falls out is the XOR of the two plaintexts, with no key anywhere
in the operation. So a recipient granted segment 3 can re-seal it with content
they choose and publish the result — and **anyone holding the record, including
a recipient who was never granted segment 3, can then XOR the two and read what
segment 3 originally said.**

The consequence is that the record footer is not only an authenticity
mechanism. A reader who cannot tell the examiner's ciphertext from a grant
holder's cannot treat any second version of a segment as merely a forgery,
because its existence is what breaks the confidentiality of the first.

Mutant refuses to do this to itself: a record is sealed once, in order, and
every segment exactly once, so no tool in this tree can produce the second
ciphertext by accident — see `SealSegment` in
[`security/record_crypto.go`](../security/record_crypto.go). That is a guard on
our own code and it is **not** a defence. A grant holder has the key and needs
none of our code.

What the footer adds here is detection rather than prevention: a second version
of a segment does not fold to the signed root, so a recipient who checks the
record before trusting a fragment of it learns that a fragment is not the
examiner's. That check is the one thing standing between a published forgery and
the confidentiality of the original, which is why `record_verify` is worth
running on a record before any part of it is read into a report.

This is all stated here rather than left to be discovered, because the party who
would otherwise discover it is an opposing expert, and the difference between a
disclosed limit and a found one is the difference between a careful tool and a
broken claim.

## 5. What a disclosure leaks by construction

**Range boundaries and lengths are public.** A recipient can see exactly where
each withheld span begins and ends, and how long it is, without holding any key
for it.

That is a feature, not an oversight. **A redaction nobody can see is a redaction
nobody can challenge**, and the ability to challenge one is the point of
disclosing a redacted document rather than a summary.

Padding is rejected for the same reason it is usually proposed. Hiding a length
means hiding the offsets, and a recipient who cannot place their fragments at
their true positions cannot reconstruct the document they were given. The cost is
real: a four-byte withheld span advertises that it holds four bytes, and there
are four-byte secrets.

`record_seal_quantised` is the answer where that matters. It rounds span
boundaries **outward** to a quantum, so a short secret is indistinguishable from
anything else inside its rounded span.

**Rounding is a reclassification, and it has a direction.** Every byte a range
grows over stops carrying the class it had and starts carrying that range's.
Whether that withholds those bytes or releases them depends on which of the two
classes is the more sensitive — and nothing in this tree knows, because a class
is a label and a tag and [Section 6](#6-a-record-without-its-case-is-evidentially-mute)
is the whole of what one means. Nothing orders them.

An earlier version of this document said a quantised record "withholds **more**
than the classification called for". That is true in one direction and false in
the other, and the false direction is the ordinary shape of a disclosure review:
default `restricted`, with short passages cleared for release. There, rounding a
four-byte `open` passage to a sixteen-byte quantum releases twelve bytes nobody
read — silently, and reported in a field documented as bytes withheld.

So the examiner names the one class rounding may grow, in a required `rounds_to`
option, and a range carrying any other class is sealed at the boundary it was
given. `quantised_extra` is how many bytes changed class and `rounds_to` is which
class they changed into; both are in the record header, so `record_verify` reports
them to a recipient holding no key. A count without a direction cannot be read,
and a tool that picked the direction itself would be answering the question the
rest of this document exists to refuse.

## 6. A record without its case is evidentially mute

A classification is a name and a tag. The name is what an examiner writes in a
report; the tag is what a segment carries, and it is an HMAC keyed to the case
key — so two investigations that both declare `restricted` produce different
tags, and an observer holding records from both cannot link them.

**The cost of that unlinkability is the subject of this section.** The tag is
derived from the key; the *meaning* of the tag lives in the case manifest, which
is signed, and not in the record. So a `.mrec` separated from its case manifest
holds tags whose meaning is not recoverable from anything its holder has. The
binding is cryptographic; the naming is documentary.

This is deliberate. The manifest is the case document and it is signed, and a
classification scheme written into the key file would either travel with the key
or not travel at all — and the key is precisely the thing an examiner keeps away
from the handover.

But it means the record alone is **evidentially mute even when it is
cryptographically openable**, and the operational consequence follows directly: a
disclosure package carries the class rows it needs, and a record handed over
without them is a file that opens and says nothing.

## 7. Three operations that must not be conflated

Conflating these is the fastest route to a claim nobody can back.

| Operation | What it destroys | What proves it |
| --- | --- | --- |
| **Withholding** a byte range | *Nothing.* It is the absence of a key grant. | The signed `withheld` list, plus the recipient's inability to decrypt |
| **Redacting graphene properties** (`RedactNodeProperties`) | Graphene's *metadata about* a range — not the range | `ProvePropertyRedaction`, which is content-free: it proves identity is unchanged and only properties were removed |
| **Crypto-erasure** | The record key, in your own storage | *Nothing cryptographic.* It is an assertion about a system you control |

Note the middle row's window: `RemovalProvable` is false between a redaction and
the next compaction. During that window the report says `provable: false` rather
than writing a claim the recipient cannot yet check.

## 8. Key material never travels as an argument

Four rules, all in force today.

- **A path is passed, never key material.** Every `case_key_*` builtin takes a
  filesystem path. No builtin accepts a key, and none returns one.
- **A passphrase is read from the terminal.** Never from an argument, never from
  a file named in program text, and **never from an environment variable** — see
  [`docs/CONFIGURATION_POLICY.md`](CONFIGURATION_POLICY.md), which makes that a
  machine-checked rule for the whole tree. An options key named `passphrase`,
  `password`, `secret` or `key` is refused **by name**, before the options parser
  can report it as merely unknown, because "unknown option" reads as a
  misspelling and the point is that the option is forbidden.
- **Plaintext is `ParamBytes`, never `ParamString`.** A Go string cannot be
  zeroed, and the runtime copies and retains one at will. See
  [`object/bytesObj.go`](../object/bytesObj.go).
- **A test binary cannot produce a key.** The passphrase source is a seam that
  `main` fills at its entry point and nothing else does, so under `go test` no
  source is installed and a request fails *before* `crypto/rand` is read and
  before any file is created. That is what makes key generation during a
  conformance probe structurally impossible rather than merely unlikely.

## 9. The signature authenticates the document, not the names in it

Identity in Mutant is **examiner-asserted and recorded**, exactly as the
free-text `examiner` string already is. There is no authentication and no
credential issuance, and there is not going to be.

A *signed* manifest invites a reader to treat the names inside it as verified.
They are not. Every rendering of a disclosure or a manifest carries the sentence
in some form: **the signature authenticates the document, not the names in it.**

One related field deserves the prominence it already has in `custody_seal.go`:
`key_created_for_this_run`. A signing key generated seconds before it signed is
not the same thing as a key an organisation has held and protected, and a
document that does not distinguish them invites a reading it cannot support.

## 10. The guard

**Not yet built.** [Section 0](#0-what-exists-and-what-this-document-is-ahead-of)
says so; this section says what it will be, so the shape is agreed before the
code lands.

`policy/disclosure_policy.go` plus `policy/disclosure_guard_test.go`, in the
style of the guards already in `policy/`, running under an ordinary
`go test ./...`. It asserts that no file in the record or disclosure family:

- calls `.Inspect()` on anything derived from a decrypt — `Inspect()` renders a
  `*object.Bytes` as the whole buffer in hex, so one call prints the plaintext;
- passes a decrypt result to `fmt` with a non-constant format string.

That turns "plaintext never reaches a log, a manifest or an error message" from a
practice into something the build enforces.

What is already enforced: the no-environment-variable rule of
[Section 8](#8-key-material-never-travels-as-an-argument), by the configuration
guard in `policy/`.

### What the `Classified` flag will and will not do

When it lands, `object.Bytes` gains a `Classified` flag set by `record_read`,
propagated through `bytes_slice`, and checked **at the sink call sites** —
`putln`, `fs_write`, the network builtins, the report builtins — and **never
inside `Inspect()`**. Making `Inspect()` classification-aware would be a worse
bug than the one it fixes: `Inspect()` is the de-facto identity function for
equality in both engines, for `unique`'s dedup key, for `contains` and
`index_of`, and for hash-key ordering, so a preview there would make two distinct
buffers compare equal, silently, in six subsystems at once.

Its limits belong next to its existence, in the same paragraph, wherever it is
documented: the flag dies at any conversion that does not propagate it, and is
defeated by a loop that rebuilds the buffer a byte at a time. **It catches
accidents, not adversaries.**

## 11. What this is not

This policy governs what **leaves** a case. It says nothing about who may open
the case in the first place — the examiner's machine is trusted, which is the
threat model this whole family is built on, and the examiner's own
responsibility. The guarantee here binds the **recipient of a disclosure**, the
only party it ever could bind.

It is also not an access-control system. Nothing here authenticates a recipient,
issues them a credential, or checks one. A grant is a set of bytes handed to a
named party, and the name is asserted by the examiner who handed them over.

## 12. See also

- [`docs/EVIDENCE_HANDLING_POLICY.md`](EVIDENCE_HANDLING_POLICY.md) — the rule
  governing the original, and the sentence this family inherits: a manifest that
  asserts something nobody verifies is worse than a manifest that says nothing,
  because it looks like verification.
- [`docs/CONFIGURATION_POLICY.md`](CONFIGURATION_POLICY.md) — why no
  configuration comes from the environment, and the guard that enforces it.
- [`docs/CAPABILITY_REFERENCE.md`](CAPABILITY_REFERENCE.md) — the chain-of-custody
  and case-key builtins.
