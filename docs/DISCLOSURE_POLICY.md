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
| `view_define`, `view_list`, `view_preview`, and the manifest's view block | **In force.** [`builtin/view.go`](../builtin/view.go), [`builtin/custody.go`](../builtin/custody.go) |
| The disclosure grant: per-segment material, sealed under a passphrase | **In force.** [`security/record_grant.go`](../security/record_grant.go) |
| `disclose_to_passphrase`, `disclose_bundle`, `disclose_verify`, and `record_open` under a grant | **In force.** [`builtin/disclose.go`](../builtin/disclose.go), [`builtin/record.go`](../builtin/record.go) |
| `disclose_withdraw`, `disclose_history`, `disclose_for_segment`, `disclose_reclassified` | **In force.** [`builtin/disclose_history.go`](../builtin/disclose_history.go), [`builtin/disclose_reclassify.go`](../builtin/disclose_reclassify.go) |
| The graphene disclosure ledger, [Section 13](#13-the-disclosure-ledger) | **In force.** [`builtin/disclose_ledger.go`](../builtin/disclose_ledger.go) |
| `disclose_to`: a grant sealed to a recipient's public key rather than a passphrase | Designed, not built -- see [Section 12](#12-what-a-grant-is-and-how-it-travels) |
| `object.Bytes.Classified`, the sink checks, and `record_release` | **In force.** [`builtin/classified.go`](../builtin/classified.go), [`object/bytesObj.go`](../object/bytesObj.go) |
| The machine guard, [Section 10](#10-the-guard) | **In force.** [`policy/disclosure_policy.go`](../policy/disclosure_policy.go), [`policy/disclosure_guard_test.go`](../policy/disclosure_guard_test.go) |

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
**which recipients hold bytes whose classification has since changed, and would
the posture they were disclosed under still give them those bytes today?**
`disclose_reclassified` answers it. Re-classification is append-only — a new
record over the same evidence plus a `SUPERSEDES` edge, never an in-place update
— because graphene keeps no history, and the next compaction would erase the
prior value along with the ability to ask. A superseded record cannot be
disclosed again.

An earlier draft of this section asked which classifications had been
**raised**. That cannot be computed: nothing in the record format or the class
table orders one class above another (see
[Section 5](#5-what-a-disclosure-leaks-by-construction)), and a tool that printed
"raised" would be supplying a judgement that is the examiner's. What is computed
is exact — which byte ranges moved from which class to which, who holds them,
and whether each recipient's view grants the new class — and the report says
nothing about direction, in a `does_not_say` field.

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

### A view is a positive set, and a preview is arithmetic

A **view** is a name and a set of classifications: `view_define(label, classes)`
declares one, and a grant issued under that name opens those classes and nothing
else. It exists so that a disclosure review asks what a *name* grants, once,
instead of reading the fourth argument of the sixth call in a script — and so
that the posture is a labelled row in the signed manifest rather than a list
assembled at the call site.

**A view cannot negate.** There is no "everything except `restricted`". A negated
posture widens by itself every time a class is declared after it: the script does
not change, the manifest row does not change, and the set of bytes it releases
grows. That is the one way a disclosure can change with nobody editing it, and
the document meant to record the change would record nothing. The omission is the
feature.

A view granting *no* class is legal and reports `grants_nothing`. It discloses
the record, its signature and its shape, and no content — which is a real
posture, not a mistake.

**`view_preview(record, view)` says what a view would release and what it would
hold back, before anything is handed over.** It is arithmetic over the record
header, which is public by construction, and the case's class table: it opens no
segment, needs no plaintext, and returns `reads_no_plaintext` as a field saying
so. Both sides are reported as byte ranges, because "what am I holding back" is
the question a disclosure review actually asks and a tool that answered only the
other half would be answering the easier one.

Three things the preview is careful about, each of them a claim it refuses to
make:

- **The rounding direction is a property of the view, not of the record.** The
  passage above establishes that `quantised_extra` cannot be read without
  `rounds_to`. The same pair cannot be read without knowing whether *this*
  recipient is granted that class. So the preview states it in the terms of the
  view in front of it: the same twelve rounded bytes are reported as *released*
  to a view that grants the rounded class and as *held back* to one that does
  not. One record, one rounding, two correct and opposite readings.
- **A class it cannot name is counted, not guessed.** The class table lives on
  the case session, so a record opened in a later session whose labels were never
  re-declared carries tags with no names. Those rows report the tag, `declared:
  false`, and an empty label, and are counted in `unnamed_classes` — rather than
  passed off as unclassified, which is the one reading that would be actively
  wrong. This is [Section 6](#6-a-record-without-its-case-is-evidentially-mute)
  arriving in a return value.
- **It does not say the classification was correct.** A `does_not_say` field
  carries that, along with the fact that a disclosure hands over the *whole*
  record file: the recipient holds every ciphertext and learns every boundary and
  length whether or not they can open it. A reviewer reading only
  `granted_bytes` would otherwise have every reason to think the rest was not
  handed over at all.

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

Two halves, one static and one at run time, and neither is a taint analysis.

**The static half.** [`policy/disclosure_policy.go`](../policy/disclosure_policy.go)
lists the files that handle classified plaintext or the key material that opens
it, and [`policy/disclosure_guard_test.go`](../policy/disclosure_guard_test.go),
running under an ordinary `go test ./...` beside the other guards in `policy/`,
asserts that none of them:

- calls `.Inspect()` — on a `*object.Bytes` it renders the whole buffer in hex,
  so one call on the wrong value prints the plaintext;
- formats with a string that is not a constant — `fmt.Sprintf`, `fmt.Errorf`,
  `fmt.Printf`, `fmt.Fprintf`, `fmt.Appendf` or the builtin package's
  `newError`, handed anything but a string literal, a concatenation of literals
  or a declared constant. `fmt.Sprintf(plaintext)` is a disclosure by
  construction, and a reviewer cannot tell a safe variable format from an unsafe
  one without tracing where it came from.

The one other form it accepts is a local wrapper declared
`name := func(format string, args ...any)`, and only because every call of that
wrapper is itself checked for a constant format. The guard exercises each rule
against source that breaks it, so a walk that matched nothing cannot pass as
clean code. Its limit: the list of files is a declaration, and a new file in the
family that is left off it is not caught by anything.

That turns "plaintext never reaches a log, a manifest or an error message" from a
practice into something the build enforces — in those files, and for the two
ways a byte of plaintext becomes text without anybody meaning it to.

Also enforced: the no-environment-variable rule of
[Section 8](#8-key-material-never-travels-as-an-argument), by the configuration
guard in `policy/`.

### What the `Classified` flag does and does not do

**The run-time half.** `object.Bytes` carries a `Classified` mark — the record
uid, and the tag and label of each class the read crossed — set by `record_read`
and `record_read_partial`, kept when the buffer is held in a variable, and
carried by `bytes_slice` and by `+` of two buffers, which marks the joined
buffer with every record and class either side came from. It is checked **at the
sink call sites**, in [`builtin/classified.go`](../builtin/classified.go):
`putln`, `putf`, `fs_write`, `fs_append`, `http_post`, `http_request`,
`report_write`, `report_render`, `case_note`, `cache_put`, `ledger_add_node`,
`ledger_add_edge` and `db_add_artifact` refuse an argument that holds a marked
buffer, directly or anywhere inside an array, hash, struct, enum payload or
captured variable, and a value nested too deep to check is refused rather than
passed. The refusal names the record, the classes and the length, and not one
byte. A builtin whose parameter is STRING alone — `net_conn_write`,
`ws_write_frame` and `exec_string` among them — cannot be handed a buffer at all.

The mark is **never consulted inside `Inspect()`**. Making `Inspect()`
classification-aware would be a worse bug than the one it fixes: `Inspect()` is
the de-facto identity function for equality in both engines, for `unique`'s
dedup key, for `contains` and `index_of`, and for hash-key ordering, so a preview
there would make two distinct buffers compare equal, silently, in six subsystems
at once. A marked buffer and an unmarked one holding the same bytes are the same
value to all of them, and a test holds it there.

`record_release(buffer, reason)` is the deliberate way out. It requires a reason
and an open case, writes into the case timeline which record and which classes
were released, how many bytes and why, and returns an unmarked copy that shares
no storage with the original. An accident is caught; a decision is recorded.

Its limits belong next to its existence, in the same paragraph, wherever it is
documented: the mark travels through `bytes_slice` and `+` of two buffers and
nothing else, so a conversion to a string, to hex, to base64 or to JSON
produces a value without it, and so does a loop that rebuilds the buffer a byte
at a time. **It catches
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

## 12. What a grant is, and how it travels

A segment's key and nonce are derived together from the record's pseudorandom
key and a digest of that segment's whole descriptor. So the only way to open one
segment without being able to open all of them is to hold that segment's
**derived** material and nothing it was derived from: 32 bytes of key and 24 of
nonce, **56 bytes a segment** -- not 32, because the nonce cannot be rebuilt
without the pseudorandom key. HKDF is one-way in that key, so the material for
one segment says nothing about any other's. That is a grant.

`disclose_to_passphrase` issues one for exactly the segments whose class the
view grants, computed by the same partition `view_preview` reports, and seals it
under a passphrase typed at the terminal -- a grant passphrase is never the
case-key passphrase, never an argument and never an environment variable, and
the prompt names which of the two it is asking for. The grant file carries the
granted set in the clear: a recipient who cannot see what they were *not* given
cannot check that what opens is everything they were meant to have. Every
public field is bound into the one AEAD that seals the material, so none of it
can be edited without the passphrase. It also carries a root over the granted
segments' descriptors, which lets a reader with no passphrase establish that the
grant was issued against this record header exactly as it stands.

**The order is the guarantee.** The grant is issued, sealed, and written into
the ledger -- and handed back only after the ledger commit succeeds. A
disclosure the ledger could not record was not issued, and nothing says it was.
The sealed grant is then held by the run that issued it until `disclose_bundle`
writes it; it is copied key material, so it is never written into the ledger.

**The package** is the record (byte for byte, re-hashed against the digest
taken at the grant), the grant, the ledger's inclusion proof for the
Disclosure node, a report, and a manifest sealed and signed over the digests of
all four, with `SHA256SUMS` last. The snapshot root the proof resolves against
is **not** in the manifest. The proof file names it, as every proof must, and
checking a proof against a root its author supplied is checking nothing; the
examiner sends the root by another route, and `disclose_verify(dir, null)` is a
finding, never a pass.

**What `disclose_verify` runs**, each as its own reported check: the manifest's
seal and signature; every file's digest and the checksum file beside them; the
record's signature, with no key; that the grant names this disclosure and this
record, and describes its header exactly; complete-as-authorised -- the grant
opens exactly the segments whose class the view names, and the withheld list is
every other segment; with the passphrase, that every granted segment decrypts
with its tag holding; and, against the supplied root, that the ledger holds this
disclosure property for property. `verified` is true only when all of them ran
and passed.

**`disclose_to`**, sealing a grant to a recipient's public key instead of a
passphrase, is designed and deliberately not built. `crypto/ecdh` would make it
cost no dependency, but nothing in this tree creates a recipient key pair, and
this design settled that identity is examiner-asserted and that the tool issues
no credentials. Whether a recipient's key is something Mutant should mint, or
something it should only accept from outside, is the owner's decision.

## 13. The disclosure ledger

Every disclosure-family write is one signed, attributed graphene transaction in
a ledger opened by `ledger_open`. The labels are Case (graphene's own built-in
type), Actor, Record, Classification, View, Recipient, Disclosure, Withdrawal
and ReclassEvent; the edges IN_CASE, CLASSIFIED_AS, GRANTS, DISCLOSED_TO,
AUTHORISED_BY, PERFORMED_BY, WITHDREW and SUPERSEDES. Three properties of it are
worth stating:

- **A script cannot forge a disclosure.** `ledger_add_node` takes types 0 to 127;
  this schema's custom labels begin at 4096. A script can write a node with a
  property called `disclosure.uid` -- the property index is shared -- but not one
  labelled Disclosure, and every read filters on the label. `disclose_history`
  counts such nodes in `foreign` rather than hiding them.
- **Nodes are written once.** A Record, View, Recipient or Classification already
  present is found and reused; a Disclosure, Withdrawal or ReclassEvent is always
  new. A Record found under the same uid with a different file digest is
  refused, never reconciled by overwriting.
- **No Segment nodes.** The design called for one per segment "classified above
  open"; that condition cannot be evaluated, because classes are not ordered.
  The granted set is written as runs of segment indices on the Disclosure node
  and its GRANTS edge, so the graph's size follows the number of spans rather
  than the size of the evidence, and `disclose_for_segment` reads the runs.

## 14. See also

- [`docs/EVIDENCE_HANDLING_POLICY.md`](EVIDENCE_HANDLING_POLICY.md) — the rule
  governing the original, and the sentence this family inherits: a manifest that
  asserts something nobody verifies is worse than a manifest that says nothing,
  because it looks like verification.
- [`docs/CONFIGURATION_POLICY.md`](CONFIGURATION_POLICY.md) — why no
  configuration comes from the environment, and the guard that enforces it.
- [`docs/CAPABILITY_REFERENCE.md`](CAPABILITY_REFERENCE.md) — the chain-of-custody
  and case-key builtins.
