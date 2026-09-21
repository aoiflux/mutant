package builtin

// Custody and anchoring: what a ledger can account for, and the one question it
// cannot answer about itself.
//
// Everything the previous two files added compares the ledger to the ledger.
// An inclusion proof resolves against a root the store produced; a chain check
// links two snapshots the store wrote; `ledger_stats` counts what the store
// holds. All of it holds together perfectly for a store that was rebuilt from
// nothing by somebody holding the signing key, because every chain was rebuilt
// with it. Graphene says so in its own words and this file does not soften it:
//
//	"Every check here compares the store against itself. A report can therefore
//	 say the store is internally consistent and complete, and still be
//	 describing a store that was rewritten wholesale by someone holding the key."
//
// So this file adds two things. `ledger_custody` walks every history the store
// keeps and reports what could not be accounted for. `ledger_checkpoint` and
// `ledger_verify_anchor` deal with the only check that is not self-referential:
// a digest that went somewhere Mutant cannot reach and came back.
//
// # Gaps, not a verdict
//
// A custody report names what is missing. "Not verified" is useless to somebody
// holding evidence; "the segment chain is intact but nothing attested the
// current snapshot" tells them what to do next. Every gap carries its layer,
// whether it is a broken chain or one that was never established, and -- added
// here -- what to do about it.
//
// # Three of graphene's six gaps ask for an option this language does not have
//
// On a ledger that has been opened and written to but not yet compacted,
// graphene reports six gaps, and three of them end in instructions:
//
//	Set Options.Retention to keep it
//	Set Options.Audit to record them
//	Set Options.Roles to record it
//
// Two of those three are already set. `ledger_open` sets `Retention` to keep
// every retired segment and `StrictOptions` sets `Audit`; there are no retired
// segments and no audit entries because **nothing has been compacted yet**, and
// a compaction is what produces the first of each. An examiner following that
// advice goes looking for an options hash that deliberately does not exist --
// `builtin/db.go` and `builtin/ledger.go` both explain at length why the
// posture is fixed -- and does not call `ledger_compact`, which is the one
// thing that would close the gap.
//
// The third is a decision, not an oversight, and it never closes. See the
// roles section of `builtin/ledger.go`: Mutant authenticates nobody, and an
// empty grant ledger records no grants either.
//
// So every gap comes back with graphene's `detail` verbatim and a `remedy`
// beside it. Both, rather than a rewrite: a reader can see that the tool
// answered the library rather than being told two different things by two
// documents. `source` says which of them wrote the line.
//
// # There is no `complete` field
//
// Graphene has `CustodyReport.Complete()`, and it is false whenever any gap
// exists. Under this posture the roles gap never goes away, so the field would
// be false on every ledger Mutant can open, for a reason that has nothing to do
// with the ledger being examined. A field that reads the same on a pristine
// store and a ruined one is worse than no field.
//
// `broken` is reported, because it says something precise and actionable: some
// chain that was established has since failed. It is not the complement of a
// pass.
//
// # Custody answers where proving refuses
//
// `ledger_prove_node` refuses an id the store never held -- there is no proof
// to produce and saying so is the only honest result. `ledger_custody` returns
// a report with `live: false` instead, because "nothing was found to account
// for" *is* an account, and it is frequently the answer somebody is chasing.
// The two builtins disagree on purpose.
//
// # An anchor is somewhere Mutant cannot reach, so the witness is an argument
//
// Graphene defines an `Anchor` interface and ships no implementation, on the
// grounds that what makes an anchor an anchor is being beyond the reach of
// whoever can rewrite the store -- a property that comes from where it lives
// and who runs it, and that nothing inside this process can establish.
//
// Mutant ships no transport either, for the same reason plus one more: a
// timestamp authority, a transparency log or another organisation's storage is
// a network service, and the dependency policy keeps core functionality clear
// of those. What Mutant ships is the shape that policy does allow -- the
// witness arrives as data.
//
// `ledger_checkpoint` produces a digest. What happens to it next is the
// examiner's: a timestamping service, an email to opposing counsel, a line read
// out in a recorded call, a printed sheet in a safe. `ledger_verify_anchor`
// takes back what the witness says it holds and checks the store against it.
// The root was an argument in `ledger_verify_proof` for exactly this reason,
// and the witness is an argument here for the same one.
//
// **`disk.InsecureLocalAnchor` is not reachable from this language, and nothing
// here is a second one under another name.** Graphene's own comment calls it
// "not an anchor" and it exists so graphene's tests can run. A file on the
// machine that holds the store witnesses nothing about that store, and a
// builtin that wrote one would let a script produce a report saying "anchored".
// The two `Anchor` implementations in this file are each deliberately half of
// the interface: the capture anchor can publish and refuses to be read, the
// witness anchor can be read and refuses to publish. Neither can become the
// other and there is no third.
//
// # Capturing is not witnessing, and a digest cannot be captured twice
//
// `Store.Checkpoint()` stamps the capture with the current time before hashing,
// so two captures of an unchanged store produce two different digests. That
// rules out the obvious protocol -- look at the digest, publish it, then record
// it -- because the recorded digest would not be the published one. The digest
// has to be handed out by the same call that records it, which is why
// `ledger_checkpoint` records into the local chain and returns
// `witnessed: false`. Recording is a promise to publish, not a publication, and
// a checkpoint that is never published is reported by `ledger_verify_anchor` as
// a fatal finding rather than as an absence.
//
// # A write that has not been compacted moves nothing, and the anchor confirms
// # it anyway
//
// This is the trap in this file, and it reads as reassurance.
//
// A checkpoint binds six heads: the snapshot root, the attestation, the segment
// chain, the audit log, the redaction ledger and the grant ledger. An ordinary
// write moves **none of them** -- it lands in the write-ahead log, and nothing
// enters a snapshot until a compaction. So a ledger that has been written to
// since its last checkpoint reports, through graphene:
//
//	matched 1 of 1 checkpoints, broken false, current_matches_last true, 0 gaps
//
// which is true of the six heads and false of the ledger. The new records are
// there, and the witness has never seen anything that covers them.
//
// `delta_records` is the number that says so, and `VerifyAgainstAnchor` does
// not look at it. Both `ledger_checkpoint` and `ledger_verify_anchor` report
// it, and the latter adds a gap of its own when it is not zero. That gap is
// marked `source: "mutant"`, because it is not graphene's finding and a reader
// comparing this output against the library should be able to see which lines
// the library did not write.

import (
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/aoiflux/graphene/disk"
	"github.com/aoiflux/graphene/merkle"
	"github.com/aoiflux/graphene/store"

	"mutant/object"
)

// ledgerDigestHexLen is how many characters a checkpoint digest is written in.
const ledgerDigestHexLen = merkle.Size * 2

// ledgerRemedyCompact is the answer to most of what a fresh ledger is missing.
//
// A ledger that has never been compacted has no snapshot, no attestation over
// one, no retired segment and no audit entry, and graphene reports each of
// those separately in the vocabulary of the layer it came from. One call fixes
// all four, and saying so four times is better than leaving a reader to infer
// it from four different sentences.
const ledgerRemedyCompact = "call ledger_compact; a ledger that has never been compacted has no snapshot, nothing attesting one, no retired segment and no operator action on record, and one compaction produces all four"

// --- the two halves of graphene's Anchor interface ---------------------------

// ledgerCaptureAnchor is what graphene requires in order to record a checkpoint
// locally, and it is not an anchor.
//
// `PublishCheckpoint` is the only way into the local checkpoint chain --
// `appendCheckpoint` is unexported -- and it takes an `Anchor`. This type
// satisfies the interface by accepting the digest and doing nothing with it.
//
// `Records` refuses rather than returning nothing. An anchor that reports an
// empty witness list is a real and meaningful thing -- it is what
// `ledger_verify_anchor` is handed when nothing was ever published, and it
// makes every local checkpoint a fatal finding. If this type ever reached a
// verification path it would produce that same result for a different reason,
// so it fails loudly instead of quietly agreeing.
type ledgerCaptureAnchor struct{}

func (ledgerCaptureAnchor) Publish(digest merkle.Hash) (disk.AnchorRecord, error) {
	// The digest is echoed because graphene checks that the anchor acknowledged
	// the value it was given. The time and the reference are left empty: this
	// type has no witness to quote and will not invent one.
	return disk.AnchorRecord{Digest: digest}, nil
}

func (ledgerCaptureAnchor) Records() ([]disk.AnchorRecord, error) {
	return nil, fmt.Errorf("%s records a checkpoint; it witnesses nothing and cannot be read back as a witness", BuiltinNameLedgerCheckpoint)
}

// ledgerWitnessAnchor is the other half: what an external witness says it
// holds, as the caller reported it.
//
// `Publish` refuses. This is a read-only view of somebody else's record, and a
// verification path that could write to its own witness would be checking the
// store against a value it had just chosen.
type ledgerWitnessAnchor struct{ records []disk.AnchorRecord }

func (*ledgerWitnessAnchor) Publish(merkle.Hash) (disk.AnchorRecord, error) {
	return disk.AnchorRecord{}, fmt.Errorf("%s is a witness list supplied by the caller; it is read and never written", BuiltinNameLedgerVerifyAnchor)
}

func (w *ledgerWitnessAnchor) Records() ([]disk.AnchorRecord, error) { return w.records, nil }

// --- shared helpers ----------------------------------------------------------

// ledgerNodeArg reads the entity id the custody builtins take.
func ledgerNodeArg(arg object.Object, op string, pos int) (store.NodeID, *object.Error) {
	idArg, ok := arg.(*object.Integer)
	if !ok {
		return 0, newError("argument %d to `%s` must be INTEGER, got %s", pos, op, arg.Type())
	}
	if idArg.Value <= 0 {
		return 0, newError("%s: node ids start at 1, got %d", op, idArg.Value)
	}
	return store.NodeID(idArg.Value), nil
}

// ledgerDigestFromHex parses a checkpoint digest supplied by the caller.
//
// Worded for a digest rather than for a root: the two are the same size and the
// same encoding, and a message naming the wrong one sends a reader to the wrong
// builtin for the value they are missing.
func ledgerDigestFromHex(value, field, op string) (merkle.Hash, *object.Error) {
	var out merkle.Hash
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return out, newError("%s: %s must not be empty; a witness record is what something outside this machine says it holds, and an empty digest is not a record of anything", op, field)
	}
	raw, err := hex.DecodeString(trimmed)
	if err != nil {
		return out, newError("%s: %s is not hexadecimal: %s", op, field, err.Error())
	}
	if len(raw) != merkle.Size {
		return out, newError("%s: %s must be %d hex characters, got %d", op, field, ledgerDigestHexLen, len(trimmed))
	}
	copy(out[:], raw)
	if out == (merkle.Hash{}) {
		return merkle.Hash{}, newError("%s: %s is all zeroes, which is what an empty value looks like once it has been padded rather than a digest any checkpoint produced; ledger_checkpoint reports the digest to publish", op, field)
	}
	return out, nil
}

// ledgerDeltaRecords reports how many records are in the delta layer, and
// whether the question could be answered at all.
//
// The second return is not decoration. Zero pending records and "the store
// could not say" are the difference between a checkpoint that covers everything
// and one that may not, and a helper that returned 0 for both would suppress
// the gap in exactly the case where it matters.
func ledgerDeltaRecords(session *ledgerSession) (int64, bool) {
	stats, err := session.graph.Stats()
	if err != nil || !stats.HasStorage {
		return 0, false
	}
	return int64(stats.Storage.DeltaRecords()), true
}

// ledgerTime turns graphene's nanoseconds into a time, and zero into no time.
//
// Zero is not 1970 here. A head that was never established carries a zero
// timestamp, and rendering it as a date in 1970 puts a claim where there is an
// absence -- formatTime already returns "" for a zero time, so the only job is
// not to hand it a real one.
func ledgerTime(unixNano int64) time.Time {
	if unixNano == 0 {
		return time.Time{}
	}
	return time.Unix(0, unixNano).UTC()
}

// ledgerCustodyState is what the remedy for a gap depends on.
//
// external is the remedy for a non-fatal external gap, which differs by call
// site: the unanchored form is missing a root, the anchored form is missing a
// snapshot, and the anchor form is missing a fresh publication. Each builtin
// knows which of those it is; matching on graphene's prose to find out would
// break the first time a sentence was reworded.
type ledgerCustodyState struct {
	live       bool
	inSnapshot bool
	compacted  bool
	redacted   bool
	external   string
}

// ledgerRemedy is what to do about one gap, in this language.
//
// Empty where there is no single action -- a broken chain is an investigation,
// not a command to run. Keyed on the layer and on state this file computed
// itself rather than on the gap's text, so a reworded detail changes the report
// and not the advice.
func ledgerRemedy(gap disk.CustodyGap, state ledgerCustodyState) string {
	if gap.Fatal {
		return ""
	}
	switch gap.Layer {
	case disk.LayerSnapshot:
		switch {
		case state.redacted:
			// Graphene rewrites this gap's detail to point at the redaction
			// layer when the absence is a documented removal. Nothing to do.
			return ""
		case !state.compacted:
			return ledgerRemedyCompact
		case state.live:
			return "call ledger_compact; this entity was written after the last compaction, so it is live and in no snapshot, and nothing about it can be proved or accounted for until it is in one"
		default:
			return "none: this ledger has no such entity. Check the id against what ledger_add_node returned"
		}
	case disk.LayerAttestation:
		if !state.compacted {
			return ledgerRemedyCompact
		}
		return ""
	case disk.LayerSegments:
		return "call ledger_compact. ledger_open already sets the retention policy this gap asks for -- a segment is retired by a compaction, and none has happened"
	case disk.LayerAudit:
		return "call ledger_compact. ledger_open already sets the audit option this gap asks for -- the log records operator actions, and a compaction is the first one a ledger performs"
	case disk.LayerRoles:
		return "none, by decision: this posture records no grants. Mutant authenticates nobody, and an empty grant ledger would manufacture the appearance of an authorisation model behind a name somebody typed. See ledger_open"
	case disk.LayerExternal:
		return state.external
	default:
		return ""
	}
}

// ledgerGapObject renders one gap.
//
// source is the field that stops this report being read as graphene's. Every
// line the library wrote says so, and the lines added here say that instead.
func ledgerGapObject(gap disk.CustodyGap, source, remedy string) object.Object {
	return makeHashObject(map[string]object.Object{
		"layer":  stringObj(string(gap.Layer)),
		"fatal":  boolObj(gap.Fatal),
		"source": stringObj(source),
		"detail": stringObj(gap.Detail),
		"remedy": stringObj(remedy),
	})
}

// ledgerAddedGap is a finding this file made rather than read.
//
// It carries its own remedy. Graphene's gaps take theirs from the layer, which
// works because a layer is a history and the fix for a missing history is the
// same wherever it is reported. A gap added here is filed under the closest
// layer graphene's vocabulary has, which is not the same as being described by
// it -- so the advice travels with the finding.
type ledgerAddedGap struct {
	gap    disk.CustodyGap
	remedy string
}

// ledgerGapsInto renders a gap list and the two counts read off it.
func ledgerGapsInto(gaps []disk.CustodyGap, state ledgerCustodyState, extra []ledgerAddedGap, out map[string]object.Object) {
	elements := make([]object.Object, 0, len(gaps)+len(extra))
	broken := false
	for _, gap := range gaps {
		if gap.Fatal {
			broken = true
		}
		elements = append(elements, ledgerGapObject(gap, "graphene", ledgerRemedy(gap, state)))
	}
	for _, added := range extra {
		if added.gap.Fatal {
			broken = true
		}
		elements = append(elements, ledgerGapObject(added.gap, "mutant", added.remedy))
	}
	out["gaps"] = &object.Array{Elements: elements}
	out["gap_count"] = intObj(int64(len(elements)))
	out["broken"] = boolObj(broken)
}

// ledgerUnwitnessedGap is the finding graphene does not make.
//
// See the file header: an uncompacted write moves none of the six heads a
// checkpoint binds, so the anchor confirms a store whose newest records it has
// never seen anything about. Non-fatal, because a live ledger legitimately has
// records in flight -- what is wrong is reading the confirmation as covering
// them.
func ledgerUnwitnessedGap(delta int64, known bool) []ledgerAddedGap {
	const remedy = "call ledger_compact and then ledger_checkpoint, and publish the digest. A checkpoint binds the snapshot, so records have to be in one before anything outside can witness them"

	switch {
	case !known:
		return []ledgerAddedGap{{
			gap: disk.CustodyGap{
				Layer:  disk.LayerExternal,
				Detail: "the delta layer could not be counted, so it is not known whether this ledger holds records written since its last compaction. A checkpoint binds the snapshot, not the log",
			},
		}}
	case delta > 0:
		return []ledgerAddedGap{{
			gap: disk.CustodyGap{
				Layer:  disk.LayerExternal,
				Detail: fmt.Sprintf("%d record(s) have been written since the last compaction. A checkpoint binds the snapshot root, the attestation, the segment chain, the audit log, the redaction ledger and the grant ledger, and an uncompacted write moves none of them -- so nothing above covers these records, however many checkpoints the witness confirms", delta),
			},
			remedy: remedy,
		}}
	default:
		return nil
	}
}

// ledgerCustodyReport renders a custody report into the shared envelope.
func ledgerCustodyReport(session *ledgerSession, report disk.CustodyReport, checkedAgainst string, anchored bool, external string) *object.Hash {
	_, compactErr := session.store.SnapshotRoots()
	state := ledgerCustodyState{
		live:       report.Live,
		inSnapshot: report.InSnapshot,
		compacted:  compactErr == nil,
		redacted:   report.Redacted != nil,
		external:   external,
	}

	snapshotRoot := ""
	if report.InSnapshot {
		snapshotRoot = ledgerHash(report.SnapshotRoot)
	}

	delta, _ := ledgerDeltaRecords(session)

	out := map[string]object.Object{
		"node_id": intObj(int64(report.NodeID)),
		// Live and in_snapshot are separate for the reason graphene separates
		// them: an entity written since the last compaction is live and
		// unaccounted for, and one the store never held is absent. Both fail an
		// inclusion proof identically.
		"live":          boolObj(report.Live),
		"in_snapshot":   boolObj(report.InSnapshot),
		"snapshot_root": stringObj(snapshotRoot),
		// anchored says which form was called, and checked_against carries the
		// value the caller supplied, so a report read on its own says what it
		// was reached against. Empty for the unanchored form, which compared
		// the store to itself and nothing else.
		"anchored":        boolObj(anchored),
		"checked_against": stringObj(checkedAgainst),

		"attested":             boolObj(report.Attested),
		"attestation_verified": boolObj(report.AttestationVerified),
		"attest_actor_id":      stringObj(fmt.Sprintf("%d", report.AttestActorID)),

		// Counts of what was walked, so a short gap list can be told from
		// nothing having been there to check.
		"segments_checked":     intObj(int64(report.SegmentsChecked)),
		"audit_entries_walked": intObj(int64(report.AuditEntriesWalked)),
		"compactions_recorded": intObj(int64(report.CompactionsRecorded)),
		"redactions_walked":    intObj(int64(report.RedactionsWalked)),
		"grants_walked":        intObj(int64(report.GrantsWalked)),

		// A redaction turns an absence from an unexplained hole into a
		// documented removal. removal_provable says whether the compacted image
		// records it, or only the ledger does -- a ledger entry persuades
		// somebody holding the store, a tombstone under a retained root
		// persuades somebody holding nothing but the image.
		"redacted":         boolObj(report.Redacted != nil),
		"removal_provable": boolObj(report.RemovalProvable),

		// Reported, but not turned into a gap here. A custody report accounts
		// for one entity, and graphene's snapshot layer already says when that
		// entity is the one waiting for a compaction; a second finding about
		// what a checkpoint would or would not cover belongs where checkpoints
		// are the subject, which is ledger_verify_anchor.
		"delta_records": intObj(delta),
	}

	ledgerGapsInto(report.Gaps, state, nil, out)
	return makeHashObject(out)
}

// --- the builtins ------------------------------------------------------------

// LedgerCustody accounts for one entity across every history the ledger keeps.
//
// The unanchored form. It always carries the external gap, because every check
// it made compared the store to itself, and a report that left that implicit
// would let a short gap list be read as proof of something it cannot establish.
func LedgerCustody(args ...object.Object) object.Object {
	if len(args) != 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=2", len(args)))
	}
	session, errObj := ledgerHandleArg(args[0], BuiltinNameLedgerCustody)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	nodeID, errObj := ledgerNodeArg(args[1], BuiltinNameLedgerCustody, 2)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	// The verifier is the keyring this ledger was opened with. Passing nil is
	// allowed by graphene and downgrades every signature-dependent layer to
	// "unestablished", which would report an unchecked attestation on a store
	// whose key is right here.
	report, err := session.store.CustodyFor(nodeID, session.verifier)
	if err != nil {
		return resultAndError(nil, newError("%s: %s", BuiltinNameLedgerCustody, err.Error()))
	}

	const external = "call ledger_custody_anchored with a snapshot root retained outside this machine, or ledger_verify_anchor with what an external witness published. Nothing checked here came from outside the store"
	return resultAndError(ledgerCustodyReport(session, report, "", false, external), nil)
}

// LedgerCustodyAnchored is LedgerCustody with the snapshot checked against a
// root the caller retained elsewhere.
//
// A separate builtin rather than a nullable third argument. The root is the one
// value in the report that did not come from the store, so choosing to go
// without it should be visible in the source rather than expressed by a value
// that happens to be empty -- and an empty value reaching the anchored form
// would otherwise be indistinguishable from a deliberate "I have no root".
func LedgerCustodyAnchored(args ...object.Object) object.Object {
	if len(args) != 3 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=3", len(args)))
	}
	session, errObj := ledgerHandleArg(args[0], BuiltinNameLedgerCustodyAnchored)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	nodeID, errObj := ledgerNodeArg(args[1], BuiltinNameLedgerCustodyAnchored, 2)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	rootArg, ok := args[2].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 3 to `%s` must be STRING, got %s", BuiltinNameLedgerCustodyAnchored, args[2].Type()))
	}
	// Empty and all-zero are refused here rather than passed through. Graphene
	// compares the retained root to the store's and reports a mismatch as a
	// broken chain, so an examiner who had no root and supplied zeroes would be
	// told the image had been tampered with.
	root, errObj := ledgerRootFromHex(rootArg.Value, "the retained snapshot root", BuiltinNameLedgerCustodyAnchored)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	report, err := session.store.CustodyForAnchored(nodeID, session.verifier, root)
	if err != nil {
		return resultAndError(nil, newError("%s: %s", BuiltinNameLedgerCustodyAnchored, err.Error()))
	}

	const external = "call ledger_compact; an entity in no snapshot cannot be checked against a retained root, because the root is over the snapshot"
	return resultAndError(ledgerCustodyReport(session, report, ledgerHash(root), true, external), nil)
}

// ledgerCheckpointInto renders one checkpoint under a field prefix.
func ledgerCheckpointInto(c disk.Checkpoint, prefix string, out map[string]object.Object) {
	out[prefix+"seq"] = intObj(int64(c.Seq))
	out[prefix+"digest"] = stringObj(ledgerHash(c.Digest))
	out[prefix+"prev"] = stringObj(ledgerHash(c.Prev))
	// Seconds and a rendering, the way every other time in this tree is
	// reported. Graphene keeps nanoseconds; the language's whole time surface
	// is seconds, so the precision is kept in the text rather than handed out
	// in a unit no other builtin here accepts.
	out[prefix+"unix"] = intObj(c.UnixNano / 1e9)
	out[prefix+"at"] = stringObj(formatTime(ledgerTime(c.UnixNano)))

	// The six heads the digest binds. A zero head means that history was never
	// established, and the digest commits to the zero -- so "there was no audit
	// log" cannot later be retrofitted into "here is the audit log".
	out[prefix+"snapshot_root"] = stringObj(ledgerHash(c.SnapshotRoot))
	out[prefix+"attestation_id"] = stringObj(hex.EncodeToString(c.AttestationID[:]))
	out[prefix+"segment_head"] = stringObj(hex.EncodeToString(c.SegmentHead[:]))
	out[prefix+"audit_head"] = stringObj(ledgerHash(c.AuditHead))
	out[prefix+"redaction_head"] = stringObj(ledgerHash(c.RedactionHead))
	out[prefix+"grant_head"] = stringObj(ledgerHash(c.GrantHead))

	// Counts, so a truncation shows up as more than a changed hash.
	out[prefix+"segment_count"] = intObj(int64(c.SegmentCount))
	out[prefix+"audit_count"] = intObj(int64(c.AuditCount))
	out[prefix+"redaction_count"] = intObj(int64(c.RedactionCount))
	out[prefix+"grant_count"] = intObj(int64(c.GrantCount))
}

// LedgerCheckpoint binds every history's head into one digest and records it.
//
// The digest is the value to publish. Everything else is what it commits to.
//
// `witnessed` comes back false and is not computed: this call publishes
// nothing, and the field exists so that a manifest assembled from this hash
// cannot say otherwise by omission. It becomes a real answer in
// `ledger_verify_anchor`, under the same name, once somebody has said what they
// witnessed.
func LedgerCheckpoint(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}
	session, errObj := ledgerHandleArg(args[0], BuiltinNameLedgerCheckpoint)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	delta, _ := ledgerDeltaRecords(session)

	// The capture anchor is the only way into the local chain. See the file
	// header for why the digest cannot be looked at before it is recorded.
	checkpoint, _, err := session.store.PublishCheckpoint(ledgerCaptureAnchor{})
	if err != nil {
		return resultAndError(nil, newError("%s: %s", BuiltinNameLedgerCheckpoint, err.Error()))
	}

	out := map[string]object.Object{
		"actor":    stringObj(session.actor),
		"actor_id": stringObj(fmt.Sprintf("%d", session.actorID)),
		// False, always. Recording a checkpoint is a promise to publish its
		// digest, and until that happens ledger_verify_anchor reports this
		// checkpoint as a fatal finding rather than as an absence.
		"witnessed":     boolObj(false),
		"delta_records": intObj(delta),
	}
	ledgerCheckpointInto(checkpoint, "", out)

	custodyRecordArtifact(BuiltinNameLedgerCheckpoint,
		fmt.Sprintf("recorded checkpoint %d", checkpoint.Seq),
		map[string]any{
			"path":          session.path,
			"actor":         session.actor,
			"seq":           fmt.Sprintf("%d", checkpoint.Seq),
			"digest":        ledgerHash(checkpoint.Digest),
			"snapshot_root": ledgerHash(checkpoint.SnapshotRoot),
			"witnessed":     false,
		})

	return resultAndError(makeHashObject(out), nil)
}

// LedgerCheckpointHistory returns this ledger's local checkpoint chain.
//
// `chain_intact` is the weak check and the metadata says so. It recomputes each
// digest from its contents and each link from the one before, which catches a
// clumsy edit and nothing else: anyone who rewrites the chain forward passes
// it. That is exactly why the digests are published, and why this call is not
// the interesting one -- `ledger_verify_anchor` is.
func LedgerCheckpointHistory(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}
	session, errObj := ledgerHandleArg(args[0], BuiltinNameLedgerCheckpointHistory)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	chain, err := session.store.CheckpointHistory()
	if err != nil {
		return resultAndError(nil, newError("%s: %s", BuiltinNameLedgerCheckpointHistory, err.Error()))
	}

	elements := make([]object.Object, 0, len(chain))
	for _, c := range chain {
		fields := map[string]object.Object{}
		ledgerCheckpointInto(c, "", fields)
		elements = append(elements, makeHashObject(fields))
	}

	out := map[string]object.Object{
		"count":       intObj(int64(len(chain))),
		"checkpoints": &object.Array{Elements: elements},
	}
	if verr := disk.VerifyCheckpointChain(chain); verr != nil {
		out["chain_intact"] = boolObj(false)
		out["reason"] = stringObj(verr.Error())
	} else {
		out["chain_intact"] = boolObj(true)
		out["reason"] = stringObj("")
	}

	return resultAndError(makeHashObject(out), nil)
}

// ledgerWitnessRecords reads the witness list.
//
// One hash per published digest, carrying what the witness said: the digest, a
// time and optionally the witness's own reference for the publication -- a
// timestamp-token serial, a transaction hash, a URL, a page number.
//
// The time is required. It is the only field in a witness record the store
// could not have written itself, which is the entire reason the record is worth
// having; graphene renders it into the gap that reports how long the store has
// been running unwitnessed, and a missing one renders as 1970 and reads as a
// claim rather than as an omission.
func ledgerWitnessRecords(arg object.Object, op string) ([]disk.AnchorRecord, *object.Error) {
	list, ok := arg.(*object.Array)
	if !ok {
		return nil, newError("argument 2 to `%s` must be ARRAY, got %s", op, arg.Type())
	}

	records := make([]disk.AnchorRecord, 0, len(list.Elements))
	seen := make(map[merkle.Hash]int, len(list.Elements))
	for i, element := range list.Elements {
		entry, ok := element.(*object.Hash)
		if !ok {
			return nil, newError("%s: witness record %d must be a HASH with a digest and a unix time, got %s", op, i+1, element.Type())
		}

		digestValue, ok := hashValueByStringKey(entry, "digest")
		if !ok {
			return nil, newError("%s: witness record %d carries no digest; it is what the witness published and what this ledger's checkpoint chain is matched against", op, i+1)
		}
		digestText, ok := digestValue.(*object.String)
		if !ok {
			return nil, newError("%s: witness record %d has a digest of type %s; it must be STRING", op, i+1, digestValue.Type())
		}
		digest, errObj := ledgerDigestFromHex(digestText.Value, fmt.Sprintf("witness record %d's digest", i+1), op)
		if errObj != nil {
			return nil, errObj
		}
		if first, dup := seen[digest]; dup {
			// Graphene indexes the witness list by digest, so a repeat is
			// silently the same record and inflates nothing -- but a caller who
			// listed one publication twice believes they supplied two, and the
			// counts in the report would disagree with their source.
			return nil, newError("%s: witness records %d and %d carry the same digest; a publication is witnessed once", op, first, i+1)
		}
		seen[digest] = i + 1

		unixValue, ok := hashValueByStringKey(entry, "unix")
		if !ok {
			return nil, newError("%s: witness record %d carries no unix time; the time is the witness's own claim and the only part of the record this store could not have written itself", op, i+1)
		}
		unix, ok := unixValue.(*object.Integer)
		if !ok {
			return nil, newError("%s: witness record %d has a unix time of type %s; it must be INTEGER seconds, as time_unix and time_parse return", op, i+1, unixValue.Type())
		}
		if unix.Value <= 0 {
			return nil, newError("%s: witness record %d has a unix time of %d; a publication happened at a time, and zero renders as 1970 rather than as an absence", op, i+1, unix.Value)
		}

		ref := ""
		if refValue, ok := hashValueByStringKey(entry, "ref"); ok {
			refText, ok := refValue.(*object.String)
			if !ok {
				return nil, newError("%s: witness record %d has a ref of type %s; it must be STRING", op, i+1, refValue.Type())
			}
			ref = refText.Value
		}

		records = append(records, disk.AnchorRecord{Digest: digest, UnixNano: unix.Value * 1e9, Ref: ref})
	}
	return records, nil
}

// LedgerVerifyAnchor checks this ledger's checkpoint chain against what an
// external witness says it holds.
//
// The one check in this family that is not the store vouching for itself, and
// it runs both ways. A locally recorded checkpoint the witness never saw means
// the local chain was rewritten after the fact; a witnessed digest with no
// local checkpoint means the local record was destroyed. Graphene treats both
// as fatal, and the second reading has to be, because it is otherwise
// indistinguishable from innocence and strictly easier to perform.
//
// An empty witness list is a legitimate argument and not an error. It says
// nothing was ever published, and every local checkpoint becomes a finding --
// which is the honest reading of a store that recorded promises it did not
// keep.
func LedgerVerifyAnchor(args ...object.Object) object.Object {
	if len(args) != 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=2", len(args)))
	}
	session, errObj := ledgerHandleArg(args[0], BuiltinNameLedgerVerifyAnchor)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	records, errObj := ledgerWitnessRecords(args[1], BuiltinNameLedgerVerifyAnchor)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	audit, err := session.store.VerifyAgainstAnchor(&ledgerWitnessAnchor{records: records})
	if err != nil {
		return resultAndError(nil, newError("%s: %s", BuiltinNameLedgerVerifyAnchor, err.Error()))
	}

	delta, deltaKnown := ledgerDeltaRecords(session)

	out := map[string]object.Object{
		"checkpoints": intObj(int64(len(audit.Checkpoints))),
		"published":   intObj(int64(len(audit.Published))),
		"matched":     intObj(int64(audit.Matched)),
		// current_matches_last is graphene's, and it is about the six heads a
		// checkpoint binds. It is not about the ledger's contents: see
		// delta_records and the gap beside it.
		"current_matches_last": boolObj(audit.CurrentMatchesLast),
		"delta_records":        intObj(delta),
	}

	if last := audit.LastAnchored; last != nil {
		out["last_anchored_seq"] = intObj(int64(last.Seq))
		out["last_anchored_digest"] = stringObj(ledgerHash(last.Digest))
		out["last_anchored_snapshot_root"] = stringObj(ledgerHash(last.SnapshotRoot))
		// The witness's claimed time, not the store's. A time the store wrote
		// down is a time the store can rewrite, which is why this one comes
		// back from the argument rather than from the checkpoint.
		out["last_anchored_unix"] = intObj(audit.LastAnchoredAt / 1e9)
		out["last_anchored_at"] = stringObj(formatTime(ledgerTime(audit.LastAnchoredAt)))
	} else {
		out["last_anchored_seq"] = intObj(0)
		out["last_anchored_digest"] = stringObj("")
		out["last_anchored_snapshot_root"] = stringObj("")
		out["last_anchored_unix"] = intObj(0)
		out["last_anchored_at"] = stringObj("")
	}

	external := "call ledger_checkpoint and publish the digest it returns; everything since the last witnessed checkpoint rests on this store's own word"
	if len(audit.Checkpoints) == 0 {
		external = "call ledger_checkpoint, then publish the digest it returns somewhere this machine cannot reach"
	}
	state := ledgerCustodyState{compacted: true, external: external}

	// witnessed is every local checkpoint confirmed and no witnessed digest
	// unaccounted for. It says the two records agree, and it does not say the
	// ledger's contents are witnessed -- an uncompacted write is covered by
	// neither record, which is what delta_records and its gap are for.
	witnessed := len(audit.Checkpoints) > 0 && audit.Matched == len(audit.Checkpoints) && !audit.Broken()
	out["witnessed"] = boolObj(witnessed)

	ledgerGapsInto(audit.Gaps, state, ledgerUnwitnessedGap(delta, deltaKnown), out)
	return resultAndError(makeHashObject(out), nil)
}

// LedgerVerifyStore recomputes a compacted image's Merkle roots from the
// records the file actually holds.
//
// Worth running beside everything else here, and it asks a different question.
// The image carries a digest, and a digest asks "do these bytes match what was
// written"; this asks "do the roots describe the records in the same file". An
// adversary who edits a record and recomputes the digest defeats the first and
// not the second -- and if they recompute the roots too, the snapshot root
// changes, which is what a root retained elsewhere detects.
//
// It takes a path and not a handle, because the party who most needs it is the
// one holding a copy of the store and no reason to trust the process that wrote
// it. It runs on an open ledger too.
func LedgerVerifyStore(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}
	path, errObj := requireStringArg(BuiltinNameLedgerVerifyStore, args[0], 1)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		return resultAndError(nil, newError("%s: the path must not be empty", BuiltinNameLedgerVerifyStore))
	}

	out := map[string]object.Object{"path": stringObj(trimmed)}
	if err := disk.VerifyCSRRoots(trimmed); err != nil {
		// Something missing is a mistake about which path was passed, not a
		// finding about an image. Graphene reports it as a file that could not
		// be opened, which arrives as a raw OS message naming a file the caller
		// never mentioned -- and the two cases behind it need different words.
		if errors.Is(err, os.ErrNotExist) {
			if _, statErr := os.Stat(trimmed); statErr != nil {
				return resultAndError(nil, newError("%s: %s does not exist", BuiltinNameLedgerVerifyStore, trimmed))
			}
			return resultAndError(nil, newError("%s: %s holds no compacted image; either it is not a ledger directory, or the ledger has never been compacted", BuiltinNameLedgerVerifyStore, trimmed))
		}
		out["roots_match"] = boolObj(false)
		out["reason"] = stringObj(err.Error())
	} else {
		out["roots_match"] = boolObj(true)
		out["reason"] = stringObj("")
	}

	return resultAndError(makeHashObject(out), nil)
}
