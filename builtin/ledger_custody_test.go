package builtin

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aoiflux/graphene/disk"
	"github.com/aoiflux/graphene/merkle"
	"github.com/aoiflux/graphene/store"

	"mutant/object"
)

// custodyGap is one gap pulled back out of a report.
type custodyGap struct {
	layer  string
	fatal  bool
	source string
	detail string
	remedy string
}

// ledgerGaps reads the gap array a custody or anchor report returns.
func ledgerGaps(t *testing.T, name string, report *object.Hash) []custodyGap {
	t.Helper()

	value, ok := hashValueByStringKey(report, "gaps")
	if !ok {
		t.Fatalf("%s returned no gaps field", name)
	}
	list, ok := value.(*object.Array)
	if !ok {
		t.Fatalf("%s returned gaps of type %T, want ARRAY", name, value)
	}

	out := make([]custodyGap, 0, len(list.Elements))
	for i, element := range list.Elements {
		entry, ok := element.(*object.Hash)
		if !ok {
			t.Fatalf("%s gap %d is %T, want HASH", name, i, element)
		}
		out = append(out, custodyGap{
			layer:  mustHashStringValue(t, entry, "layer"),
			fatal:  mustHashBoolValue(t, entry, "fatal"),
			source: mustHashStringValue(t, entry, "source"),
			detail: mustHashStringValue(t, entry, "detail"),
			remedy: mustHashStringValue(t, entry, "remedy"),
		})
	}

	// gap_count is derived from the same slice, so a disagreement means the
	// count was computed somewhere the array was not.
	if got := mustHashIntValue(t, report, "gap_count"); got != int64(len(out)) {
		t.Errorf("%s reports gap_count %d over %d gaps", name, got, len(out))
	}
	return out
}

// gapsInLayer is every gap from one of graphene's six layers.
func gapsInLayer(gaps []custodyGap, layer string) []custodyGap {
	var out []custodyGap
	for _, gap := range gaps {
		if gap.layer == layer {
			out = append(out, gap)
		}
	}
	return out
}

// oneGapIn insists there is exactly one gap in a layer and returns it.
func oneGapIn(t *testing.T, gaps []custodyGap, layer string) custodyGap {
	t.Helper()

	found := gapsInLayer(gaps, layer)
	if len(found) != 1 {
		t.Fatalf("want exactly one %s gap, got %d: %+v", layer, len(found), gaps)
	}
	return found[0]
}

// ledgerSessionFor reaches the session behind a handle, for the tests that pin
// what graphene does rather than what Mutant reports about it.
func ledgerSessionFor(t *testing.T, handle int64) *ledgerSession {
	t.Helper()

	session, ok := ledgerGet(handle)
	if !ok {
		t.Fatalf("handle %d resolves to no ledger session", handle)
	}
	return session
}

// compactedTestLedger is a ledger with two nodes and one compaction, which is
// the smallest state in which anything here can be proved or accounted for.
func compactedTestLedger(t *testing.T) (handle int64, dir string, first int64) {
	t.Helper()

	handle, dir = openTestLedger(t, "G. Gogia")
	written := mustLedgerHash(t, BuiltinNameLedgerAddNode,
		LedgerAddNode(intObj(handle), ledgerProps(map[string]string{"uid": "rec-0001"})))
	first = mustHashIntValue(t, written, "id")
	mustLedgerHash(t, BuiltinNameLedgerAddNode,
		LedgerAddNode(intObj(handle), ledgerProps(map[string]string{"uid": "rec-0002"})))
	mustLedgerHash(t, BuiltinNameLedgerCompact, LedgerCompact(intObj(handle)))
	return handle, dir, first
}

// witnessRecord builds one entry of the array ledger_verify_anchor takes.
func witnessRecord(digest string, unix int64, ref string) *object.Hash {
	return makeHashObject(map[string]object.Object{
		"digest": stringObj(digest),
		"unix":   intObj(unix),
		"ref":    stringObj(ref),
	})
}

// TestACustodyReportNamesWhatIsMissingRatherThanReturningAVerdict is the shape
// of the whole family: a list of things that could not be accounted for, each
// saying which history it came from.
func TestACustodyReportNamesWhatIsMissingRatherThanReturningAVerdict(t *testing.T) {
	handle, _ := openTestLedger(t, "G. Gogia")
	written := mustLedgerHash(t, BuiltinNameLedgerAddNode,
		LedgerAddNode(intObj(handle), ledgerProps(map[string]string{"uid": "rec-0001"})))
	id := mustHashIntValue(t, written, "id")

	report := mustLedgerHash(t, BuiltinNameLedgerCustody, LedgerCustody(intObj(handle), intObj(id)))

	// A custody report is about one entity. Every gap in it is graphene's,
	// because the one finding this file adds is about what a checkpoint covers
	// and a custody report never mentions checkpoints.
	for _, gap := range ledgerGaps(t, BuiltinNameLedgerCustody, report) {
		if gap.source != "graphene" {
			t.Errorf("a custody report carries a %s gap: %s", gap.source, gap.detail)
		}
	}

	if !mustHashBoolValue(t, report, "live") {
		t.Error("a node just written is not reported live")
	}
	if mustHashBoolValue(t, report, "in_snapshot") {
		t.Error("a node written before any compaction is reported in a snapshot")
	}
	// Nothing established, nothing broken. The distinction is the point of the
	// gap's fatal flag: a chain that was never set up is not a chain that failed.
	if mustHashBoolValue(t, report, "broken") {
		t.Error("an un-compacted ledger is reported as broken")
	}

	gaps := ledgerGaps(t, BuiltinNameLedgerCustody, report)
	for _, layer := range []string{"snapshot", "attestation", "segments", "audit", "roles", "external"} {
		if len(gapsInLayer(gaps, layer)) == 0 {
			t.Errorf("no gap reported for the %s layer: %+v", layer, gaps)
		}
	}
	for _, gap := range gaps {
		if gap.fatal {
			t.Errorf("gap in layer %q is fatal on a ledger where nothing was ever established: %s", gap.layer, gap.detail)
		}
		if gap.detail == "" {
			t.Errorf("gap in layer %q carries no detail", gap.layer)
		}
	}
}

// TestThereIsNoCompleteFieldBecauseItWouldReadFalseOnEveryLedger pins both
// halves: graphene's Complete() is false even on a ledger with a correct
// retained root, and Mutant therefore does not return it.
func TestThereIsNoCompleteFieldBecauseItWouldReadFalseOnEveryLedger(t *testing.T) {
	handle, _, id := compactedTestLedger(t)
	session := ledgerSessionFor(t, handle)

	roots, err := session.store.SnapshotRoots()
	if err != nil {
		t.Fatalf("SnapshotRoots: %v", err)
	}

	// Graphene, directly. The anchor is the store's own root, which is the most
	// favourable argument that exists -- and the report still is not complete,
	// because this posture records no role grants by decision.
	report, err := session.store.CustodyForAnchored(store.NodeID(id), session.verifier, roots.Snapshot)
	if err != nil {
		t.Fatalf("CustodyForAnchored: %v", err)
	}
	if report.Complete() {
		t.Fatal("graphene now reports a roles-free ledger as complete; the reason this field is not surfaced has changed")
	}
	if report.Broken() {
		t.Fatalf("a correct retained root reports the ledger broken: %v", report.Gaps)
	}

	for _, name := range []string{BuiltinNameLedgerCustody, BuiltinNameLedgerCustodyAnchored} {
		var result object.Object
		if name == BuiltinNameLedgerCustody {
			result = LedgerCustody(intObj(handle), intObj(id))
		} else {
			result = LedgerCustodyAnchored(intObj(handle), intObj(id), stringObj(ledgerHash(roots.Snapshot)))
		}
		payload := mustLedgerHash(t, name, result)
		if _, ok := hashValueByStringKey(payload, "complete"); ok {
			t.Errorf("%s returns a complete field, which is false on every ledger this tool can open", name)
		}
	}
}

// TestTheRemedyForAGapIsTheOneThisLanguageCanFollow is the answer to graphene's
// advice.
//
// Three of its six details end by naming an option to set. Two of those options
// are already set by ledger_open and the real fix is a compaction; the third is
// a settled decision that never closes. Both halves are pinned: graphene's
// wording, so a reword is noticed, and the remedy beside it.
func TestTheRemedyForAGapIsTheOneThisLanguageCanFollow(t *testing.T) {
	handle, _ := openTestLedger(t, "G. Gogia")
	written := mustLedgerHash(t, BuiltinNameLedgerAddNode,
		LedgerAddNode(intObj(handle), ledgerProps(map[string]string{"uid": "rec-0001"})))
	id := mustHashIntValue(t, written, "id")

	report := mustLedgerHash(t, BuiltinNameLedgerCustody, LedgerCustody(intObj(handle), intObj(id)))
	gaps := ledgerGaps(t, BuiltinNameLedgerCustody, report)

	// The two that ledger_open has already answered.
	for _, tc := range []struct{ layer, grapheneAsks string }{
		{"segments", "Set Options.Retention"},
		{"audit", "Set Options.Audit"},
	} {
		gap := oneGapIn(t, gaps, tc.layer)
		if !strings.Contains(gap.detail, tc.grapheneAsks) {
			t.Errorf("the %s gap no longer says %q; the remedy beside it was written to answer that sentence: %s",
				tc.layer, tc.grapheneAsks, gap.detail)
		}
		if !strings.Contains(gap.remedy, BuiltinNameLedgerCompact) {
			t.Errorf("the %s gap's remedy does not name %s: %q", tc.layer, BuiltinNameLedgerCompact, gap.remedy)
		}
		if !strings.Contains(gap.remedy, "already sets") {
			t.Errorf("the %s gap's remedy does not say the option graphene asks for is already set: %q", tc.layer, gap.remedy)
		}
	}

	// The one that is a decision rather than an oversight.
	roles := oneGapIn(t, gaps, "roles")
	if !strings.Contains(roles.detail, "Set Options.Roles") {
		t.Errorf("the roles gap no longer asks for Options.Roles: %s", roles.detail)
	}
	if strings.Contains(roles.remedy, BuiltinNameLedgerCompact) {
		t.Errorf("the roles remedy suggests compacting, which does not record a grant: %q", roles.remedy)
	}
	if !strings.Contains(roles.remedy, "by decision") {
		t.Errorf("the roles remedy does not say the gap is deliberate: %q", roles.remedy)
	}

	// And the snapshot layer, whose remedy is the one call that closes four.
	snapshot := oneGapIn(t, gaps, "snapshot")
	if !strings.Contains(snapshot.remedy, BuiltinNameLedgerCompact) {
		t.Errorf("the snapshot remedy on a never-compacted ledger does not name %s: %q", BuiltinNameLedgerCompact, snapshot.remedy)
	}
}

// TestEveryGapSaysWhichOfTheTwoWroteIt keeps the tool's findings separable from
// the library's.
func TestEveryGapSaysWhichOfTheTwoWroteIt(t *testing.T) {
	handle, _, _ := compactedTestLedger(t)
	checkpoint := mustLedgerHash(t, BuiltinNameLedgerCheckpoint, LedgerCheckpoint(intObj(handle)))

	// A write after the checkpoint, so this tool's own gap is present too.
	mustLedgerHash(t, BuiltinNameLedgerAddNode,
		LedgerAddNode(intObj(handle), ledgerProps(map[string]string{"uid": "rec-0003"})))

	report := mustLedgerHash(t, BuiltinNameLedgerVerifyAnchor,
		LedgerVerifyAnchor(intObj(handle), &object.Array{Elements: []object.Object{
			witnessRecord(mustHashStringValue(t, checkpoint, "digest"), 1_700_000_000, "tsa:41"),
		}}))
	gaps := ledgerGaps(t, BuiltinNameLedgerVerifyAnchor, report)

	// Every graphene gap here belongs to the custody side: with a matching
	// witness and one uncompacted write, graphene reports nothing at all --
	// which is the trap, and the reason the gap below exists.
	custody := mustLedgerHash(t, BuiltinNameLedgerCustody, LedgerCustody(intObj(handle), intObj(1)))
	gaps = append(gaps, ledgerGaps(t, BuiltinNameLedgerCustody, custody)...)

	sources := map[string]int{}
	for _, gap := range gaps {
		switch gap.source {
		case "graphene", "mutant":
			sources[gap.source]++
		default:
			t.Errorf("gap in layer %q claims source %q", gap.layer, gap.source)
		}
	}
	if sources["graphene"] == 0 {
		t.Error("no gap is attributed to graphene")
	}
	if sources["mutant"] == 0 {
		t.Errorf("no gap is attributed to mutant on a ledger with uncompacted writes: %+v", gaps)
	}

	// And a gap this tool made carries advice this tool can act on, not the
	// remedy its layer would have given it.
	for _, gap := range gaps {
		if gap.source != "mutant" {
			continue
		}
		if !strings.Contains(gap.remedy, BuiltinNameLedgerCompact) {
			t.Errorf("the unwitnessed-tail gap's remedy does not name %s: %q", BuiltinNameLedgerCompact, gap.remedy)
		}
		if !strings.Contains(gap.remedy, BuiltinNameLedgerCheckpoint) {
			t.Errorf("the unwitnessed-tail gap's remedy does not name %s: %q", BuiltinNameLedgerCheckpoint, gap.remedy)
		}
	}
}

// TestCustodyAnswersWhereProvingRefuses is the deliberate disagreement between
// two builtins over the same id.
func TestCustodyAnswersWhereProvingRefuses(t *testing.T) {
	handle, _, _ := compactedTestLedger(t)
	const absent = 424242

	if _, errObj := unwrapPair(t, LedgerProveNode(intObj(handle), intObj(absent))); errObj == nil {
		t.Fatal("ledger_prove_node produced a proof for a node that does not exist")
	}

	report := mustLedgerHash(t, BuiltinNameLedgerCustody, LedgerCustody(intObj(handle), intObj(absent)))
	if mustHashBoolValue(t, report, "live") {
		t.Error("a node that does not exist is reported live")
	}
	if got := mustHashIntValue(t, report, "node_id"); got != absent {
		t.Errorf("the report is about node %d, asked about %d", got, absent)
	}
	// The snapshot gap has to say the store never held it, not that it is
	// waiting for a compaction -- those have opposite fixes.
	snapshot := oneGapIn(t, ledgerGaps(t, BuiltinNameLedgerCustody, report), "snapshot")
	if !strings.Contains(snapshot.detail, "no such entity") {
		t.Errorf("the snapshot gap for an absent node reads %q", snapshot.detail)
	}
	if strings.Contains(snapshot.remedy, BuiltinNameLedgerCompact) {
		t.Errorf("the remedy for an id this ledger never held is to compact: %q", snapshot.remedy)
	}
}

// TestARetainedRootIsRefusedRatherThanAssumed keeps the anchored form from
// being handed a value that means "I have no root".
func TestARetainedRootIsRefusedRatherThanAssumed(t *testing.T) {
	handle, _, id := compactedTestLedger(t)

	for _, tc := range []struct{ name, root string }{
		{"empty", ""},
		{"blank", "   "},
		{"all zeroes", strings.Repeat("0", 64)},
		{"too short", strings.Repeat("ab", 16)},
		{"not hexadecimal", strings.Repeat("zz", 32)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, errObj := unwrapPair(t, LedgerCustodyAnchored(intObj(handle), intObj(id), stringObj(tc.root)))
			if errObj == nil {
				t.Fatalf("a %s retained root was accepted", tc.name)
			}
			if !strings.Contains(errObj.Message, BuiltinNameLedgerCustodyAnchored) {
				t.Errorf("the refusal does not name the builtin: %s", errObj.Message)
			}
		})
	}
}

// TestARootFromElsewhereIsWhatSeparatesConsistentFromUntampered exercises the
// one check that is not the store comparing itself to itself.
func TestARootFromElsewhereIsWhatSeparatesConsistentFromUntampered(t *testing.T) {
	handle, _, id := compactedTestLedger(t)

	retained := mustLedgerHash(t, BuiltinNameLedgerRootExport, LedgerRootExport(intObj(handle)))
	root := mustHashStringValue(t, retained, "snapshot_root")

	// With the root that was actually retained, the external gap is answered.
	good := mustLedgerHash(t, BuiltinNameLedgerCustodyAnchored,
		LedgerCustodyAnchored(intObj(handle), intObj(id), stringObj(root)))
	if !mustHashBoolValue(t, good, "anchored") {
		t.Error("the anchored form does not report itself as anchored")
	}
	if got := mustHashStringValue(t, good, "checked_against"); got != root {
		t.Errorf("checked_against is %q, retained root is %q", got, root)
	}
	if mustHashBoolValue(t, good, "broken") {
		t.Errorf("a correct retained root reports the ledger broken: %+v", ledgerGaps(t, BuiltinNameLedgerCustodyAnchored, good))
	}
	if found := gapsInLayer(ledgerGaps(t, BuiltinNameLedgerCustodyAnchored, good), "external"); len(found) != 0 {
		t.Errorf("a correct retained root leaves an external gap: %+v", found)
	}

	// With any other root, the image is not the one that was recorded.
	other := strings.Repeat("11", 32)
	bad := mustLedgerHash(t, BuiltinNameLedgerCustodyAnchored,
		LedgerCustodyAnchored(intObj(handle), intObj(id), stringObj(other)))
	if !mustHashBoolValue(t, bad, "broken") {
		t.Fatal("a retained root that does not match the store is not reported as broken")
	}
	external := oneGapIn(t, ledgerGaps(t, BuiltinNameLedgerCustodyAnchored, bad), "external")
	if !external.fatal {
		t.Errorf("the mismatch is reported as merely incomplete: %s", external.detail)
	}

	// And the unanchored form always carries the external gap, whatever else it
	// found, because everything it checked came out of the store.
	plain := mustLedgerHash(t, BuiltinNameLedgerCustody, LedgerCustody(intObj(handle), intObj(id)))
	if got := mustHashStringValue(t, plain, "checked_against"); got != "" {
		t.Errorf("the unanchored form reports checked_against %q", got)
	}
	unanchored := oneGapIn(t, ledgerGaps(t, BuiltinNameLedgerCustody, plain), "external")
	if unanchored.fatal {
		t.Errorf("the absence of a retained root is reported as a broken chain: %s", unanchored.detail)
	}
	if !strings.Contains(unanchored.remedy, BuiltinNameLedgerCustodyAnchored) {
		t.Errorf("the external remedy does not name %s: %q", BuiltinNameLedgerCustodyAnchored, unanchored.remedy)
	}
}

// TestCapturingACheckpointIsNotPublishingIt pins the two facts that shape the
// whole anchoring surface: a capture is stamped with its time before it is
// hashed, and recording one claims no witness.
func TestCapturingACheckpointIsNotPublishingIt(t *testing.T) {
	handle, _, _ := compactedTestLedger(t)

	first := mustLedgerHash(t, BuiltinNameLedgerCheckpoint, LedgerCheckpoint(intObj(handle)))
	if mustHashBoolValue(t, first, "witnessed") {
		t.Fatal("ledger_checkpoint reports the checkpoint witnessed; it publishes nothing")
	}
	if got := mustHashIntValue(t, first, "seq"); got != 1 {
		t.Errorf("the first checkpoint has sequence %d", got)
	}
	firstDigest := mustHashStringValue(t, first, "digest")
	if firstDigest == "" || firstDigest == strings.Repeat("0", 64) {
		t.Fatalf("the first checkpoint's digest is %q", firstDigest)
	}
	if got := mustHashStringValue(t, first, "prev"); got != strings.Repeat("0", 64) {
		t.Errorf("the first checkpoint names a predecessor: %q", got)
	}

	// A second capture of a ledger nothing has touched. Every head is the same
	// and the digest is not, because the capture time is inside it -- which is
	// why there is no form of this call that shows the digest before recording it.
	second := mustLedgerHash(t, BuiltinNameLedgerCheckpoint, LedgerCheckpoint(intObj(handle)))
	if got := mustHashStringValue(t, second, "snapshot_root"); got != mustHashStringValue(t, first, "snapshot_root") {
		t.Error("an untouched ledger's snapshot root moved between two captures")
	}
	secondDigest := mustHashStringValue(t, second, "digest")
	if secondDigest == firstDigest {
		t.Fatal("two captures of an unchanged ledger produced the same digest; the publish-then-record protocol this family rules out would now be possible")
	}
	if got := mustHashStringValue(t, second, "prev"); got != firstDigest {
		t.Errorf("the second checkpoint's prev is %q, want the first's digest %q", got, firstDigest)
	}

	history := mustLedgerHash(t, BuiltinNameLedgerCheckpointHistory, LedgerCheckpointHistory(intObj(handle)))
	if got := mustHashIntValue(t, history, "count"); got != 2 {
		t.Errorf("the local chain holds %d checkpoints, want 2", got)
	}
	if !mustHashBoolValue(t, history, "chain_intact") {
		t.Errorf("the chain this process just wrote does not verify: %s", mustHashStringValue(t, history, "reason"))
	}
}

// TestACheckpointThatWasNeverPublishedIsAFindingNotAnAbsence is what makes
// recording a promise rather than a claim.
func TestACheckpointThatWasNeverPublishedIsAFindingNotAnAbsence(t *testing.T) {
	handle, _, _ := compactedTestLedger(t)
	mustLedgerHash(t, BuiltinNameLedgerCheckpoint, LedgerCheckpoint(intObj(handle)))

	// An empty witness list is a legitimate argument: it says nothing was ever
	// published.
	report := mustLedgerHash(t, BuiltinNameLedgerVerifyAnchor,
		LedgerVerifyAnchor(intObj(handle), &object.Array{}))
	if mustHashBoolValue(t, report, "witnessed") {
		t.Fatal("a checkpoint nobody published is reported as witnessed")
	}
	if !mustHashBoolValue(t, report, "broken") {
		t.Fatal("a local checkpoint absent from the witness is not reported as broken")
	}
	if got := mustHashIntValue(t, report, "matched"); got != 0 {
		t.Errorf("matched %d against an empty witness list", got)
	}
	gap := oneGapIn(t, ledgerGaps(t, BuiltinNameLedgerVerifyAnchor, report), "external")
	if !gap.fatal || !strings.Contains(gap.detail, "never published") {
		t.Errorf("the unpublished checkpoint is reported as %+v", gap)
	}
}

// TestTheWitnessIsAnArgumentAndNothingHereWritesOne is the design statement
// about anchoring, checked structurally.
//
// disk.InsecureLocalAnchor is not reachable from the language and neither is
// any other transport. The two Anchor implementations in this package are each
// half of the interface: the one that can record refuses to be read as a
// witness, and the one that can be read refuses to write. Neither can stand in
// for the other, so no path exists from "record a checkpoint" to "and treat
// that as having published it".
func TestTheWitnessIsAnArgumentAndNothingHereWritesOne(t *testing.T) {
	if _, err := (ledgerCaptureAnchor{}).Records(); err == nil {
		t.Error("the capture anchor can be read back as a witness")
	}
	if _, err := (&ledgerWitnessAnchor{}).Publish(merkle.Hash{}); err == nil {
		t.Error("the witness anchor can publish")
	}

	handle, _, _ := compactedTestLedger(t)
	checkpoint := mustLedgerHash(t, BuiltinNameLedgerCheckpoint, LedgerCheckpoint(intObj(handle)))
	digest := mustHashStringValue(t, checkpoint, "digest")

	report := mustLedgerHash(t, BuiltinNameLedgerVerifyAnchor,
		LedgerVerifyAnchor(intObj(handle), &object.Array{Elements: []object.Object{
			witnessRecord(digest, 1_700_000_000, "tsa:serial-41"),
		}}))

	if !mustHashBoolValue(t, report, "witnessed") {
		t.Fatalf("a published checkpoint is not reported witnessed: %+v", ledgerGaps(t, BuiltinNameLedgerVerifyAnchor, report))
	}
	if mustHashBoolValue(t, report, "broken") {
		t.Error("a matching witness list is reported as broken")
	}
	if got := mustHashIntValue(t, report, "matched"); got != 1 {
		t.Errorf("matched %d of 1", got)
	}
	if got := mustHashStringValue(t, report, "last_anchored_digest"); got != digest {
		t.Errorf("last_anchored_digest is %q, want %q", got, digest)
	}
	// The time comes back from the argument, not from the checkpoint: a time
	// the store wrote down is a time the store can rewrite.
	if got := mustHashIntValue(t, report, "last_anchored_unix"); got != 1_700_000_000 {
		t.Errorf("last_anchored_unix is %d, want the witness's claim", got)
	}
	if got := mustHashStringValue(t, report, "last_anchored_at"); !strings.HasPrefix(got, "2023-11-14") {
		t.Errorf("last_anchored_at is %q, want the witness's claimed time rendered", got)
	}
}

// TestAnUncompactedWriteIsWitnessedByNothingAndGrapheneReportsNoGap is the trap
// in this file, and it reads as reassurance.
//
// A checkpoint binds six heads and an ordinary write moves none of them, so a
// ledger with records in flight is confirmed by its witness while those records
// are covered by nothing. Both halves are pinned: graphene's clean verdict, so
// the compensation is removed rather than left dangling if it ever changes, and
// Mutant's gap beside it.
func TestAnUncompactedWriteIsWitnessedByNothingAndGrapheneReportsNoGap(t *testing.T) {
	handle, _, _ := compactedTestLedger(t)
	checkpoint := mustLedgerHash(t, BuiltinNameLedgerCheckpoint, LedgerCheckpoint(intObj(handle)))
	digest := mustHashStringValue(t, checkpoint, "digest")
	if got := mustHashIntValue(t, checkpoint, "delta_records"); got != 0 {
		t.Fatalf("the ledger has %d records in flight at checkpoint time, want 0", got)
	}

	// One write, and no compaction.
	mustLedgerHash(t, BuiltinNameLedgerAddNode,
		LedgerAddNode(intObj(handle), ledgerProps(map[string]string{"uid": "rec-0003"})))

	// Graphene, directly. This is the assumption the gap below compensates for.
	session := ledgerSessionFor(t, handle)
	audit, err := session.store.VerifyAgainstAnchor(&ledgerWitnessAnchor{records: []disk.AnchorRecord{
		{Digest: mustMerkleHash(t, digest), UnixNano: 1_700_000_000e9, Ref: "tsa:serial-41"},
	}})
	if err != nil {
		t.Fatalf("VerifyAgainstAnchor: %v", err)
	}
	if len(audit.Gaps) != 0 || !audit.CurrentMatchesLast {
		t.Fatalf("graphene now notices a write since the last checkpoint (gaps=%d, current_matches_last=%v); the gap Mutant adds for it is no longer needed",
			len(audit.Gaps), audit.CurrentMatchesLast)
	}

	// And Mutant's reading of the same state.
	report := mustLedgerHash(t, BuiltinNameLedgerVerifyAnchor,
		LedgerVerifyAnchor(intObj(handle), &object.Array{Elements: []object.Object{
			witnessRecord(digest, 1_700_000_000, "tsa:serial-41"),
		}}))
	if got := mustHashIntValue(t, report, "delta_records"); got == 0 {
		t.Fatal("a record written since the last compaction is not counted")
	}
	// current_matches_last stays true: it is graphene's answer about the six
	// heads, and it is correct about them.
	if !mustHashBoolValue(t, report, "current_matches_last") {
		t.Error("current_matches_last went false on a ledger whose heads did not move")
	}

	gaps := ledgerGaps(t, BuiltinNameLedgerVerifyAnchor, report)
	var found bool
	for _, gap := range gaps {
		if gap.source == "mutant" && strings.Contains(gap.detail, "since the last compaction") {
			found = true
			if gap.fatal {
				t.Error("records in flight are reported as a broken chain; a live ledger legitimately has them")
			}
		}
	}
	if !found {
		t.Errorf("nothing reports that the witness covers none of the records written since the last compaction: %+v", gaps)
	}
}

// TestAWitnessedDigestWithNoLocalCheckpointIsFatal is the same attack from the
// other end: destroy the local record and the store looks as though it was
// never anchored.
func TestAWitnessedDigestWithNoLocalCheckpointIsFatal(t *testing.T) {
	handle, _, _ := compactedTestLedger(t)
	checkpoint := mustLedgerHash(t, BuiltinNameLedgerCheckpoint, LedgerCheckpoint(intObj(handle)))

	report := mustLedgerHash(t, BuiltinNameLedgerVerifyAnchor,
		LedgerVerifyAnchor(intObj(handle), &object.Array{Elements: []object.Object{
			witnessRecord(mustHashStringValue(t, checkpoint, "digest"), 1_700_000_000, "tsa:41"),
			witnessRecord(strings.Repeat("99", 32), 1_700_000_100, "tsa:42"),
		}}))

	if !mustHashBoolValue(t, report, "broken") {
		t.Fatal("a witnessed digest this ledger has no record of is not fatal")
	}
	if mustHashBoolValue(t, report, "witnessed") {
		t.Error("a ledger that cannot account for a publication is reported witnessed")
	}
	if got := mustHashIntValue(t, report, "published"); got != 2 {
		t.Errorf("published %d, want the two records supplied", got)
	}
}

// TestAWitnessRecordIsRefusedRatherThanGuessedAt walks the argument shape.
func TestAWitnessRecordIsRefusedRatherThanGuessedAt(t *testing.T) {
	handle, _, _ := compactedTestLedger(t)
	good := strings.Repeat("ab", 32)

	for _, tc := range []struct {
		name    string
		records object.Object
		want    string
	}{
		{"not an array", stringObj(good), "must be ARRAY"},
		{"element is not a hash", &object.Array{Elements: []object.Object{stringObj(good)}}, "must be a HASH"},
		{"no digest", &object.Array{Elements: []object.Object{
			makeHashObject(map[string]object.Object{"unix": intObj(1)})}}, "carries no digest"},
		{"digest is not text", &object.Array{Elements: []object.Object{
			makeHashObject(map[string]object.Object{"digest": intObj(1), "unix": intObj(1)})}}, "must be STRING"},
		{"digest is empty", &object.Array{Elements: []object.Object{witnessRecord("", 1, "")}}, "must not be empty"},
		{"digest is all zeroes", &object.Array{Elements: []object.Object{
			witnessRecord(strings.Repeat("0", 64), 1, "")}}, "all zeroes"},
		{"digest is short", &object.Array{Elements: []object.Object{witnessRecord("abcd", 1, "")}}, "64 hex characters"},
		{"digest is not hexadecimal", &object.Array{Elements: []object.Object{
			witnessRecord(strings.Repeat("zz", 32), 1, "")}}, "not hexadecimal"},
		{"the same publication twice", &object.Array{Elements: []object.Object{
			witnessRecord(good, 1, ""), witnessRecord(good, 2, "")}}, "witnessed once"},
		{"no time", &object.Array{Elements: []object.Object{
			makeHashObject(map[string]object.Object{"digest": stringObj(good)})}}, "carries no unix time"},
		{"time is not an integer", &object.Array{Elements: []object.Object{
			makeHashObject(map[string]object.Object{"digest": stringObj(good), "unix": stringObj("now")})}}, "INTEGER seconds"},
		{"time is zero", &object.Array{Elements: []object.Object{witnessRecord(good, 0, "")}}, "renders as 1970"},
		{"ref is not text", &object.Array{Elements: []object.Object{
			makeHashObject(map[string]object.Object{"digest": stringObj(good), "unix": intObj(1), "ref": intObj(7)})}}, "ref of type"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, errObj := unwrapPair(t, LedgerVerifyAnchor(intObj(handle), tc.records))
			if errObj == nil {
				t.Fatalf("%s was accepted", tc.name)
			}
			if !strings.Contains(errObj.Message, tc.want) {
				t.Errorf("refusal %q does not contain %q", errObj.Message, tc.want)
			}
		})
	}
}

// TestAFlippedByteIsFoundByTheRootsAndNotByTheFileBeingReadable is what
// ledger_verify_store is for.
func TestAFlippedByteIsFoundByTheRootsAndNotByTheFileBeingReadable(t *testing.T) {
	handle, dir, _ := compactedTestLedger(t)

	good := mustLedgerHash(t, BuiltinNameLedgerVerifyStore, LedgerVerifyStore(stringObj(dir)))
	if !mustHashBoolValue(t, good, "roots_match") {
		t.Fatalf("a ledger this process just compacted does not verify: %s", mustHashStringValue(t, good, "reason"))
	}
	if got := mustHashStringValue(t, good, "reason"); got != "" {
		t.Errorf("a passing check carries a reason: %q", got)
	}

	// Close first: the image is what is being edited, and an open store holds
	// its own view of it.
	if _, errObj := unwrapPair(t, LedgerClose(intObj(handle))); errObj != nil {
		t.Fatalf("ledger_close: %s", errObj.Message)
	}

	image := filepath.Join(dir, "graphene.csr")
	data, err := os.ReadFile(image)
	if err != nil {
		t.Fatalf("read the image: %v", err)
	}
	data[len(data)/2] ^= 0x01
	if err := os.WriteFile(image, data, 0o600); err != nil {
		t.Fatalf("write the image: %v", err)
	}

	bad := mustLedgerHash(t, BuiltinNameLedgerVerifyStore, LedgerVerifyStore(stringObj(dir)))
	if mustHashBoolValue(t, bad, "roots_match") {
		t.Fatal("an edited image's roots still describe its records")
	}
	if mustHashStringValue(t, bad, "reason") == "" {
		t.Error("a failing check says nothing about why")
	}

	// The same file, named directly rather than by its directory.
	byFile := mustLedgerHash(t, BuiltinNameLedgerVerifyStore, LedgerVerifyStore(stringObj(image)))
	if mustHashBoolValue(t, byFile, "roots_match") {
		t.Error("the same image passes when named by file rather than by directory")
	}
}

// TestVerifyStoreRefusesAPathHoldingNoImage keeps a mistake about which path
// was passed from being reported as a finding about an image.
func TestVerifyStoreRefusesAPathHoldingNoImage(t *testing.T) {
	empty := t.TempDir()

	for _, tc := range []struct{ name, path, want string }{
		{"a directory with no store", empty, "holds no compacted image"},
		{"a path that does not exist", filepath.Join(empty, "nowhere"), "does not exist"},
		{"an empty path", "", "must not be empty"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, errObj := unwrapPair(t, LedgerVerifyStore(stringObj(tc.path)))
			if errObj == nil {
				t.Fatalf("%s was accepted", tc.name)
			}
			if !strings.Contains(errObj.Message, tc.want) {
				t.Errorf("refusal %q does not contain %q", errObj.Message, tc.want)
			}
		})
	}

	// A ledger that exists but has never been compacted is the same answer:
	// there is no image to check, and it is not a failed check.
	handle, dir := openTestLedger(t, "G. Gogia")
	mustLedgerHash(t, BuiltinNameLedgerAddNode,
		LedgerAddNode(intObj(handle), ledgerProps(map[string]string{"uid": "rec-0001"})))
	if _, errObj := unwrapPair(t, LedgerVerifyStore(stringObj(dir))); errObj == nil {
		t.Error("a ledger with no compacted image reports a verdict about one")
	}
}

// TestEveryCustodyBuiltinRefusesAHandleThatIsNotOne covers the whole family at
// its first argument.
func TestEveryCustodyBuiltinRefusesAHandleThatIsNotOne(t *testing.T) {
	handle, _, id := compactedTestLedger(t)
	root := mustHashStringValue(t,
		mustLedgerHash(t, BuiltinNameLedgerRootExport, LedgerRootExport(intObj(handle))), "snapshot_root")

	for _, tc := range []struct {
		name string
		call func(object.Object) object.Object
	}{
		{BuiltinNameLedgerCustody, func(h object.Object) object.Object { return LedgerCustody(h, intObj(id)) }},
		{BuiltinNameLedgerCustodyAnchored, func(h object.Object) object.Object {
			return LedgerCustodyAnchored(h, intObj(id), stringObj(root))
		}},
		{BuiltinNameLedgerCheckpoint, func(h object.Object) object.Object { return LedgerCheckpoint(h) }},
		{BuiltinNameLedgerCheckpointHistory, func(h object.Object) object.Object { return LedgerCheckpointHistory(h) }},
		{BuiltinNameLedgerVerifyAnchor, func(h object.Object) object.Object {
			return LedgerVerifyAnchor(h, &object.Array{})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, bad := range []object.Object{stringObj("1"), intObj(handle + 9999)} {
				if _, errObj := unwrapPair(t, tc.call(bad)); errObj == nil {
					t.Errorf("%s accepted %s as a ledger handle", tc.name, bad.Inspect())
				}
			}
		})
	}
}

// TestEveryCustodyBuiltinChecksItsArity keeps a missing argument from being read
// as a default.
func TestEveryCustodyBuiltinChecksItsArity(t *testing.T) {
	handle, _, id := compactedTestLedger(t)

	for _, tc := range []struct {
		name string
		call func(...object.Object) object.Object
		args [][]object.Object
	}{
		{BuiltinNameLedgerCustody, LedgerCustody, [][]object.Object{
			{}, {intObj(handle)}, {intObj(handle), intObj(id), intObj(1)}}},
		{BuiltinNameLedgerCustodyAnchored, LedgerCustodyAnchored, [][]object.Object{
			{}, {intObj(handle), intObj(id)}, {intObj(handle), intObj(id), stringObj(""), intObj(1)}}},
		{BuiltinNameLedgerCheckpoint, LedgerCheckpoint, [][]object.Object{
			{}, {intObj(handle), intObj(1)}}},
		{BuiltinNameLedgerCheckpointHistory, LedgerCheckpointHistory, [][]object.Object{
			{}, {intObj(handle), intObj(1)}}},
		{BuiltinNameLedgerVerifyAnchor, LedgerVerifyAnchor, [][]object.Object{
			{}, {intObj(handle)}, {intObj(handle), &object.Array{}, intObj(1)}}},
		{BuiltinNameLedgerVerifyStore, LedgerVerifyStore, [][]object.Object{
			{}, {stringObj("a"), stringObj("b")}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, args := range tc.args {
				if _, errObj := unwrapPair(t, tc.call(args...)); errObj == nil {
					t.Errorf("%s accepted %d arguments", tc.name, len(args))
				}
			}
		})
	}
}

// TestEveryCustodyBuiltinReturnsTheDeclaredFields keeps the metadata and the
// implementations from drifting, which is what hover, completion and the
// conformance probes all read.
func TestEveryCustodyBuiltinReturnsTheDeclaredFields(t *testing.T) {
	handle, dir, id := compactedTestLedger(t)
	root := mustHashStringValue(t,
		mustLedgerHash(t, BuiltinNameLedgerRootExport, LedgerRootExport(intObj(handle))), "snapshot_root")
	checkpoint := mustLedgerHash(t, BuiltinNameLedgerCheckpoint, LedgerCheckpoint(intObj(handle)))

	for _, tc := range []struct {
		name   string
		result object.Object
	}{
		{BuiltinNameLedgerCustody, LedgerCustody(intObj(handle), intObj(id))},
		{BuiltinNameLedgerCustodyAnchored, LedgerCustodyAnchored(intObj(handle), intObj(id), stringObj(root))},
		{BuiltinNameLedgerCheckpoint, LedgerCheckpoint(intObj(handle))},
		{BuiltinNameLedgerCheckpointHistory, LedgerCheckpointHistory(intObj(handle))},
		{BuiltinNameLedgerVerifyAnchor, LedgerVerifyAnchor(intObj(handle), &object.Array{Elements: []object.Object{
			witnessRecord(mustHashStringValue(t, checkpoint, "digest"), 1_700_000_000, "tsa:41"),
		}})},
		{BuiltinNameLedgerVerifyStore, LedgerVerifyStore(stringObj(dir))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			payload, errObj := unwrapPair(t, tc.result)
			if errObj != nil {
				t.Fatalf("%s: %s", tc.name, errObj.Message)
			}
			assertLedgerDeclaredFields(t, tc.name, payload)
		})
	}
}

// mustMerkleHash parses a hex root for the tests that talk to graphene directly.
func mustMerkleHash(t *testing.T, text string) merkle.Hash {
	t.Helper()

	hash, errObj := ledgerDigestFromHex(text, "digest", "test")
	if errObj != nil {
		t.Fatalf("parse %q: %s", text, errObj.Message)
	}
	return hash
}
