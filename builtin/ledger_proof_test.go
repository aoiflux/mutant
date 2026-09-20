package builtin

import (
	"bytes"
	"strings"
	"testing"

	"github.com/aoiflux/graphene/disk"
	"github.com/aoiflux/graphene/store"

	"mutant/object"
)

// --- helpers ---------------------------------------------------------------

func mustLedgerBytes(t *testing.T, hash *object.Hash, key string) []byte {
	t.Helper()

	value, ok := hashValueByStringKey(hash, key)
	if !ok {
		t.Fatalf("missing key %q", key)
	}
	buf, ok := value.(*object.Bytes)
	if !ok {
		t.Fatalf("key %q is %T, want *object.Bytes", key, value)
	}
	return buf.Value
}

// proveOneNode writes a node, compacts, and returns its id, its proof bytes
// and the root the proof resolves against.
func proveOneNode(t *testing.T, handle int64, props map[string]string) (int64, []byte, string) {
	t.Helper()

	written := mustLedgerHash(t, "ledger_add_node",
		LedgerAddNode(intObj(handle), ledgerProps(props)))
	id := mustHashIntValue(t, written, "id")

	if _, errObj := unwrapPair(t, LedgerCompact(intObj(handle))); errObj != nil {
		t.Fatalf("ledger_compact: %s", errObj.Message)
	}

	proof := mustLedgerHash(t, "ledger_prove_node",
		LedgerProveNode(intObj(handle), intObj(id)))
	return id, mustLedgerBytes(t, proof, "proof"), mustHashStringValue(t, proof, "snapshot_root")
}

// --- nothing is provable until there is a snapshot -------------------------

func TestNothingIsProvableUntilThereIsASnapshotToProveAgainst(t *testing.T) {
	handle, _ := openTestLedger(t, "G. Gogia")

	written := mustLedgerHash(t, "ledger_add_node",
		LedgerAddNode(intObj(handle), ledgerProps(map[string]string{"uid": "rec-1"})))
	id := mustHashIntValue(t, written, "id")

	_, errObj := unwrapPair(t, LedgerProveNode(intObj(handle), intObj(id)))
	if errObj == nil {
		t.Fatal("proved a node in a ledger that has never been compacted")
	}
	// The refusal has to name the fix. "no snapshot roots" is a true sentence
	// that leaves the caller nowhere to go.
	if !strings.Contains(errObj.Message, "ledger_compact") {
		t.Errorf("the refusal does not say what to do about it: %s", errObj.Message)
	}

	_, errObj = unwrapPair(t, LedgerRootExport(intObj(handle)))
	if errObj == nil {
		t.Fatal("exported a root from a ledger that has never been compacted")
	}
	if !strings.Contains(errObj.Message, "ledger_compact") {
		t.Errorf("the refusal does not say what to do about it: %s", errObj.Message)
	}
}

// ledger_root_export refuses where ledger_stats reports, and the difference is
// the point: one says what the ledger is, the other produces a value somebody
// will write down.
func TestARootIsRefusedRatherThanReturnedEmpty(t *testing.T) {
	handle, _ := openTestLedger(t, "G. Gogia")

	stats := mustLedgerHash(t, "ledger_stats", LedgerStats(intObj(handle)))
	if got := mustHashStringValue(t, stats, "snapshot_root"); got != "" {
		t.Fatalf("ledger_stats snapshot_root = %q, want empty before any compaction", got)
	}
	if mustHashBoolValue(t, stats, "compacted") {
		t.Fatal("ledger_stats reports compacted before any compaction")
	}

	if _, errObj := unwrapPair(t, LedgerRootExport(intObj(handle))); errObj == nil {
		t.Fatal("ledger_root_export returned a root where ledger_stats reported none; " +
			"an empty root retained now is an empty root quoted later as though it were one")
	}
}

// --- the headline: two situations, one graphene error ----------------------

// Graphene returns ErrNotInSnapshot both for an entity written since the last
// compaction and for an entity that was never written at all. The two have
// opposite fixes -- compact, versus you have the wrong id -- so this pins both
// the graphene behaviour this family compensates for and the compensation.
func TestLiveButUnprovenIsNotTheSameThingAsAbsent(t *testing.T) {
	handle, _ := openTestLedger(t, "G. Gogia")

	// One node in the snapshot, one written after it.
	inSnapshot, _, _ := proveOneNode(t, handle, map[string]string{"uid": "rec-1"})
	written := mustLedgerHash(t, "ledger_add_node",
		LedgerAddNode(intObj(handle), ledgerProps(map[string]string{"uid": "rec-2"})))
	afterSnapshot := mustHashIntValue(t, written, "id")
	const neverWritten = 4242

	// First, the assumption this whole builtin exists for: graphene cannot
	// tell them apart. If a later version can, the compensation below should
	// be reconsidered rather than silently kept.
	session, ok := ledgerGet(handle)
	if !ok {
		t.Fatal("the ledger handle did not resolve")
	}
	_, liveErr := session.store.ProveNode(store.NodeID(afterSnapshot))
	_, ghostErr := session.store.ProveNode(store.NodeID(neverWritten))
	if liveErr == nil || ghostErr == nil {
		t.Fatal("graphene proved a node that is in no snapshot")
	}
	if !errorsIsNotInSnapshot(liveErr) || !errorsIsNotInSnapshot(ghostErr) {
		t.Fatalf("graphene no longer reports both as ErrNotInSnapshot: live=%v ghost=%v", liveErr, ghostErr)
	}

	// Now the two answers Mutant gives instead of the one.
	_, errObj := unwrapPair(t, LedgerProveNode(intObj(handle), intObj(afterSnapshot)))
	if errObj == nil {
		t.Fatal("proved a node written after the last compaction")
	}
	if !strings.Contains(errObj.Message, "live") || !strings.Contains(errObj.Message, "ledger_compact") {
		t.Errorf("a live-but-uncompacted node should be answered with compaction, got: %s", errObj.Message)
	}

	_, errObj = unwrapPair(t, LedgerProveNode(intObj(handle), intObj(neverWritten)))
	if errObj == nil {
		t.Fatal("proved a node that was never written")
	}
	if strings.Contains(errObj.Message, "ledger_compact") {
		t.Errorf("a node that does not exist should not be answered with compaction, got: %s", errObj.Message)
	}
	if !strings.Contains(errObj.Message, "no node") {
		t.Errorf("the refusal does not say the node is absent: %s", errObj.Message)
	}

	// And the one that is in the snapshot still proves.
	if _, errObj := unwrapPair(t, LedgerProveNode(intObj(handle), intObj(inSnapshot))); errObj != nil {
		t.Fatalf("the compacted node stopped proving: %s", errObj.Message)
	}
}

func errorsIsNotInSnapshot(err error) bool {
	return err != nil && strings.Contains(err.Error(), disk.ErrNotInSnapshot.Error())
}

// --- a proof needs a root and nothing else ---------------------------------

func TestAProofVerifiesWithTheBytesAndARootAndNothingElse(t *testing.T) {
	handle, _ := openTestLedger(t, "G. Gogia")
	id, proof, root := proveOneNode(t, handle, map[string]string{"uid": "rec-1", "case": "IR-1"})

	// Closed first: the verifier has no store, which is the property the whole
	// exercise exists for.
	if _, errObj := unwrapPair(t, LedgerClose(intObj(handle))); errObj != nil {
		t.Fatalf("ledger_close: %s", errObj.Message)
	}

	result := mustLedgerHash(t, "ledger_verify_proof",
		LedgerVerifyProof(&object.Bytes{Value: proof}, stringObj(root)))

	if !mustHashBoolValue(t, result, "verified") {
		t.Fatalf("a proof straight out of the ledger did not verify: %s",
			mustHashStringValue(t, result, "reason"))
	}
	if got := mustHashIntValue(t, result, "node_id"); got != id {
		t.Errorf("node_id = %d, want %d", got, id)
	}
	if got := mustHashStringValue(t, result, "kind"); got != "node-inclusion" {
		t.Errorf("kind = %q", got)
	}
	// Both roots, always, so a reader can see what the verdict was reached
	// between.
	if got := mustHashStringValue(t, result, "checked_against"); got != root {
		t.Errorf("checked_against = %q, want %q", got, root)
	}
	if got := mustHashStringValue(t, result, "stated_snapshot_root"); got != root {
		t.Errorf("stated_snapshot_root = %q, want %q", got, root)
	}
}

// The refusal that keeps the family honest.
func TestAProofIsNeverCheckedAgainstARootTakenFromItself(t *testing.T) {
	handle, _ := openTestLedger(t, "G. Gogia")
	_, proof, root := proveOneNode(t, handle, map[string]string{"uid": "rec-1"})

	for name, supplied := range map[string]string{
		"empty":        "",
		"blank":        "   ",
		"all zeroes":   strings.Repeat("0", 64),
		"short":        root[:32],
		"not hex":      strings.Repeat("z", 64),
		"a proof file": "GPRF",
	} {
		t.Run(name, func(t *testing.T) {
			_, errObj := unwrapPair(t, LedgerVerifyProof(&object.Bytes{Value: proof}, stringObj(supplied)))
			if errObj == nil {
				t.Fatalf("accepted %s as a snapshot root", name)
			}
		})
	}

	// The empty case is the one a script reaches by having nowhere to get a
	// root, so its message has to say where roots come from.
	_, errObj := unwrapPair(t, LedgerVerifyProof(&object.Bytes{Value: proof}, stringObj("")))
	if !strings.Contains(errObj.Message, "independently") {
		t.Errorf("the refusal does not explain why the root cannot come from the proof: %s", errObj.Message)
	}
	_, errObj = unwrapPair(t, LedgerVerifyProof(&object.Bytes{Value: proof}, stringObj(strings.Repeat("0", 64))))
	if !strings.Contains(errObj.Message, "ledger_root_export") {
		t.Errorf("the all-zero refusal does not say where a real root comes from: %s", errObj.Message)
	}
}

// A well-formed proof checked against the wrong root is a verdict, not a crash.
func TestAProofCheckedAgainstAnUnrelatedRootIsFalseNotBroken(t *testing.T) {
	handleA, _ := openTestLedger(t, "G. Gogia")
	_, proofA, rootA := proveOneNode(t, handleA, map[string]string{"uid": "rec-A"})

	handleB, _ := openTestLedger(t, "G. Gogia")
	_, _, rootB := proveOneNode(t, handleB, map[string]string{"uid": "rec-B"})

	if rootA == rootB {
		t.Fatal("two different ledgers produced the same snapshot root")
	}

	result := mustLedgerHash(t, "ledger_verify_proof",
		LedgerVerifyProof(&object.Bytes{Value: proofA}, stringObj(rootB)))
	if mustHashBoolValue(t, result, "verified") {
		t.Fatal("a proof from one ledger verified against another ledger's root")
	}
	if mustHashStringValue(t, result, "reason") == "" {
		t.Error("a false verdict came back with no reason")
	}
	// The two roots differ, and both are reported, which is what says the
	// proof is about a different snapshot rather than simply being false.
	if mustHashStringValue(t, result, "checked_against") == mustHashStringValue(t, result, "stated_snapshot_root") {
		t.Error("checked_against and stated_snapshot_root agree on a failed verification")
	}
}

// --- malformed is an error; false is a value -------------------------------

func TestAnUnreadableProofIsAnErrorAndAReadableFalseOneIsAValue(t *testing.T) {
	handle, _ := openTestLedger(t, "G. Gogia")
	_, proof, root := proveOneNode(t, handle, map[string]string{"uid": "rec-1"})

	unreadable := map[string][]byte{
		"not a proof at all": []byte("this is not a proof"),
		"empty":              {},
		"truncated":          proof[:len(proof)-9],
		"a trailing byte":    append(append([]byte(nil), proof...), 0x00),
	}
	for name, blob := range unreadable {
		t.Run(name, func(t *testing.T) {
			if _, errObj := unwrapPair(t, LedgerVerifyProof(&object.Bytes{Value: blob}, stringObj(root))); errObj == nil {
				t.Fatalf("%s was accepted as a readable proof", name)
			}
			if _, errObj := unwrapPair(t, LedgerProofDescribe(&object.Bytes{Value: blob})); errObj == nil {
				t.Fatalf("%s was described as though it were a proof", name)
			}
		})
	}

	// A byte flipped inside the roots region still decodes. "It parsed" is not
	// a weaker form of "it verified", and the two have to come back
	// differently or a corrupt download reads as a forgery.
	flipped := append([]byte(nil), proof...)
	flipped[len(flipped)-1] ^= 0xFF
	result, errObj := unwrapPair(t, LedgerVerifyProof(&object.Bytes{Value: flipped}, stringObj(root)))
	if errObj != nil {
		t.Skipf("this build's encoding rejects the flipped byte at decode time: %s", errObj.Message)
	}
	if mustHashBoolValue(t, result.(*object.Hash), "verified") {
		t.Fatal("a proof with a flipped byte verified")
	}
}

// --- proofs are bound to a snapshot ----------------------------------------

func TestEveryCompactionMovesTheRootAProofResolvesAgainst(t *testing.T) {
	handle, _ := openTestLedger(t, "G. Gogia")
	id, firstProof, firstRoot := proveOneNode(t, handle, map[string]string{"uid": "rec-1"})

	// Something else happens in the ledger, and it is compacted again. The
	// entity being proved is untouched.
	if _, errObj := unwrapPair(t, LedgerAddNode(intObj(handle), ledgerProps(map[string]string{"uid": "rec-2"}))); errObj != nil {
		t.Fatalf("ledger_add_node: %s", errObj.Message)
	}
	if _, errObj := unwrapPair(t, LedgerCompact(intObj(handle))); errObj != nil {
		t.Fatalf("ledger_compact: %s", errObj.Message)
	}
	secondRoot := mustHashStringValue(t,
		mustLedgerHash(t, "ledger_root_export", LedgerRootExport(intObj(handle))), "snapshot_root")

	if firstRoot == secondRoot {
		t.Fatal("a second compaction produced the same snapshot root")
	}

	// The old proof is still true about the old snapshot, forever.
	old := mustLedgerHash(t, "ledger_verify_proof",
		LedgerVerifyProof(&object.Bytes{Value: firstProof}, stringObj(firstRoot)))
	if !mustHashBoolValue(t, old, "verified") {
		t.Errorf("a proof stopped being true about the snapshot it names: %s",
			mustHashStringValue(t, old, "reason"))
	}

	// And it is not true about the new one, which is why the root has to be
	// retained beside the proof rather than fetched later.
	stale := mustLedgerHash(t, "ledger_verify_proof",
		LedgerVerifyProof(&object.Bytes{Value: firstProof}, stringObj(secondRoot)))
	if mustHashBoolValue(t, stale, "verified") {
		t.Error("a proof from an earlier snapshot verified against a later root")
	}

	// A fresh proof for the same unchanged entity is different bytes.
	fresh := mustLedgerHash(t, "ledger_prove_node", LedgerProveNode(intObj(handle), intObj(id)))
	freshProof := mustLedgerBytes(t, fresh, "proof")
	if bytes.Equal(firstProof, freshProof) {
		t.Error("the proof bytes did not change across a compaction")
	}
	current := mustLedgerHash(t, "ledger_verify_proof",
		LedgerVerifyProof(&object.Bytes{Value: freshProof}, stringObj(secondRoot)))
	if !mustHashBoolValue(t, current, "verified") {
		t.Errorf("a fresh proof did not verify against the current root: %s",
			mustHashStringValue(t, current, "reason"))
	}
}

// --- what a proof carries, and what it must not ----------------------------

// The privacy property a Merkle proof is chosen for: the recipient learns
// about one entity and nothing about any other.
func TestAProofAboutOneEntityCarriesNothingAboutAnother(t *testing.T) {
	handle, _ := openTestLedger(t, "G. Gogia")

	const secret = "informant-name-that-must-not-travel"
	if _, errObj := unwrapPair(t, LedgerAddNode(intObj(handle),
		ledgerProps(map[string]string{"uid": "rec-secret", "witness": secret}))); errObj != nil {
		t.Fatalf("ledger_add_node: %s", errObj.Message)
	}
	subject, proof, _ := proveOneNode(t, handle, map[string]string{"uid": "rec-public"})

	if bytes.Contains(proof, []byte(secret)) {
		t.Fatalf("the proof about node %d carried another entity's property value", subject)
	}
	if bytes.Contains(proof, []byte("rec-secret")) {
		t.Errorf("the proof about node %d carried another entity's property key", subject)
	}
}

// --- describing is not verifying -------------------------------------------

func TestDescribingAProofChecksNothingAndTheFieldNamesSaySo(t *testing.T) {
	handle, _ := openTestLedger(t, "G. Gogia")
	id, proof, root := proveOneNode(t, handle, map[string]string{"uid": "rec-1"})

	described := mustLedgerHash(t, "ledger_proof_describe",
		LedgerProofDescribe(&object.Bytes{Value: proof}))

	for _, pair := range described.Pairs {
		key := pair.Key.(*object.String).Value
		if strings.HasSuffix(key, "_root") && !strings.HasPrefix(key, "stated_") {
			t.Errorf("describe returned an unprefixed root field %q; nothing here was checked", key)
		}
		if key == "verified" || key == "reason" {
			t.Errorf("describe returned %q, which reads as a verdict it did not reach", key)
		}
	}
	if got := mustHashStringValue(t, described, "stated_snapshot_root"); got != root {
		t.Errorf("stated_snapshot_root = %q, want %q", got, root)
	}
	if got := mustHashIntValue(t, described, "node_id"); got != id {
		t.Errorf("node_id = %d, want %d", got, id)
	}

	// A proof whose stated root is a lie still describes cleanly. That is the
	// whole reason the prefix exists.
	lying := append([]byte(nil), proof...)
	lying[len(lying)-1] ^= 0xFF
	if payload, errObj := unwrapPair(t, LedgerProofDescribe(&object.Bytes{Value: lying})); errObj == nil {
		claimed := mustHashStringValue(t, payload.(*object.Hash), "stated_snapshot_root")
		if claimed == root {
			t.Skip("the flipped byte did not land in the stated roots")
		}
		verdict := mustLedgerHash(t, "ledger_verify_proof",
			LedgerVerifyProof(&object.Bytes{Value: lying}, stringObj(claimed)))
		if mustHashBoolValue(t, verdict, "verified") {
			t.Fatal("a proof verified against the root it claimed for itself")
		}
	}
}

// --- the chain --------------------------------------------------------------

func TestAChainIsWhatSeparatesAHistoryFromACollectionOfFiles(t *testing.T) {
	handle, _ := openTestLedger(t, "G. Gogia")

	proveOneNode(t, handle, map[string]string{"uid": "rec-1"})
	first := mustLedgerHash(t, "ledger_root_export", LedgerRootExport(intObj(handle)))

	if _, errObj := unwrapPair(t, LedgerAddNode(intObj(handle), ledgerProps(map[string]string{"uid": "rec-2"}))); errObj != nil {
		t.Fatalf("ledger_add_node: %s", errObj.Message)
	}
	if _, errObj := unwrapPair(t, LedgerCompact(intObj(handle))); errObj != nil {
		t.Fatalf("ledger_compact: %s", errObj.Message)
	}
	second := mustLedgerHash(t, "ledger_root_export", LedgerRootExport(intObj(handle)))

	linked := mustLedgerHash(t, "ledger_verify_chain", LedgerVerifyChain(first, second))
	if !mustHashBoolValue(t, linked, "chained") {
		t.Fatalf("the second snapshot does not name the first: %s",
			mustHashStringValue(t, linked, "reason"))
	}

	// Backwards is not a chain, and neither is a snapshot to itself.
	for name, args := range map[string][2]*object.Hash{
		"backwards": {second, first},
		"to itself": {first, first},
	} {
		t.Run(name, func(t *testing.T) {
			result := mustLedgerHash(t, "ledger_verify_chain", LedgerVerifyChain(args[0], args[1]))
			if mustHashBoolValue(t, result, "chained") {
				t.Fatalf("%s reported as a chain", name)
			}
			if mustHashStringValue(t, result, "reason") == "" {
				t.Error("a false verdict came back with no reason")
			}
		})
	}
}

// A component read as zero would fail the snapshot root's own binding check and
// be reported as a broken chain, when what was broken was the argument.
func TestAChainArgumentMissingAComponentIsRefusedNotAssumedZero(t *testing.T) {
	handle, _ := openTestLedger(t, "G. Gogia")
	proveOneNode(t, handle, map[string]string{"uid": "rec-1"})
	roots := mustLedgerHash(t, "ledger_root_export", LedgerRootExport(intObj(handle)))

	for _, missing := range []string{
		"snapshot_root", "node_root", "edge_root", "index_root",
		"prev_root", "tombstone_root", "body_version",
	} {
		t.Run(missing, func(t *testing.T) {
			trimmed := map[string]object.Object{}
			for _, pair := range roots.Pairs {
				key := pair.Key.(*object.String).Value
				if key != missing {
					trimmed[key] = pair.Value
				}
			}
			partial := makeHashObject(trimmed)
			_, errObj := unwrapPair(t, LedgerVerifyChain(partial, roots))
			if errObj == nil {
				t.Fatalf("a root set with no %s was accepted", missing)
			}
			if !strings.Contains(errObj.Message, missing) {
				t.Errorf("the refusal does not name the missing field: %s", errObj.Message)
			}
			if !strings.Contains(errObj.Message, "ledger_root_export") {
				t.Errorf("the refusal does not say where a complete root set comes from: %s", errObj.Message)
			}
		})
	}
}

// --- the verifier takes whatever it is handed ------------------------------

// ledger_verify_proof is the recipient's builtin, and a recipient is handed
// whatever the other side produced. Redaction proofs have no builtin of their
// own until the redaction half of this phase lands, so one is built through
// graphene directly here rather than leaving the path unexercised.
func TestTheVerifierReachesAVerdictOnAProofKindNothingHereProducesYet(t *testing.T) {
	handle, _ := openTestLedger(t, "G. Gogia")
	id, _, _ := proveOneNode(t, handle, map[string]string{"uid": "rec-1", "case": "IR-1"})

	session, ok := ledgerGet(handle)
	if !ok {
		t.Fatal("the ledger handle did not resolve")
	}
	if _, err := session.store.RedactNodeProperties(store.NodeID(id), disk.RedactionRequest{
		ActorID: session.actorID,
		Reason:  "out of scope for the disclosure",
	}); err != nil {
		t.Fatalf("RedactNodeProperties: %s", err)
	}
	// The redaction is not provable until the next compaction; graphene says
	// so and this family will report it as such when the redaction builtins
	// land. Here it is only the step that makes a tombstone exist.
	if _, errObj := unwrapPair(t, LedgerCompact(intObj(handle))); errObj != nil {
		t.Fatalf("ledger_compact: %s", errObj.Message)
	}
	root := mustHashStringValue(t,
		mustLedgerHash(t, "ledger_root_export", LedgerRootExport(intObj(handle))), "snapshot_root")

	blob, err := session.store.ExportPropertyRedactionProof(store.NodeID(id))
	if err != nil {
		t.Fatalf("ExportPropertyRedactionProof: %s", err)
	}

	described := mustLedgerHash(t, "ledger_proof_describe", LedgerProofDescribe(&object.Bytes{Value: blob}))
	if got := mustHashStringValue(t, described, "kind"); got != "property-redaction" {
		t.Errorf("kind = %q, want property-redaction", got)
	}

	result := mustLedgerHash(t, "ledger_verify_proof",
		LedgerVerifyProof(&object.Bytes{Value: blob}, stringObj(root)))
	if !mustHashBoolValue(t, result, "verified") {
		t.Fatalf("a property-redaction proof did not verify: %s",
			mustHashStringValue(t, result, "reason"))
	}
	if got := mustHashIntValue(t, result, "node_id"); got != id {
		t.Errorf("node_id = %d, want %d", got, id)
	}
	// Content-free by construction: the destroyed values must not travel.
	if bytes.Contains(blob, []byte("IR-1")) {
		t.Error("a redaction proof carried the value it says was destroyed")
	}
}

// --- the family's own contracts --------------------------------------------

func TestEveryProofBuiltinRefusesAHandleThatIsNotOne(t *testing.T) {
	for name, fn := range map[string]func(...object.Object) object.Object{
		BuiltinNameLedgerProveNode:  func(a ...object.Object) object.Object { return LedgerProveNode(a[0], intObj(1)) },
		BuiltinNameLedgerRootExport: LedgerRootExport,
	} {
		t.Run(name, func(t *testing.T) {
			_, errObj := unwrapPair(t, fn(intObj(987654)))
			if errObj == nil {
				t.Fatal("accepted a handle that is not a ledger")
			}
			if !strings.Contains(errObj.Message, "ledger_open") {
				t.Errorf("the refusal does not name the family the handle comes from: %s", errObj.Message)
			}
			if _, errObj := unwrapPair(t, fn(stringObj("not a handle"))); errObj == nil {
				t.Fatal("accepted a STRING as a handle")
			}
		})
	}
}

func TestEveryProofBuiltinChecksItsArity(t *testing.T) {
	handle, _ := openTestLedger(t, "G. Gogia")
	_, proof, root := proveOneNode(t, handle, map[string]string{"uid": "rec-1"})
	roots := mustLedgerHash(t, "ledger_root_export", LedgerRootExport(intObj(handle)))
	blob := &object.Bytes{Value: proof}

	cases := map[string]struct {
		fn   func(...object.Object) object.Object
		ok   []object.Object
		want int
	}{
		BuiltinNameLedgerProveNode:     {LedgerProveNode, []object.Object{intObj(handle), intObj(1)}, 2},
		BuiltinNameLedgerVerifyProof:   {LedgerVerifyProof, []object.Object{blob, stringObj(root)}, 2},
		BuiltinNameLedgerProofDescribe: {LedgerProofDescribe, []object.Object{blob}, 1},
		BuiltinNameLedgerRootExport:    {LedgerRootExport, []object.Object{intObj(handle)}, 1},
		BuiltinNameLedgerVerifyChain:   {LedgerVerifyChain, []object.Object{roots, roots}, 2},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if _, errObj := unwrapPair(t, tc.fn()); errObj == nil {
				t.Error("accepted no arguments")
			}
			tooMany := append(append([]object.Object{}, tc.ok...), stringObj("extra"))
			if _, errObj := unwrapPair(t, tc.fn(tooMany...)); errObj == nil {
				t.Error("accepted one argument too many")
			}
			if len(tc.ok) > 1 {
				if _, errObj := unwrapPair(t, tc.fn(tc.ok[:len(tc.ok)-1]...)); errObj == nil {
					t.Error("accepted one argument too few")
				}
			}
			if declared := builtinDocs[name].params; len(declared) != tc.want {
				t.Errorf("metadata declares %d parameters, the implementation takes %d", len(declared), tc.want)
			}
		})
	}
}

func TestEveryProofBuiltinReturnsTheDeclaredFields(t *testing.T) {
	handle, _ := openTestLedger(t, "G. Gogia")
	id, proof, root := proveOneNode(t, handle, map[string]string{"uid": "rec-1"})
	blob := &object.Bytes{Value: proof}
	roots := mustLedgerHash(t, "ledger_root_export", LedgerRootExport(intObj(handle)))

	for name, result := range map[string]object.Object{
		BuiltinNameLedgerProveNode:     LedgerProveNode(intObj(handle), intObj(id)),
		BuiltinNameLedgerVerifyProof:   LedgerVerifyProof(blob, stringObj(root)),
		BuiltinNameLedgerProofDescribe: LedgerProofDescribe(blob),
		BuiltinNameLedgerRootExport:    LedgerRootExport(intObj(handle)),
		BuiltinNameLedgerVerifyChain:   LedgerVerifyChain(roots, roots),
	} {
		t.Run(name, func(t *testing.T) {
			payload, errObj := unwrapPair(t, result)
			if errObj != nil {
				t.Fatalf("%s: %s", name, errObj.Message)
			}
			assertLedgerDeclaredFields(t, name, payload)
		})
	}
}

// A proof arrives from a file, and which builtin read it decides whether it is
// BYTES or STRING. Refusing one of them would make the verifier's first act a
// complaint about how its input was loaded.
func TestAProofIsAcceptedAsBytesOrAsText(t *testing.T) {
	handle, _ := openTestLedger(t, "G. Gogia")
	_, proof, root := proveOneNode(t, handle, map[string]string{"uid": "rec-1"})

	asBytes := mustLedgerHash(t, "ledger_verify_proof",
		LedgerVerifyProof(&object.Bytes{Value: proof}, stringObj(root)))
	asText := mustLedgerHash(t, "ledger_verify_proof",
		LedgerVerifyProof(stringObj(string(proof)), stringObj(root)))

	if !mustHashBoolValue(t, asBytes, "verified") || !mustHashBoolValue(t, asText, "verified") {
		t.Fatal("the same proof verified as one type and not the other")
	}
}
