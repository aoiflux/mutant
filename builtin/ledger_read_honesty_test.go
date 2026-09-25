package builtin

import (
	"testing"

	"mutant/object"
)

func ledgerEqualsQuery(key, value string) object.Object {
	return makeHashObject(map[string]object.Object{
		"filters": &object.Array{Elements: []object.Object{
			makeHashObject(map[string]object.Object{
				"key": stringObj(key), "op": stringObj("eq"), "value": stringObj(value),
			}),
		}},
	})
}

func ledgerStrings(t *testing.T, h *object.Hash, key string) []string {
	t.Helper()
	array, ok := mustHashValue(t, h, key).(*object.Array)
	if !ok {
		t.Fatalf("%s is not an array", key)
	}
	out := make([]string, 0, len(array.Elements))
	for _, element := range array.Elements {
		out = append(out, element.(*object.String).Value)
	}
	return out
}

func ledgerInts(t *testing.T, h *object.Hash, key string) []int64 {
	t.Helper()
	array, ok := mustHashValue(t, h, key).(*object.Array)
	if !ok {
		t.Fatalf("%s is not an array", key)
	}
	out := make([]int64, 0, len(array.Elements))
	for _, element := range array.Elements {
		out = append(out, element.(*object.Integer).Value)
	}
	return out
}

// M26-CUS-002, the first read. A filter on a key the index holds nothing under
// matched nothing and said nothing, so "no such record" and "this key cannot
// be asked about" were one answer. The disclosure schema keeps most of its
// properties in the node's blob and indexes only the keys it looks records up
// by, so a query for a disclosure's recipient by name was always empty. The
// result now names every filter key the index has never held.
func TestAQueryOnAKeyTheIndexNeverHeldSaysSo(t *testing.T) {
	f := newDiscloseFixture(t)
	f.issue(t, "counsel", "Counsel")

	byName := mustLedgerHash(t, BuiltinNameLedgerQueryNodes,
		LedgerQueryNodes(intObj(f.ledger), ledgerEqualsQuery("disclosure.recipient", "Counsel")))
	if mustHashIntValue(t, byName, "count") != 0 {
		t.Fatal("the recipient's name is indexed after all; this test's premise is gone")
	}
	if !mustHashBoolValue(t, byName, "index_keys_known") {
		t.Fatal("the disk ledger could not say which keys its index holds")
	}
	if got := ledgerStrings(t, byName, "unindexed_keys"); len(got) != 1 || got[0] != "disclosure.recipient" {
		t.Fatalf("an empty answer on a key the index never held names unindexed_keys %v", got)
	}

	byFingerprint := mustLedgerHash(t, BuiltinNameLedgerQueryNodes,
		LedgerQueryNodes(intObj(f.ledger), ledgerEqualsQuery("disclosure.recipient_fp", disclosureRecipientFingerprint("Counsel"))))
	if mustHashIntValue(t, byFingerprint, "count") != 1 {
		t.Fatalf("the indexed fingerprint found %d disclosures, want 1", mustHashIntValue(t, byFingerprint, "count"))
	}
	if got := ledgerStrings(t, byFingerprint, "unindexed_keys"); len(got) != 0 {
		t.Fatalf("an indexed key is reported unindexed: %v", got)
	}

	// A misspelt key on a script's own ledger is the same answer for the same
	// reason, and a key that is indexed but has no match is not.
	handle, _ := scoredTestLedger(t)
	typo := mustLedgerHash(t, BuiltinNameLedgerQueryNodes, LedgerQueryNodes(intObj(handle), ledgerEqualsQuery("scroe", "9")))
	if got := ledgerStrings(t, typo, "unindexed_keys"); len(got) != 1 || got[0] != "scroe" {
		t.Fatalf("a misspelt key names unindexed_keys %v", got)
	}
	absent := mustLedgerHash(t, BuiltinNameLedgerQueryNodes, LedgerQueryNodes(intObj(handle), ledgerEqualsQuery("score", "404")))
	if got := ledgerStrings(t, absent, "unindexed_keys"); len(got) != 0 {
		t.Fatalf("an indexed key with no matching value is reported unindexed: %v", got)
	}
}

// M26-CUS-002, the second read. graphene's weighted shortest path walks edges
// both ways, so ledger_path found a path from a file back to the image that
// contains it and reported it like any other. The edges it returned showed
// their own direction, but nothing said a hop had run against one. The result
// now lists those hops and says whether the path is directed.
func TestAPathThatRunsAgainstAnEdgeSaysWhichHops(t *testing.T) {
	handle, image, _, artefact, _, _ := readableTestLedger(t)

	forward := mustLedgerHash(t, BuiltinNameLedgerPath,
		LedgerPath(intObj(handle), intObj(image), intObj(artefact), stringObj("hops")))
	if !mustHashBoolValue(t, forward, "directed") || len(ledgerInts(t, forward, "reversed_hops")) != 0 {
		t.Fatalf("a path along its edges is not reported directed: %s", forward.Inspect())
	}

	backward := mustLedgerHash(t, BuiltinNameLedgerPath,
		LedgerPath(intObj(handle), intObj(artefact), intObj(image), stringObj("hops")))
	if !mustHashBoolValue(t, backward, "found") || mustHashIntValue(t, backward, "hops") != 2 {
		t.Fatalf("no two-hop path from the artefact back to the image: %s", backward.Inspect())
	}
	if mustHashBoolValue(t, backward, "directed") {
		t.Fatal("a path that ran against both of its edges is reported directed")
	}
	if got := ledgerInts(t, backward, "reversed_hops"); len(got) != 2 || got[0] != 0 || got[1] != 1 {
		t.Fatalf("reversed_hops is %v, want [0 1]", got)
	}
}
