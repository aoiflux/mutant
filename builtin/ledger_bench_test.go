package builtin

import (
	"fmt"
	"path/filepath"
	"testing"

	"mutant/object"
)

// The ledger reads that run under the shared walk budget, the unindexed-key
// check and the reversed-hop marking, measured through the marshalling layer a
// script pays for.
//
// The fixture is a chain thirteen entities long -- provenance at depth twelve,
// the depth db_bfs is measured at -- beside two hundred entities spread over
// four roles for the query to choose among. Every write is a signed commit,
// so it is built once per benchmark, outside the timed loop. Read B/op and
// allocs/op; see db_bench_test.go on ns/op.

const (
	benchLedgerChain  = 13
	benchLedgerSpread = 200
)

// benchPayload unwraps a builtin's (value, err) pair, failing the benchmark on
// an error.
func benchPayload(b *testing.B, name string, result object.Object) object.Object {
	b.Helper()
	pair, ok := result.(*object.MultiValue)
	if !ok || len(pair.Values) != 2 {
		b.Fatalf("%s did not return a pair: %T", name, result)
	}
	if errObj, failed := pair.Values[1].(*object.Error); failed {
		b.Fatalf("%s: %s", name, errObj.Message)
	}
	return pair.Values[0]
}

// benchHashInt reads one integer field of a hash payload.
func benchHashInt(b *testing.B, name string, payload object.Object, key string) int64 {
	b.Helper()
	hash, ok := payload.(*object.Hash)
	if !ok {
		b.Fatalf("%s payload is %T, not a hash", name, payload)
	}
	value, found := hashValueByStringKey(hash, key)
	if !found {
		b.Fatalf("%s payload has no %q", name, key)
	}
	number, ok := value.(*object.Integer)
	if !ok {
		b.Fatalf("%s payload %q is %T", name, key, value)
	}
	return number.Value
}

// benchLedger opens a ledger holding the fixture and returns its handle and the
// chain's ids, first to last.
func benchLedger(b *testing.B) (int64, []int64) {
	b.Helper()
	dir := filepath.Join(b.TempDir(), "ledger")
	opened := benchPayload(b, BuiltinNameLedgerOpen, LedgerOpen(stringObj(dir), stringObj("bench")))
	handle := benchHashInt(b, BuiltinNameLedgerOpen, opened, "handle")
	b.Cleanup(func() { LedgerClose(intObj(handle)) })

	add := func(props map[string]string) int64 {
		written := benchPayload(b, BuiltinNameLedgerAddNode, LedgerAddNode(intObj(handle), ledgerProps(props)))
		return benchHashInt(b, BuiltinNameLedgerAddNode, written, "id")
	}
	chain := make([]int64, 0, benchLedgerChain)
	for i := 0; i < benchLedgerChain; i++ {
		chain = append(chain, add(map[string]string{"uid": fmt.Sprintf("chain-%02d", i), "role": "chain"}))
	}
	for i := 1; i < len(chain); i++ {
		benchPayload(b, BuiltinNameLedgerAddEdge, LedgerAddEdge(intObj(handle), intObj(chain[i-1]), intObj(chain[i]),
			ledgerProps(map[string]string{"kind": "DERIVED"})))
	}
	roles := []string{"image", "file", "artefact", "note"}
	for i := 0; i < benchLedgerSpread; i++ {
		add(map[string]string{"uid": fmt.Sprintf("spread-%03d", i), "role": roles[i%len(roles)]})
	}
	return handle, chain
}

func benchLedgerRead(b *testing.B, name string, call func() object.Object) {
	b.Helper()
	benchPayload(b, name, call())
	b.ReportAllocs()
	for b.Loop() {
		call()
	}
}

func BenchmarkLedgerQueryNodes(b *testing.B) {
	handle, _ := benchLedger(b)
	query := ledgerEqualsQuery("role", "file")
	benchLedgerRead(b, BuiltinNameLedgerQueryNodes, func() object.Object {
		return LedgerQueryNodes(intObj(handle), query)
	})
}

func BenchmarkLedgerProvenance(b *testing.B) {
	handle, chain := benchLedger(b)
	last, depth := intObj(chain[len(chain)-1]), intObj(benchLedgerChain-1)
	benchLedgerRead(b, BuiltinNameLedgerProvenance, func() object.Object {
		return LedgerProvenance(intObj(handle), last, depth)
	})
}

func BenchmarkLedgerSubgraph(b *testing.B) {
	handle, chain := benchLedger(b)
	ids := make([]object.Object, 0, len(chain))
	for _, id := range chain {
		ids = append(ids, intObj(id))
	}
	scope := &object.Array{Elements: ids}
	benchLedgerRead(b, BuiltinNameLedgerSubgraph, func() object.Object {
		return LedgerSubgraph(intObj(handle), scope)
	})
}

// BenchmarkLedgerPath runs the chain both ways, because the way back is the
// one whose every hop is marked as reversed.
func BenchmarkLedgerPath(b *testing.B) {
	handle, chain := benchLedger(b)
	first, last := intObj(chain[0]), intObj(chain[len(chain)-1])
	hops := stringObj("hops")
	b.Run("forward", func(b *testing.B) {
		benchLedgerRead(b, BuiltinNameLedgerPath, func() object.Object {
			return LedgerPath(intObj(handle), first, last, hops)
		})
	})
	b.Run("backward", func(b *testing.B) {
		benchLedgerRead(b, BuiltinNameLedgerPath, func() object.Object {
			return LedgerPath(intObj(handle), last, first, hops)
		})
	})
}
