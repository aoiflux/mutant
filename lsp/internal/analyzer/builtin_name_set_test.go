package analyzer

import (
	"runtime"
	"testing"

	mast "mutant/ast"
	"mutant/builtin"
)

// TestTheRegistryIsReadNotRebuilt holds the rules that ask whether a callee is a
// builtin in this build to the set built once, when the package starts
// (builtinNameSet). forEachBuiltinCall and uncheckedError each built it again on
// every call -- a map of every builtin's name, about 20 KB -- and eleven rules
// ask per analysis, so every keystroke paid for eleven copies of a set that
// never changes (M26-LSP-026).
//
// Measured over one statement making one builtin call, so that a set built per
// call is caught as well as one built per walk, and which gives the walk next to
// nothing to allocate. A set of every name holds a 16-byte string header for
// each, so it cannot be built under half of that per name, which is the bound.
func TestTheRegistryIsReadNotRebuilt(t *testing.T) {
	snapshot := New().Analyze("let x = len(\"evidence\");\n")
	if snapshot == nil || snapshot.Program == nil {
		t.Fatal("the one-statement program did not analyse")
	}
	calls := 0
	forEachBuiltinCall(snapshot.Program.Statements, nil,
		func(string, mast.Node, *mast.CallExpression, map[string]mast.Expression) { calls++ })
	if calls != 1 {
		t.Fatalf("the walk visited %d builtin calls, want the one the program makes", calls)
	}
	bound := uint64(len(builtin.Builtins)) * 8
	for _, tc := range []struct {
		name string
		run  func()
	}{
		{"forEachBuiltinCall", func() {
			forEachBuiltinCall(snapshot.Program.Statements, nil,
				func(string, mast.Node, *mast.CallExpression, map[string]mast.Expression) {})
		}},
		{"uncheckedError", func() { lintUncheckedErrors(snapshot, DefaultLintConfig()) }},
	} {
		if got := bytesPerRun(tc.run); got >= bound {
			t.Errorf("%s allocates %d bytes a run over one statement, at least %d: it builds a set of every "+
				"builtin's name again instead of reading builtinNameSet", tc.name, got, bound)
		}
	}
}

// bytesPerRun is what one run of f allocates on the heap, averaged over a few,
// after one run that builds whatever is built on first use.
func bytesPerRun(f func()) uint64 {
	f()
	const runs = 20
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	for range runs {
		f()
	}
	runtime.ReadMemStats(&after)
	return (after.TotalAlloc - before.TotalAlloc) / runs
}
