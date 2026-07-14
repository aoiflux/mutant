package evaluator

import (
	"testing"

	"mutant/builtin"
)

func TestEvaluatorBuiltinsStayInSyncWithRegistry(t *testing.T) {
	if len(builtins) != len(builtin.Builtins) {
		t.Fatalf("builtin map size mismatch: evaluator=%d registry=%d", len(builtins), len(builtin.Builtins))
	}

	for _, entry := range builtin.Builtins {
		if entry.Name == "" {
			t.Fatalf("builtin registry has empty name")
		}
		fn, ok := builtins[entry.Name]
		if !ok {
			t.Fatalf("evaluator builtins missing %q", entry.Name)
		}
		if fn == nil {
			t.Fatalf("evaluator builtin %q is nil", entry.Name)
		}
		if fn != entry.Builtin {
			t.Fatalf("evaluator builtin %q does not match registry pointer", entry.Name)
		}
	}
}
