package builtin

import (
	"sort"
	"testing"
)

// TestAllBuiltinsHavePerFunctionDocs enforces the "every builtin is documented"
// principle: every registered builtin must have a builtinDocs entry (signature +
// summary), not merely a family-prefix blurb.
func TestAllBuiltinsHavePerFunctionDocs(t *testing.T) {
	var missing []string
	for _, def := range Builtins {
		if def.Name == "" {
			continue
		}
		if _, ok := builtinDocs[def.Name]; !ok {
			missing = append(missing, def.Name)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		t.Fatalf("%d registered builtins lack a per-function metadata doc:\n  %v", len(missing), missing)
	}
}
