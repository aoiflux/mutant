package analyzer

import (
	"strings"
	"testing"
)

func undefinedNames(t *testing.T, src string) map[string]bool {
	t.Helper()

	names := make(map[string]bool)
	for _, diagnostic := range Diagnostics(New().Analyze(src), DefaultLintConfig()) {
		const prefix = "undefined identifier `"
		if !strings.HasPrefix(diagnostic.Message, prefix) {
			continue
		}
		names[strings.TrimSuffix(strings.TrimPrefix(diagnostic.Message, prefix), "`")] = true
	}
	return names
}

// TestImportNamespaceIsDefined pins that an import binds a usable name.
//
// Without this the rule fired at error severity on every namespace reference,
// and `mutant lint` exits non-zero on any error-severity diagnostic regardless
// of --strict -- so a single working import made the linter unusable on the
// file that used it.
func TestImportNamespaceIsDefined(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{"alias", "import util \"pkg/util.mut\";\nlet x = util.greet(\"a\");\nx;\n"},
		{"derived from the file name", "import \"pkg/util.mut\";\nlet x = util.greet(\"a\");\nx;\n"},
		{"derived from a bare file name", "import \"util.mut\";\nlet x = util.greet(\"a\");\nx;\n"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if undefinedNames(t, tt.src)["util"] {
				t.Fatal("an imported namespace must not be reported as undefined")
			}
		})
	}
}

// TestImportNamespaceDoesNotSilenceOtherNames guards the other direction: the
// fix must whitelist exactly the names the imports bind, not disable the rule
// wherever a file happens to contain an import.
func TestImportNamespaceDoesNotSilenceOtherNames(t *testing.T) {
	src := "import util \"pkg/util.mut\";\nlet x = nope.f();\nlet y = util.f();\nx;\ny;\n"

	undefined := undefinedNames(t, src)
	if !undefined["nope"] {
		t.Fatal("expected `nope` to still be reported as undefined")
	}
	if undefined["util"] {
		t.Fatal("did not expect the imported namespace to be reported")
	}
}
