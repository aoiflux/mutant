package server

import (
	"strings"
	"testing"

	"mutant/lsp/internal/analyzer"

	lsp "github.com/tliron/glsp/protocol_3_16"
)

// An import binds a name in one file, so whether anything reads it is a
// question that file answers. These drive the real server because the rule is
// only interesting where imports resolve -- an analyzer with no workspace has
// no imports to be unused.

func lintDiagnostics(t *testing.T, root, openRel, containing string) []lsp.Diagnostic {
	t.Helper()
	s, uri := serverOver(t, root, openRel)
	snapshot, ok := s.snapshot(uri)
	if !ok || snapshot == nil {
		t.Fatal("no snapshot for the opened document")
	}

	found := make([]lsp.Diagnostic, 0, 2)
	for _, d := range analyzer.Diagnostics(snapshot, analyzer.DefaultLintConfig()) {
		if strings.Contains(d.Message, containing) {
			found = append(found, d)
		}
	}
	return found
}

func lintMessages(t *testing.T, root, openRel, containing string) []string {
	t.Helper()
	said := make([]string, 0, 2)
	for _, d := range lintDiagnostics(t, root, openRel, containing) {
		said = append(said, d.Message)
	}
	return said
}

func TestAnImportNothingReadsIsReported(t *testing.T) {
	root := writeModules(t, map[string]string{
		"main.mut": "import util \"lib/util.mut\";\n" +
			"putln(\"hello\");\n",
		"lib/util.mut": "let helper = fn() { return 1; };\n",
	})

	said := lintMessages(t, root, "main.mut", "unused import")
	if len(said) != 1 {
		t.Fatalf("unused import diagnostics = %v, want exactly one", said)
	}
	// The wording has to carry the reason deleting the line is not automatic,
	// because there is no `import _` form to say the module was wanted for
	// what it does rather than for what it declares.
	if !strings.Contains(said[0], "still run") {
		t.Fatalf("the message does not say the module still runs: %q", said[0])
	}

	// And the squiggle covers the statement, not the alias. The alias is a word
	// in the middle of the line when it is written at all, so underlining it
	// points at the half of the line that is not the finding.
	const statement = `import util "lib/util.mut";`
	rng := lintDiagnostics(t, root, "main.mut", "unused import")[0].Range
	if rng.Start.Line != 0 || rng.End.Line != 0 {
		t.Fatalf("the diagnostic spans lines %d..%d, want the import's own line",
			rng.Start.Line, rng.End.Line)
	}
	if rng.Start.Character != 0 || int(rng.End.Character) < len(statement) {
		t.Fatalf("the diagnostic covers characters %d..%d, want 0..%d -- the whole "+
			"statement, not the alias", rng.Start.Character, rng.End.Character, len(statement))
	}
}

func TestAnImportSomethingReadsIsNotReported(t *testing.T) {
	for _, c := range []struct{ name, main string }{
		{
			name: "a member is called",
			main: "import util \"lib/util.mut\";\n" +
				"util.helper();\n",
		},
		{
			// The namespace as a value rather than as a receiver. It is still
			// a read of the binding, and a rule that only looked at field
			// expressions would miss it.
			name: "the namespace is passed along",
			main: "import util \"lib/util.mut\";\n" +
				"let take = fn(n) { return n; };\n" +
				"take(util);\n",
		},
		{
			// Inside a function body, which is a different scope from the
			// declaration -- and the alias is declared at the top level.
			name: "the namespace is read inside a function",
			main: "import util \"lib/util.mut\";\n" +
				"let go = fn() { return util.helper(); };\n" +
				"go();\n",
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			root := writeModules(t, map[string]string{
				"main.mut":     c.main,
				"lib/util.mut": "let helper = fn() { return 1; };\n",
			})
			if said := lintMessages(t, root, "main.mut", "unused import"); len(said) != 0 {
				t.Fatalf("an import that is read was reported: %v\n\n%s", said, c.main)
			}
		})
	}
}

// A derived alias is never written down -- `import "lib/util.mut";` binds
// `util` without the word appearing -- so the diagnostic has to be anchored on
// the statement. Without that it would have nowhere to go and the rule would
// silently skip exactly the imports whose alias is easiest to forget.
func TestADerivedAliasIsStillReported(t *testing.T) {
	root := writeModules(t, map[string]string{
		"main.mut":     "import \"lib/util.mut\";\nputln(\"hello\");\n",
		"lib/util.mut": "let helper = fn() { return 1; };\n",
	})

	said := lintMessages(t, root, "main.mut", "unused import")
	if len(said) != 1 || !strings.Contains(said[0], "`util`") {
		t.Fatalf("unused import diagnostics = %v, want one naming util", said)
	}
}

// The certain half of "unused export". A top-level `_name` cannot be reached
// from another file -- the compiler refuses `ns._name` -- so a module file
// keeps its exemption for the names it exports and loses it for the ones it
// cannot.
func TestAPrivateTopLevelNameIsNotExemptFromTheUnusedRule(t *testing.T) {
	root := writeModules(t, map[string]string{
		"main.mut": "import util \"lib/util.mut\";\n" +
			"util.helper();\n",
		"lib/util.mut": "let _unreachable = fn() { return 2; };\n" +
			"let helper = fn() { return 1; };\n",
	})

	said := lintMessages(t, root, "lib/util.mut", "unused declaration")
	if len(said) != 1 || !strings.Contains(said[0], "_unreachable") {
		t.Fatalf("unused declarations in a module file = %v, want one naming "+
			"_unreachable; `helper` is an export and must stay exempt", said)
	}
}

func TestAPrivateTopLevelNameItsOwnFileUsesIsNotReported(t *testing.T) {
	root := writeModules(t, map[string]string{
		"main.mut": "import util \"lib/util.mut\";\n" +
			"util.helper();\n",
		"lib/util.mut": "let _total = 2;\n" +
			"let helper = fn() { return _total; };\n",
	})

	if said := lintMessages(t, root, "lib/util.mut", "unused declaration"); len(said) != 0 {
		t.Fatalf("a private name its own module uses was reported: %v", said)
	}
}
