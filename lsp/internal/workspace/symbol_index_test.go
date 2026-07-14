package workspace

import (
	"testing"

	mast "mutant/ast"
	"mutant/lsp/internal/analyzer"

	lsp "github.com/tliron/glsp/protocol_3_16"
)

func TestSymbolIndexUniqueTopLevelDefinition(t *testing.T) {
	idx := NewSymbolIndex()
	idx.Update("file:///defs.mut", analyzedSnapshot(t, "let shared = 1;\n"))
	idx.Update("file:///usage.mut", analyzedSnapshot(t, "shared;\n"))

	location, ok := idx.UniqueTopLevelDefinition("shared", "file:///usage.mut")
	if !ok || location == nil {
		t.Fatal("unique top-level definition not found")
	}
	if location.URI != "file:///defs.mut" {
		t.Fatalf("definition URI = %q, want file:///defs.mut", location.URI)
	}
	if location.Range.Start.Line != 0 || location.Range.Start.Character != 4 {
		t.Fatalf("definition start = %+v, want line 0 char 4", location.Range.Start)
	}
}

func TestSymbolIndexUniqueTopLevelDefinitionRejectsAmbiguousMatches(t *testing.T) {
	idx := NewSymbolIndex()
	idx.Update("file:///defs-a.mut", analyzedSnapshot(t, "let shared = 1;\n"))
	idx.Update("file:///defs-b.mut", analyzedSnapshot(t, "let shared = 2;\n"))

	if location, ok := idx.UniqueTopLevelDefinition("shared", "file:///usage.mut"); ok || location != nil {
		t.Fatalf("definition = %#v, ok=%t, want ambiguous miss", location, ok)
	}
}

func TestSymbolIndexReferenceLocationsIncludeDeclarationOption(t *testing.T) {
	idx := NewSymbolIndex()
	idx.Update("file:///defs.mut", analyzedSnapshot(t, "let shared = 1;\n"))
	idx.Update("file:///usage.mut", analyzedSnapshot(t,
		"shared;\n"+
			"let own = 1;\n"+
			"own;\n"+
			"shared;\n"))

	decl, ok := idx.UniqueTopLevelDefinition("shared", "file:///usage.mut")
	if !ok || decl == nil {
		t.Fatal("missing declaration for shared")
	}

	withDecl := idx.ReferenceLocations("shared", decl, true)
	if len(withDecl) != 3 {
		t.Fatalf("reference count with declaration = %d, want 3", len(withDecl))
	}
	assertLocationURIStart(t, withDecl, "file:///defs.mut", 0, 4)
	assertLocationURIStart(t, withDecl, "file:///usage.mut", 0, 0)
	assertLocationURIStart(t, withDecl, "file:///usage.mut", 3, 0)

	withoutDecl := idx.ReferenceLocations("shared", decl, false)
	if len(withoutDecl) != 2 {
		t.Fatalf("reference count without declaration = %d, want 2", len(withoutDecl))
	}
	assertLocationURIStart(t, withoutDecl, "file:///usage.mut", 0, 0)
	assertLocationURIStart(t, withoutDecl, "file:///usage.mut", 3, 0)
}

func TestSymbolIndexDeleteRemovesDocumentEntries(t *testing.T) {
	idx := NewSymbolIndex()
	idx.Update("file:///defs.mut", analyzedSnapshot(t, "let shared = 1;\n"))
	idx.Delete("file:///defs.mut")

	if location, ok := idx.UniqueTopLevelDefinition("shared", "file:///usage.mut"); ok || location != nil {
		t.Fatalf("definition = %#v, ok=%t, want miss after delete", location, ok)
	}
}

func TestSymbolIndexUpdateReplacesTopLevelSymbolsForSameDocument(t *testing.T) {
	idx := NewSymbolIndex()
	idx.Update("file:///defs.mut", analyzedSnapshot(t, "let shared = 1;\n"))

	if location, ok := idx.UniqueTopLevelDefinition("shared", "file:///usage.mut"); !ok || location == nil {
		t.Fatal("expected initial shared definition")
	}

	idx.Update("file:///defs.mut", analyzedSnapshot(t, "let renamed = 1;\n"))

	if location, ok := idx.UniqueTopLevelDefinition("shared", "file:///usage.mut"); ok || location != nil {
		t.Fatalf("definition = %#v, ok=%t, want shared to be removed after update", location, ok)
	}

	renamedLocation, ok := idx.UniqueTopLevelDefinition("renamed", "file:///usage.mut")
	if !ok || renamedLocation == nil {
		t.Fatal("expected renamed definition after update")
	}
	if renamedLocation.URI != "file:///defs.mut" {
		t.Fatalf("renamed definition URI = %q, want file:///defs.mut", renamedLocation.URI)
	}
}

func TestSymbolIndexUpdateReplacesUnresolvedReferencesForSameDocument(t *testing.T) {
	idx := NewSymbolIndex()
	idx.Update("file:///defs.mut", analyzedSnapshot(t, "let shared = 1;\n"))
	decl, ok := idx.UniqueTopLevelDefinition("shared", "file:///usage.mut")
	if !ok || decl == nil {
		t.Fatal("missing declaration for shared")
	}

	idx.Update("file:///usage.mut", analyzedSnapshot(t, "shared;\nshared;\n"))
	locations := idx.ReferenceLocations("shared", decl, false)
	if len(locations) != 2 {
		t.Fatalf("initial reference count = %d, want 2", len(locations))
	}
	assertLocationURIStart(t, locations, "file:///usage.mut", 0, 0)
	assertLocationURIStart(t, locations, "file:///usage.mut", 1, 0)

	idx.Update("file:///usage.mut", analyzedSnapshot(t, "shared;\n"))
	locations = idx.ReferenceLocations("shared", decl, false)
	if len(locations) != 1 {
		t.Fatalf("updated reference count = %d, want 1", len(locations))
	}
	assertLocationURIStart(t, locations, "file:///usage.mut", 0, 0)
}

func TestSymbolIndexUpdateHandlesTypedNilStatement(t *testing.T) {
	idx := NewSymbolIndex()
	var typedNilInit *mast.ExpressionStatement

	snapshot := &analyzer.Snapshot{
		Program: &mast.Program{
			Statements: []mast.Statement{
				&mast.ForStatement{Init: typedNilInit},
			},
			NodePositions: map[mast.Node]mast.Range{},
		},
	}

	idx.Update("file:///typed-nil-stmt.mut", snapshot)
}

func TestSymbolIndexUpdateHandlesTypedNilExpression(t *testing.T) {
	idx := NewSymbolIndex()
	var typedNilCondition *mast.Identifier

	snapshot := &analyzer.Snapshot{
		Program: &mast.Program{
			Statements: []mast.Statement{
				&mast.ExpressionStatement{Expression: &mast.IfExpression{Condition: typedNilCondition}},
			},
			NodePositions: map[mast.Node]mast.Range{},
		},
	}

	idx.Update("file:///typed-nil-expr.mut", snapshot)
}

func TestSymbolIndexWorkspaceSymbolsQueryAndLimit(t *testing.T) {
	idx := NewSymbolIndex()
	idx.Update("file:///defs-a.mut", analyzedSnapshot(t,
		"let alpha = 1;\n"+
			"let beta = 2;\n"+
			"struct Basket { id; }\n"))
	idx.Update("file:///defs-b.mut", analyzedSnapshot(t,
		"enum Better { One, Two }\n"+
			"let gamma = 3;\n"))

	all := idx.WorkspaceSymbols("", 100)
	if len(all) < 5 {
		t.Fatalf("workspace symbol count = %d, want at least 5", len(all))
	}

	filtered := idx.WorkspaceSymbols("be", 100)
	if len(filtered) != 2 {
		t.Fatalf("filtered symbol count = %d, want 2", len(filtered))
	}
	assertSymbolName(t, filtered, "beta")
	assertSymbolName(t, filtered, "Better")

	limited := idx.WorkspaceSymbols("", 2)
	if len(limited) != 2 {
		t.Fatalf("limited symbol count = %d, want 2", len(limited))
	}
}

func analyzedSnapshot(t *testing.T, src string) *analyzer.Snapshot {
	t.Helper()
	return analyzer.New().Analyze(src)
}

func assertLocationURIStart(t *testing.T, locations []lsp.Location, wantURI lsp.DocumentUri, wantLine, wantCharacter uint32) {
	t.Helper()
	for _, location := range locations {
		if location.URI == wantURI && location.Range.Start.Line == wantLine && location.Range.Start.Character == wantCharacter {
			return
		}
	}
	t.Fatalf("location uri=%q line=%d char=%d not found", wantURI, wantLine, wantCharacter)
}

func assertSymbolName(t *testing.T, symbols []lsp.SymbolInformation, wantName string) {
	t.Helper()
	for _, symbol := range symbols {
		if symbol.Name == wantName {
			return
		}
	}
	t.Fatalf("symbol name %q not found", wantName)
}
