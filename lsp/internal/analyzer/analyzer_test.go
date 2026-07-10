package analyzer

import (
	mast "mutant/ast"
	"mutant/builtin"
	"strings"
	"testing"
)

func TestSemanticTokensDataHandlesTypedNilStatements(t *testing.T) {
	var typedNilInit *mast.ExpressionStatement

	s := &Snapshot{
		Program: &mast.Program{
			Statements: []mast.Statement{
				&mast.ForStatement{Init: typedNilInit},
			},
			NodePositions: map[mast.Node]mast.Range{},
		},
	}

	_ = s.SemanticTokensData()
}

func TestBuiltinsHaveCompletionAndTeachingCoverage(t *testing.T) {
	a := New()
	s := a.Analyze("let sample = 1;\nsample;\n")
	items := s.CompletionItems()

	byLabel := make(map[string]struct {
		detail string
		has    bool
	}, len(items))
	for _, item := range items {
		detail := ""
		if item.Detail != nil {
			detail = *item.Detail
		}
		byLabel[item.Label] = struct {
			detail string
			has    bool
		}{detail: detail, has: true}
	}

	for _, entry := range builtin.Builtins {
		item, ok := byLabel[entry.Name]
		if !ok || !item.has {
			t.Fatalf("builtin %q missing from completion items", entry.Name)
		}
		if item.detail != "builtin" {
			t.Fatalf("builtin %q completion detail = %q, want %q", entry.Name, item.detail, "builtin")
		}

		hover, ok := builtinHoverText(entry.Name)
		if !ok {
			t.Fatalf("builtin %q missing hover coverage", entry.Name)
		}
		if !strings.Contains(hover, "builtin `") {
			t.Fatalf("builtin %q hover text = %q, want builtin teaching prefix", entry.Name, hover)
		}

		sig, ok := builtinSignatureInformation(entry.Name)
		if !ok {
			t.Fatalf("builtin %q missing signature coverage", entry.Name)
		}
		if strings.TrimSpace(sig.Label) == "" {
			t.Fatalf("builtin %q signature label is empty", entry.Name)
		}
	}
}
