package analyzer

import (
	"testing"

	lsp "github.com/tliron/glsp/protocol_3_16"
)

// typeDefLine returns the start line of the type-definition location for the
// symbol at (line, char), or -1 if none was found.
func typeDefLine(t *testing.T, src string, line, char uint32) int {
	t.Helper()
	s := New().Analyze(src)
	loc, ok := s.TypeDefinitionLocation(lsp.DocumentUri("file:///t.mut"), lsp.Position{Line: line, Character: char})
	if !ok || loc == nil {
		return -1
	}
	return int(loc.Range.Start.Line)
}

func TestTypeDefinitionViaInferredEnum(t *testing.T) {
	// `c` is inferred as Color (an enum value); go-to-type jumps to the enum decl.
	src := "enum Color { Red, Green };\nlet c = Color.Red;\nc;\n"
	if got := typeDefLine(t, src, 2, 0); got != 0 {
		t.Fatalf("type-def line for c = %d, want 0 (the enum decl)", got)
	}
}

func TestTypeDefinitionViaFunctionReturnedStruct(t *testing.T) {
	// `p` gets its struct type only through the function's inferred return type,
	// which the old syntactic heuristic could not see.
	src := "struct Point { x; };\nlet mk = fn() { return Point{x: 1}; };\nlet p = mk();\np;\n"
	if got := typeDefLine(t, src, 3, 0); got != 0 {
		t.Fatalf("type-def line for p = %d, want 0 (the struct decl)", got)
	}
}

func TestTypeDefinitionDirectStructStillWorks(t *testing.T) {
	// Regression: the direct `let p = Point{...}` path must keep working.
	src := "struct Point { x; };\nlet p = Point{x: 1};\np;\n"
	if got := typeDefLine(t, src, 2, 0); got != 0 {
		t.Fatalf("type-def line for p = %d, want 0 (the struct decl)", got)
	}
}
