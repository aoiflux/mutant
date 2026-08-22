package analyzer

import (
	"strings"
	"testing"

	lsp "github.com/tliron/glsp/protocol_3_16"
)

func TestHoverShowsInferredType(t *testing.T) {
	s := New().Analyze("let count = 5;\ncount;\n")
	// hover on the usage `count` (line 1)
	text, _, ok := s.HoverText(lsp.Position{Line: 1, Character: 0})
	if !ok {
		t.Fatal("expected hover text")
	}
	if !strings.Contains(text, ": int") {
		t.Fatalf("hover = %q, want it to contain ': int'", text)
	}
}

func TestHoverShowsStructType(t *testing.T) {
	s := New().Analyze("struct Point { x; };\nlet p = Point{x: 1};\np;\n")
	text, _, ok := s.HoverText(lsp.Position{Line: 2, Character: 0})
	if !ok {
		t.Fatal("expected hover text")
	}
	if !strings.Contains(text, ": Point") {
		t.Fatalf("hover = %q, want it to contain ': Point'", text)
	}
}

func TestHoverNoTypeForUnknown(t *testing.T) {
	s := New().Analyze("let x = mystery_call();\nx;\n")
	text, _, ok := s.HoverText(lsp.Position{Line: 1, Character: 0})
	if !ok {
		t.Fatal("expected hover text")
	}
	if strings.Contains(text, " : ") {
		t.Fatalf("hover for unknown type should not show ' : ', got %q", text)
	}
}

func TestHoverShowsFunctionReturnType(t *testing.T) {
	s := New().Analyze("let f = fn() { return 42; };\nf;\n")
	text, _, ok := s.HoverText(lsp.Position{Line: 1, Character: 0})
	if !ok {
		t.Fatal("expected hover text")
	}
	// The card renders inferred types in the same uppercase vocabulary the
	// builtin cards use, so hovering a user function and hovering a builtin
	// read alike rather than in two different type languages.
	if !strings.Contains(text, "-> INTEGER") {
		t.Fatalf("hover = %q, want it to contain '-> INTEGER'", text)
	}
}

func TestCompletionDetailCarriesType(t *testing.T) {
	s := New().Analyze("let total = 42;\n\n")
	items := s.CompletionItemsAt(lsp.Position{Line: 1, Character: 0})
	var found bool
	for _, it := range items {
		if it.Label == "total" {
			found = true
			if it.Detail == nil || *it.Detail != "int" {
				t.Fatalf("completion detail for total = %v, want \"int\"", it.Detail)
			}
		}
	}
	if !found {
		t.Fatal("expected a completion item for total")
	}
}

func TestHoverShowsStructFieldType(t *testing.T) {
	s := New().Analyze("struct Point { x; };\nlet p = Point{x: 1};\np.x;\n")
	// hover on the field accessor `x` in `p.x` (line 2, the `x` at column 2)
	text, _, ok := s.HoverText(lsp.Position{Line: 2, Character: 2})
	if !ok {
		t.Fatal("expected hover text")
	}
	// A field renders the way the struct card renders it, in the same uppercase
	// vocabulary the builtin cards use, and names the struct it belongs to.
	if !strings.Contains(text, "field `x` · `INTEGER` _(inferred)_") {
		t.Fatalf("hover = %q, want the typed field line", text)
	}
	if !strings.Contains(text, "Field of struct `Point`.") {
		t.Fatalf("hover = %q, want the owning struct named", text)
	}
}

// TestHoverOnStructDeclarationListsFieldTypes covers the card a struct
// declaration gets. A struct declaration carries only field *names*, so the
// types come from how the document initialises one — which is why they are
// marked inferred, and why a field nothing initialises says so instead of
// guessing.
func TestHoverOnStructDeclarationListsFieldTypes(t *testing.T) {
	s := New().Analyze("struct Finding { path; score; notes; };\n" +
		"let f = Finding{path: \"a\", score: 3, notes: unknown_call()};\n")

	text, _, ok := s.HoverText(lsp.Position{Line: 0, Character: 8})
	if !ok {
		t.Fatal("expected hover text on the struct declaration")
	}
	for _, want := range []string{
		"struct `Finding`",
		"**Fields**",
		"- `path` · `STRING` _(inferred)_",
		"- `score` · `INTEGER` _(inferred)_",
		"- `notes` _(not inferred)_",
		"_Field types are inferred from this file's struct initializers._",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("struct card is missing %q:\n%s", want, text)
		}
	}
}

// TestHoverOnStructWithNoInitializerSaysSo keeps the card honest about why it
// has nothing to show, rather than rendering a field list that looks broken.
func TestHoverOnStructWithNoInitializerSaysSo(t *testing.T) {
	s := New().Analyze("struct Empty { a; b; };\n")

	text, _, ok := s.HoverText(lsp.Position{Line: 0, Character: 8})
	if !ok {
		t.Fatal("expected hover text on the struct declaration")
	}
	if !strings.Contains(text, "- `a` _(not inferred)_") {
		t.Errorf("card should list the field with no type:\n%s", text)
	}
	if !strings.Contains(text, "No initializer for this struct in this file") {
		t.Errorf("card should explain why no types are shown:\n%s", text)
	}
}

// TestHoverOnEnumDeclarationListsVariants shows the ordinal each variant
// carries. Both engines assign it by declaration order, and it is the value a
// builtin taking an ENUM_VALUE actually receives — db_add_node's 0..127 range
// is a constraint on exactly this number.
func TestHoverOnEnumDeclarationListsVariants(t *testing.T) {
	s := New().Analyze("enum Severity { Low, Medium, High };\n")

	text, _, ok := s.HoverText(lsp.Position{Line: 0, Character: 6})
	if !ok {
		t.Fatal("expected hover text on the enum declaration")
	}
	for _, want := range []string{
		"enum `Severity`",
		"**Variants**",
		"- `Low` · `0`",
		"- `Medium` · `1`",
		"- `High` · `2`",
		"_Ordinals are assigned by declaration order._",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("enum card is missing %q:\n%s", want, text)
		}
	}
}

// TestHoverOnTypeNameUsageReachesTheSameCard checks a type name mentioned away
// from its declaration — as a literal's type — gets the card rather than the
// bare "identifier `Point` : Point" line it used to.
func TestHoverOnTypeNameUsageReachesTheSameCard(t *testing.T) {
	s := New().Analyze("struct Point { x; y; };\nlet p = Point{x: 1, y: 2};\n")

	text, _, ok := s.HoverText(lsp.Position{Line: 1, Character: 9})
	if !ok {
		t.Fatal("expected hover text on the struct literal's type name")
	}
	if !strings.Contains(text, "struct `Point`") || !strings.Contains(text, "**Fields**") {
		t.Errorf("a type name usage did not reach the struct card:\n%s", text)
	}
}

func TestMemberCompletionCarriesFieldType(t *testing.T) {
	s := New().Analyze("struct Point { x; y; };\nlet p = Point{x: 1, y: 2.0};\np.\n")
	items, ok := s.MemberCompletionsAt(lsp.Position{Line: 2, Character: 2})
	if !ok {
		t.Fatal("expected member completions after `p.`")
	}
	want := map[string]string{"x": "int", "y": "float"}
	seen := map[string]bool{}
	for _, it := range items {
		exp, tracked := want[it.Label]
		if !tracked {
			continue
		}
		seen[it.Label] = true
		if it.Detail == nil || *it.Detail != exp {
			t.Fatalf("field %q detail = %v, want %q", it.Label, it.Detail, exp)
		}
	}
	for field := range want {
		if !seen[field] {
			t.Fatalf("expected a member completion item for field %q", field)
		}
	}
}

func TestInlayTypeHintOnLetBinding(t *testing.T) {
	s := New().Analyze("let count = 5;\nlet mystery = unknown_fn();\n")
	hints := s.InlayHints(lsp.Range{
		Start: lsp.Position{Line: 0, Character: 0},
		End:   lsp.Position{Line: 100, Character: 0},
	})

	var haveInt, haveMystery bool
	for _, h := range hints {
		if h.Label == ": int" {
			haveInt = true
		}
		// `mystery` has an unknown type -> no type hint for it.
		if strings.HasPrefix(h.Label, ":") && h.Position.Line == 1 {
			haveMystery = true
		}
	}
	if !haveInt {
		t.Fatalf("expected a ': int' type hint for count, got %+v", hints)
	}
	if haveMystery {
		t.Fatal("expected no type hint for the untyped `mystery` binding")
	}
}
