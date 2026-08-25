package analyzer

import (
	"testing"

	lsp "github.com/tliron/glsp/protocol_3_16"
)

func memberLabels(items []lsp.CompletionItem) map[string]bool {
	out := make(map[string]bool, len(items))
	for _, it := range items {
		out[it.Label] = true
	}
	return out
}

func TestMemberCompletionStructFields(t *testing.T) {
	src := "struct Point { x; y; };\n" +
		"let p = Point{x: 1, y: 2};\n" +
		"p.\n"
	s := New().Analyze(src)
	items, ok := s.MemberCompletionsAt(lsp.Position{Line: 2, Character: 2})
	if !ok {
		t.Fatal("expected member completion after p.")
	}
	labels := memberLabels(items)
	if !labels["x"] || !labels["y"] {
		t.Fatalf("expected fields x and y, got %v", labels)
	}
	// Fields must be classified as Field.
	for _, it := range items {
		if it.Kind == nil || *it.Kind != lsp.CompletionItemKindField {
			t.Fatalf("field %q kind = %v, want Field", it.Label, it.Kind)
		}
	}
}

func TestMemberCompletionEnumVariants(t *testing.T) {
	src := "enum Color { Red, Green, Blue };\n" +
		"Color.\n"
	s := New().Analyze(src)
	items, ok := s.MemberCompletionsAt(lsp.Position{Line: 1, Character: 6})
	if !ok {
		t.Fatal("expected member completion after Color.")
	}
	labels := memberLabels(items)
	if !labels["Red"] || !labels["Green"] || !labels["Blue"] {
		t.Fatalf("expected variants Red/Green/Blue, got %v", labels)
	}
	for _, it := range items {
		if it.Kind == nil || *it.Kind != lsp.CompletionItemKindEnumMember {
			t.Fatalf("variant %q kind = %v, want EnumMember", it.Label, it.Kind)
		}
	}
}

func TestMemberCompletionPrefixFilter(t *testing.T) {
	src := "struct Point { x; y; name; };\n" +
		"let p = Point{x: 1, y: 2, name: 3};\n" +
		"p.na\n"
	s := New().Analyze(src)
	items, ok := s.MemberCompletionsAt(lsp.Position{Line: 2, Character: 4})
	if !ok {
		t.Fatal("expected member completion after p.na")
	}
	labels := memberLabels(items)
	if !labels["name"] {
		t.Fatalf("expected 'name' to match prefix 'na', got %v", labels)
	}
	if labels["x"] || labels["y"] {
		t.Fatalf("prefix 'na' should exclude x/y, got %v", labels)
	}
}

func TestMemberCompletionNotAMemberAccess(t *testing.T) {
	src := "let a = 1;\na\n"
	s := New().Analyze(src)
	if _, ok := s.MemberCompletionsAt(lsp.Position{Line: 1, Character: 1}); ok {
		t.Fatal("plain identifier should not trigger member completion")
	}
}

func TestMemberCompletionUnknownReceiver(t *testing.T) {
	src := "let x = 1;\nfoo.\n"
	s := New().Analyze(src)
	if _, ok := s.MemberCompletionsAt(lsp.Position{Line: 1, Character: 4}); ok {
		t.Fatal("unknown receiver should not produce member completion")
	}
}

func TestMemberCompletionChainedReceiverUnsupported(t *testing.T) {
	src := "struct Point { x; };\nlet p = Point{x: 1};\np.x.\n"
	s := New().Analyze(src)
	if _, ok := s.MemberCompletionsAt(lsp.Position{Line: 2, Character: 4}); ok {
		t.Fatal("chained receiver a.b. is out of scope and must return false")
	}
}
