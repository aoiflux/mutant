package analyzer

import (
	"testing"

	"mutant/object"

	lsp "github.com/tliron/glsp/protocol_3_16"
)

// The editor's field table is a second copy of one the runtime owns. This is the
// pin that stops it drifting: a field added to object.Error.Field and not here
// would otherwise hover as `any` and be missing from completion, silently and
// forever.
func TestErrorFieldTableMatchesTheRuntime(t *testing.T) {
	runtime := object.ErrorFieldNames()

	for _, name := range runtime {
		if _, ok := errorFieldType(name); !ok {
			t.Errorf("the runtime has field %q and the analyzer does not", name)
		}
	}
	if len(errorFieldTypes) != len(runtime) {
		t.Errorf("analyzer has %d fields, the runtime has %d",
			len(errorFieldTypes), len(runtime))
	}

	// Order is load-bearing for completion, so it is checked rather than assumed.
	names := errorFieldNames()
	if len(names) != len(runtime) || (len(names) > 0 && names[0] != "message") {
		t.Errorf("completion order = %v, want the runtime's order starting at message", names)
	}
}

// Line 0 binds an error; the expression under test goes on line 1, so every case
// below reads the type of the `x` at 1:4.
const errBinding = "let d, err = fs_read(\"p\");\n"

// Hovering err.line should say `int`, not `any`. The types come from a fixed
// table rather than from initializers, so unlike a struct's fields they are
// known without the analyzer having seen the value built.
func TestErrorFieldTypesAreInferred(t *testing.T) {
	cases := []struct {
		expr string
		want string
	}{
		{"err.message", "string"},
		{"err.line", "int"},
		{"err.related", "hash"},
		{"err.stack", "[]string"},
		{`err["column"]`, "int"},
	}

	for _, tc := range cases {
		got := typeAt(t, errBinding+"let x = "+tc.expr+";\n", 1, 4)
		if got != tc.want {
			t.Errorf("%s is %s, want %s", tc.expr, got, tc.want)
		}
	}
}

// An unknown field falls back to the gradual unknown rather than being claimed
// as something. The runtime reads it as null; the editor declining to guess is
// the honest match for that.
func TestUnknownErrorFieldStaysUnknown(t *testing.T) {
	got := typeAt(t, errBinding+"let x = err.no_such_field;\n", 1, 4)
	if got != "" && got != "any" {
		t.Errorf("an unknown error field typed as %s, want any", got)
	}
}

// A computed key could name any field, so no type is claimed for it. Picking one
// would make the hover a coin flip.
func TestComputedErrorIndexIsNotTyped(t *testing.T) {
	src := errBinding + "let k = \"line\";\nlet x = err[k];\n"
	if got := typeAt(t, src, 2, 4); got != "" && got != "any" {
		t.Errorf("a computed error index typed as %s, want any", got)
	}
}

func TestMemberCompletionErrorFields(t *testing.T) {
	s := New().Analyze(errBinding + "err.\n")

	items, ok := s.MemberCompletionsAt(lsp.Position{Line: 1, Character: 4})
	if !ok {
		t.Fatal("expected member completion after err.")
	}

	labels := memberLabels(items)
	for _, name := range object.ErrorFieldNames() {
		if !labels[name] {
			t.Errorf("completion is missing %q: %v", name, labels)
		}
	}

	for _, it := range items {
		if it.Kind == nil || *it.Kind != lsp.CompletionItemKindField {
			t.Errorf("field %q kind = %v, want Field", it.Label, it.Kind)
		}
		if it.Detail == nil || *it.Detail == "" {
			t.Errorf("field %q has no type detail", it.Label)
		}
	}
}
