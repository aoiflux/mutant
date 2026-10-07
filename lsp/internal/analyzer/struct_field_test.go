package analyzer

import (
	"strings"
	"testing"
)

// The editor's half of "a struct's declared field set is authoritative".
//
// Two properties, and the second is the one that costs something to get wrong.
// The squiggle has to appear where the build will refuse, and it has to be
// absent everywhere else -- an Error on a program that compiles is worse than no
// Error at all, because the author has no way to tell which of the two the
// editor is being.

// structFieldMessages returns the messages of every struct-field diagnostic in
// source.
//
// It goes through Diagnostics rather than calling StructFieldDiagnostics
// directly, so that the wiring is under the test too: a rule nothing calls
// passes every test of its own. The source tag is what isolates them, the same
// way the module rules' tag isolates theirs.
func structFieldMessages(t *testing.T, source string) []string {
	t.Helper()

	snapshot := New().Analyze(source)
	messages := make([]string, 0, 2)
	for _, diagnostic := range Diagnostics(snapshot, DefaultLintConfig()) {
		if diagnostic.Source != nil && *diagnostic.Source == structFieldSource {
			messages = append(messages, diagnostic.Message)
		}
	}
	return messages
}

func TestTheEditorFlagsAFieldTheStructDoesNotDeclare(t *testing.T) {
	for _, tc := range []struct {
		name   string
		source string
		want   []string
	}{
		{
			name:   "a read",
			source: "struct P { a; b; };\nlet p = P { a: 1, b: 2 };\np.zzz;\n",
			want:   []string{"struct P has no field zzz", "it declares a, b"},
		},
		{
			name:   "a write, in a write's words",
			source: "struct P { a; b; };\nlet p = P { a: 1, b: 2 };\np.zzz = 9;\n",
			want:   []string{"cannot set field zzz on struct P", "fixed by its declaration"},
		},
		{
			name:   "a read inside a function that closes over the struct",
			source: "struct P { a; };\nlet p = P { a: 1 };\nlet f = fn() { return p.zzz; };\n",
			want:   []string{"has no field zzz"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			messages := structFieldMessages(t, tc.source)
			if len(messages) != 1 {
				t.Fatalf("got %d diagnostics, want 1: %v", len(messages), messages)
			}
			for _, want := range tc.want {
				if !strings.Contains(messages[0], want) {
					t.Errorf("%q does not contain %q", messages[0], want)
				}
			}
		})
	}
}

// Everything the editor must stay quiet about. Each of these either compiles or
// is somebody else's diagnostic, and a struct-field Error on any of them would
// be the editor contradicting the build.
func TestTheEditorStaysQuietWhereTheTypeIsNotCertain(t *testing.T) {
	for _, tc := range []struct{ name, source string }{
		{
			name:   "a declared field",
			source: "struct P { a; b; };\nlet p = P { a: 1, b: 2 };\np.a;\np.b = 9;\n",
		},
		{
			// The program is legal: p holds a Q by the time the read runs.
			// resolveDefinition still answers "the let that made it a P", which
			// is why reassignedNames exists.
			name: "a name reassigned to another struct type",
			source: "struct P { a; };\nstruct Q { zzz; };\n" +
				"let p = P { a: 1 };\nlet f = fn() { return p.zzz; };\np = Q { zzz: 7 };\n",
		},
		{
			name:   "a name reassigned to anything at all",
			source: "struct P { a; };\nlet p = P { a: 1 };\np = 5;\np.zzz;\n",
		},
		{
			// A parameter is its own declaration, and the graph says so, so no
			// name-poisoning is needed to get this right.
			name:   "a parameter that shadows a struct binding",
			source: "struct P { a; };\nlet p = P { a: 1 };\nlet f = fn(p) { return p.zzz; };\n",
		},
		{
			name:   "a receiver that is a parameter",
			source: "struct P { a; };\nlet f = fn(rec) { return rec.zzz; };\n",
		},
		{
			name:   "a receiver that came from a call",
			source: "struct P { a; };\nlet f = fn() { return P { a: 1 }; };\nf().zzz;\n",
		},
		{
			name:   "a receiver that came from another binding",
			source: "struct P { a; };\nlet p = P { a: 1 };\nlet q = p;\nq.zzz;\n",
		},
		{
			name: "the second hop of a chain",
			source: "struct Inner { z; };\nstruct Outer { i; };\n" +
				"let o = Outer { i: Inner { z: 1 } };\no.i.zzz;\n",
		},
		{
			name:   "an enum variant, which is not a field at all",
			source: "enum Colour { Red; Green; };\nlet c = Colour.Red;\n",
		},
		{
			name:   "a builtin fold, which is a spelling and not a binding",
			source: "let digest = hash.sha256(\"x\");\n",
		},
		{
			name:   "a field read on an error, whose unknown fields are null by design",
			source: "let v, e = to_int(\"x\");\ne.no_such_field;\n",
		},
		{
			// A literal nothing declared is compileStructLiteral's refusal, and
			// the type has no field list to check a read against.
			name:   "a receiver of an undeclared type",
			source: "let p = Undeclared { a: 1 };\np.zzz;\n",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if messages := structFieldMessages(t, tc.source); len(messages) != 0 {
				t.Errorf("the editor flagged a program it must not: %v", messages)
			}
		})
	}
}

// The words are the compiler's, taken from the same function, so that the
// squiggle and the build error cannot drift into two phrasings. object's own
// tests own the wording; this owns the fact that the editor reads it from there.
func TestTheEditorUsesTheCompilersWords(t *testing.T) {
	messages := structFieldMessages(t, "struct P { a; b; };\nlet p = P { a: 1, b: 2 };\np.zzz;\n")
	if len(messages) != 1 {
		t.Fatalf("got %d diagnostics, want 1", len(messages))
	}
	want := "struct P has no field zzz: it declares a, b"
	if messages[0] != want {
		t.Errorf("message = %q, want %q", messages[0], want)
	}
}
