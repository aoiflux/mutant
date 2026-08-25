package analyzer

import (
	"strings"
	"testing"
)

// elementDiagnostics returns the messages of every element-contract complaint
// the linter produced for src.
func elementDiagnostics(t *testing.T, src string) []string {
	t.Helper()

	snapshot := New().Analyze(src)
	messages := make([]string, 0, 2)
	for _, diagnostic := range Diagnostics(snapshot, DefaultLintConfig()) {
		if strings.Contains(diagnostic.Message, "must be an ARRAY of") {
			messages = append(messages, diagnostic.Message)
		}
	}
	return messages
}

// TestElementTypeDiagnosticFlagsWrongElements covers the builtins whose
// implementations genuinely reject an element of the wrong kind.
func TestElementTypeDiagnosticFlagsWrongElements(t *testing.T) {
	for _, tc := range []struct {
		name  string
		src   string
		count int
		want  string
	}{
		{
			name:  "str_join rejects non-strings",
			src:   `putln(str_join([1, 2], ","));`,
			count: 2,
			want:  "must be an ARRAY of STRING; this element is INTEGER",
		},
		{
			name:  "str_join accepts strings",
			src:   `putln(str_join(["a", "b"], ","));`,
			count: 0,
		},
		{
			name:  "sum rejects a string element",
			src:   `putln(sum([1, "2", 3]));`,
			count: 1,
			want:  "must be an ARRAY of INTEGER or FLOAT; this element is STRING",
		},
		{
			name:  "sum accepts a mixed numeric array",
			src:   `putln(sum([1, 2.5, 3]));`,
			count: 0,
		},
		{
			name:  "only the offending element is flagged",
			src:   `putln(str_join(["a", 1, "c"], ","));`,
			count: 1,
			want:  "this element is INTEGER",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := elementDiagnostics(t, tc.src)
			if len(got) != tc.count {
				t.Fatalf("got %d element diagnostics %q, want %d", len(got), got, tc.count)
			}
			if tc.want != "" && !strings.Contains(got[0], tc.want) {
				t.Errorf("message %q does not contain %q", got[0], tc.want)
			}
		})
	}
}

// TestElementTypeDiagnosticStaysQuiet is the false-positive guard.
//
// The element check inherits every restriction the argument check has, and adds
// one of its own: it reads an array *literal* only. Each case here is something
// the checker cannot know is wrong, so saying nothing is the correct answer.
func TestElementTypeDiagnosticStaysQuiet(t *testing.T) {
	for _, tc := range []struct {
		name string
		src  string
		why  string
	}{
		{
			name: "array held in a variable",
			src:  `let parts = [1, 2]; putln(str_join(parts, ","));`,
			why:  "inference does not track element types through a binding",
		},
		{
			name: "array from a call",
			src:  `putln(str_join(text_split("a,b", ","), "-"));`,
			why:  "the element types of a call's result are not certain",
		},
		{
			name: "elements from calls",
			src:  `putln(str_join([str_upper("a"), str_upper("b")], ","));`,
			why:  "an element that is a call is not certain",
		},
		{
			name: "element mentions a reassigned name",
			src:  `let x = 1; x = "s"; putln(str_join([x], ","));`,
			why:  "a reassigned name has no type inference can be trusted on",
		},
		{
			name: "parameter with no element contract",
			src:  `putln(reverse([1, "two", 3.0]));`,
			why:  "reverse is polymorphic and declares no element kinds",
		},
		{
			name: "shadowed builtin",
			src:  `let str_join = fn(a, b) { 1; }; putln(str_join([1, 2], ","));`,
			why:  "the name resolves to a local binding, not the builtin",
		},
		{
			name: "empty array",
			src:  `putln(str_join([], ","));`,
			why:  "there is no element to be wrong",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := elementDiagnostics(t, tc.src); len(got) != 0 {
				t.Errorf("flagged %q, but %s", got, tc.why)
			}
		})
	}
}

// TestElementTypeDiagnosticCarriesFixData checks the payload a quick fix reads,
// so `str_join([1], ",")` can offer the same to_string wrap that a wrongly
// typed argument gets.
func TestElementTypeDiagnosticCarriesFixData(t *testing.T) {
	snapshot := New().Analyze(`putln(str_join([1], ","));`)

	for _, diagnostic := range Diagnostics(snapshot, DefaultLintConfig()) {
		if !strings.Contains(diagnostic.Message, "must be an ARRAY of") {
			continue
		}
		want, got, ok := ArgTypeDiagnosticKinds(diagnostic.Data)
		if !ok {
			t.Fatalf("element diagnostic carries no readable data: %#v", diagnostic.Data)
		}
		if len(want) != 1 || string(want[0]) != "STRING" {
			t.Errorf("want kinds = %v, expected [STRING]", want)
		}
		if string(got) != "INTEGER" {
			t.Errorf("got kind = %q, expected INTEGER", got)
		}
		return
	}
	t.Fatal("no element diagnostic was produced")
}
