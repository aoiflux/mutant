package analyzer

import (
	"testing"

	lsp "github.com/tliron/glsp/protocol_3_16"
)

// typeAt analyzes src and returns the inferred type string at the given 0-based
// position (on an identifier or literal), or "" if none was inferred.
func typeAt(t *testing.T, src string, line, char uint32) string {
	t.Helper()
	s := New().Analyze(src)
	node, _, ok := s.NodeAt(lsp.Position{Line: line, Character: char})
	if !ok {
		t.Fatalf("no node at %d:%d in %q", line, char, src)
	}
	ty, ok := s.TypeOf(node)
	if !ok {
		return ""
	}
	return ty.String()
}

func TestInferLiteralAndLetTypes(t *testing.T) {
	cases := []struct {
		name string
		src  string
		char uint32 // column of the `let` name (always line 0, after "let ")
		want string
	}{
		{"int", "let x = 42;", 4, "int"},
		{"float", "let x = 3.14;", 4, "float"},
		{"string", "let x = \"hi\";", 4, "string"},
		{"bool", "let x = true;", 4, "bool"},
		{"array-int", "let x = [1, 2, 3];", 4, "[]int"},
		{"hash", "let x = {\"a\": 1};", 4, "hash"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := typeAt(t, c.src, 0, c.char); got != c.want {
				t.Fatalf("type of let-name = %q, want %q", got, c.want)
			}
		})
	}
}

func TestInferBuiltinReturnTypes(t *testing.T) {
	cases := []struct {
		src  string
		want string
	}{
		{"let x = len(\"hi\");", "int"},
		{"let x = str_upper(\"hi\");", "string"},
		{"let x = str_split(\"a,b\", \",\");", "[]string"},
		{"let x = fs_exists(\"p\");", "bool"},
		{"let x = time_now();", "hash"},
	}
	for _, c := range cases {
		if got := typeAt(t, c.src, 0, 4); got != c.want {
			t.Fatalf("%q: type = %q, want %q", c.src, got, c.want)
		}
	}
}

func TestInferMultiBindFallible(t *testing.T) {
	src := "let v, err = to_int(\"5\");"
	// `v` at column 4, `err` at column 7
	if got := typeAt(t, src, 0, 4); got != "int" {
		t.Fatalf("v type = %q, want int", got)
	}
	if got := typeAt(t, src, 0, 7); got != "error" {
		t.Fatalf("err type = %q, want error", got)
	}
}

func TestInferStructLiteralType(t *testing.T) {
	src := "struct Point { x; y; };\nlet p = Point{x: 1, y: 2};\n"
	// `p` is on line 1 at column 4
	if got := typeAt(t, src, 1, 4); got != "Point" {
		t.Fatalf("p type = %q, want Point", got)
	}
}

func TestInferInfixTypes(t *testing.T) {
	cases := []struct {
		src  string
		want string
	}{
		{"let x = 1 + 2;", "int"},
		{"let x = 1.0 + 2;", "float"},
		{"let x = 1 < 2;", "bool"},
		{"let x = \"a\" + \"b\";", "string"},
	}
	for _, c := range cases {
		if got := typeAt(t, c.src, 0, 4); got != c.want {
			t.Fatalf("%q: type = %q, want %q", c.src, got, c.want)
		}
	}
}

func TestInferUnknownIsAbsent(t *testing.T) {
	// An unknown builtin/function result must not be typed (Any -> absent).
	if got := typeAt(t, "let x = mystery_call(1);", 0, 4); got != "" {
		t.Fatalf("unknown result should be untyped, got %q", got)
	}
}

func TestInferIdentifierUsageType(t *testing.T) {
	// A usage of a typed binding carries the binding's type.
	src := "let count = 5;\ncount;\n"
	if got := typeAt(t, src, 1, 0); got != "int" {
		t.Fatalf("usage of count = %q, want int", got)
	}
}
