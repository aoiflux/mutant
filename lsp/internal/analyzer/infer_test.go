package analyzer

import (
	"strings"
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
		// text_split, not str_split: the curated return table this replaced
		// named two builtins — str_split and str_replace — that do not exist,
		// so those entries could never have fired.
		{"let x = text_split(\"a,b\", \",\");", "[]string"},
		{"let x = time_now();", "hash"},
	}
	for _, c := range cases {
		if got := typeAt(t, c.src, 0, 4); got != c.want {
			t.Fatalf("%q: type = %q, want %q", c.src, got, c.want)
		}
	}
}

// TestSingleBindOfAPairBuiltinIsTypedAsThePair covers the correction the
// derived return contracts made possible.
//
// A builtin following the (value, err) convention returns a MULTI_VALUE, and
// binding it to one name stores the whole thing: evaluator.go takes the
// `len(names) <= 1` branch and calls env.Set with the value unchanged. The
// curated table had fs_exists down as a bare BOOLEAN, so hover and the inlay
// hint both described a plain `bool` that the program never actually holds.
func TestSingleBindOfAPairBuiltinIsTypedAsThePair(t *testing.T) {
	cases := []struct {
		src  string
		want string
	}{
		{"let x = fs_exists(\"p\");", "(bool, error)"},
		{"let x = fs_read(\"p\");", "(string, error)"},
		{"let x = fs_stat(\"p\");", "(hash, error)"},
		// fs_write returns boolObj(true), not a byte count — another thing the
		// curated table had wrong.
		{"let x = fs_write(\"p\", \"d\");", "(bool, error)"},
	}
	for _, c := range cases {
		if got := typeAt(t, c.src, 0, 4); got != c.want {
			t.Errorf("%q: type = %q, want %q", c.src, got, c.want)
		}
	}

	// Destructuring is unchanged: that is the shape the builtin was written for.
	if got := typeAt(t, "let ok, err = fs_exists(\"p\");", 0, 4); got != "bool" {
		t.Errorf("destructured value = %q, want bool", got)
	}
	if got := typeAt(t, "let ok, err = fs_exists(\"p\");", 0, 8); got != "error" {
		t.Errorf("destructured error = %q, want error", got)
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

func TestInferUserFunctionReturnType(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want string
	}{
		{
			"explicit-return",
			"let f = fn() { return 42; };\nlet y = f();\n",
			"int",
		},
		{
			"implicit-trailing-return",
			"let f = fn() { 3.14 };\nlet y = f();\n",
			"float",
		},
		{
			"return-through-if",
			"let f = fn(b) { if (b) { return 1; } else { return 2; } };\nlet y = f(true);\n",
			"int",
		},
		{
			"conflicting-returns-any",
			"let f = fn(b) { if (b) { return 1; } else { return \"x\"; } };\nlet y = f(true);\n",
			"", // disagreement collapses to Any (absent)
		},
		{
			"iife",
			"let y = fn() { return len(\"hi\"); }();\n",
			"int",
		},
		{
			"struct-return",
			"struct Point { x; };\nlet mk = fn() { return Point{x: 1}; };\nlet p = mk();\n",
			"Point",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// The `let y`/`let p` binding is always the last line, name at column 4.
			line := uint32(strings.Count(c.src, "\n") - 1)
			if got := typeAt(t, c.src, line, 4); got != c.want {
				t.Fatalf("%s: type = %q, want %q", c.name, got, c.want)
			}
		})
	}
}

func TestInferFunctionValueShowsReturn(t *testing.T) {
	// The function binding itself carries `fn -> T` when the return is known.
	src := "let f = fn() { return 42; };\nf;\n"
	if got := typeAt(t, src, 1, 0); got != "fn -> int" {
		t.Fatalf("f type = %q, want \"fn -> int\"", got)
	}
}

func TestInferElementTypesThroughCalls(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want string
	}{
		{"sort-preserves-elem", "let x = sort([1, 2, 3]);", "[]int"},
		{"reverse-preserves-elem", "let x = reverse([1, 2, 3]);", "[]int"},
		{"unique-preserves-elem", "let x = unique([1, 2, 3]);", "[]int"},
		{"rest-preserves-elem", "let x = rest([1, 2, 3]);", "[]int"},
		{"pop-preserves-elem", "let x = pop([1, 2, 3]);", "[]int"},
		{"slice-preserves-elem", "let x = slice([1, 2, 3], 0, 2);", "[]int"},
		{"filter-preserves-elem", "let x = filter([1, 2, 3], fn(n) { n > 1 });", "[]int"},
		{"sort_by-preserves-elem", "let x = sort_by([\"b\", \"a\"], fn(s) { s });", "[]string"},
		{"first-yields-elem", "let x = first([1, 2, 3]);", "int"},
		{"last-yields-elem", "let x = last([\"a\", \"b\"]);", "string"},
		{"map-uses-mapper-ret", "let x = map([1, 2, 3], fn(n) { to_string(n) });", "[]string"},
		{"push-same-type", "let x = push([1, 2], 3);", "[]int"},
		{"push-mixed-type-bare", "let x = push([1, 2], \"a\");", "array"},
		{"concat-same-type", "let x = concat([1, 2], [3, 4]);", "[]int"},
		{"concat-mixed-type-bare", "let x = concat([1], [\"a\"]);", "array"},
		{"element-through-binding", "let a = [1, 2, 3];\nlet b = sort(a);", "[]int"},
		{"unknown-array-stays-bare", "let a = read_stuff();\nlet b = sort(a);", "array"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// The bound name is always at column 4 on the source's last line.
			line := uint32(strings.Count(c.src, "\n"))
			if got := typeAt(t, c.src, line, 4); got != c.want {
				t.Fatalf("%s: type = %q, want %q", c.name, got, c.want)
			}
		})
	}
}

func TestInferNumericKindPreservingCalls(t *testing.T) {
	cases := []struct {
		src  string
		want string
	}{
		{"let x = abs(-5);", "int"},
		{"let x = abs(-3.14);", "float"},
		{"let x = sum([1, 2, 3]);", "int"},
		{"let x = sum([1.0, 2.0]);", "float"},
		{"let x = min(1, 2, 3);", "int"},
		{"let x = max(1.0, 2.0);", "float"},
		{"let x = mod(10, 3);", "int"},
		{"let x = mod(10.0, 3);", "float"},
		{"let x = min(1, 2.0);", ""}, // mixed int/float -> ambiguous -> absent
	}
	for _, c := range cases {
		if got := typeAt(t, c.src, 0, 4); got != c.want {
			t.Fatalf("%q: type = %q, want %q", c.src, got, c.want)
		}
	}
}

func TestInferBroadenedBuiltinTable(t *testing.T) {
	cases := []struct {
		src  string
		want string
	}{
		{"let x = pow(2, 3);", "float"},
		{"let x = sqrt(4);", "float"},
		{"let x = floor(3.7);", "int"},
		{"let x = round(3.4);", "int"},
		{"let x = avg([1, 2, 3]);", "float"},
		{"let x = rand_int(1, 10);", "int"},
		{"let x = has_key({\"a\": 1}, \"a\");", "bool"},
		{"let x = is_null(1);", "bool"},
		{"let x = time_unix();", "int"},
		{"let x = time_format(0, \"2006\");", "string"},
		{"let x = base32_encode(\"hi\");", "string"},
		{"let x = uuid_v7();", "string"},
		{"let x = to_base(255, 16);", "string"},
	}
	for _, c := range cases {
		if got := typeAt(t, c.src, 0, 4); got != c.want {
			t.Fatalf("%q: type = %q, want %q", c.src, got, c.want)
		}
	}
}

func TestInferStructFieldTypes(t *testing.T) {
	cases := []struct {
		name string
		src  string
		line uint32
		char uint32
		want string
	}{
		{
			"int-field",
			"struct Point { x; y; };\nlet p = Point{x: 1, y: 2.0};\np.x;\n",
			2, 2, "int",
		},
		{
			"float-field",
			"struct Point { x; y; };\nlet p = Point{x: 1, y: 2.0};\np.y;\n",
			2, 2, "float",
		},
		{
			"string-field",
			"struct User { name; };\nlet u = User{name: \"bob\"};\nu.name;\n",
			2, 2, "string",
		},
		{
			// The field type flows through a binding: q = p.x is an int.
			"field-propagates-to-binding",
			"struct Point { x; };\nlet p = Point{x: 1};\nlet q = p.x;\nq;\n",
			3, 0, "int",
		},
		{
			// Disagreeing initializers poison the field -> no type (safe).
			"conflicting-initializers-absent",
			"struct Box { v; };\nlet a = Box{v: 1};\nlet b = Box{v: \"s\"};\na.v;\n",
			3, 2, "",
		},
		{
			// A field never set in any initializer has no inferred type.
			"uninitialized-field-absent",
			"struct Point { x; y; };\nlet p = Point{x: 1};\np.y;\n",
			2, 2, "",
		},
		{
			// An unknown initializer value poisons the field (could be anything).
			"unknown-initializer-value-absent",
			"struct Point { x; };\nlet p = Point{x: mystery()};\np.x;\n",
			2, 2, "",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := typeAt(t, c.src, c.line, c.char); got != c.want {
				t.Fatalf("%s: type = %q, want %q", c.name, got, c.want)
			}
		})
	}
}

func TestInferMultiBindNewFallibles(t *testing.T) {
	// parse_int -> (int, error)
	src := "let n, err = parse_int(\"5\", 10);"
	if got := typeAt(t, src, 0, 4); got != "int" {
		t.Fatalf("n type = %q, want int", got)
	}
	if got := typeAt(t, src, 0, 7); got != "error" {
		t.Fatalf("err type = %q, want error", got)
	}
	// base32_decode -> (string, error)
	src = "let v, err = base32_decode(\"aa\");"
	if got := typeAt(t, src, 0, 4); got != "string" {
		t.Fatalf("v type = %q, want string", got)
	}
	if got := typeAt(t, src, 0, 7); got != "error" {
		t.Fatalf("err type = %q, want error", got)
	}
}
