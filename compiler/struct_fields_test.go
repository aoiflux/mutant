package compiler

import (
	"strings"
	"testing"

	"mutant/lexer"
	"mutant/parser"
)

// A struct's declared field set is authoritative, and the compiler refuses a
// field outside it wherever it can prove what the receiver holds.
//
// The refusals are the easy half. The half these tests exist for is the other
// one: the compiler must not refuse a program that works. compileFieldExpression
// sees `p.zzz` long before it sees whatever line reassigns p, so the only way
// the answer can be trusted is for the scan to have read the whole program
// first -- and for anything it did not understand to abandon the attempt rather
// than be skipped. TestAnAssignmentAnywhereKeepsTheReadCompiling is that half.

// compileProgram parses and compiles, failing the test on a parse error rather
// than compiling the wreckage.
//
// Without that check an input that is not a program at all reads as whatever
// the compiler made of the pieces. `{ p = 1; }` cost an afternoon: LBRACE is
// registered as a prefix for parseHashLiteral, so a bare block is a hash
// literal here and there is no such statement in the language.
func compileProgram(t *testing.T, input string) error {
	t.Helper()
	p := parser.New(lexer.New(input))
	program := p.ParseProgram()
	if errs := p.Errors(); len(errs) > 0 {
		t.Fatalf("%q does not parse: %s", input, strings.Join(errs, "; "))
	}
	return New().Compile(program)
}

func TestAFieldTheStructDoesNotDeclareIsRefused(t *testing.T) {
	for _, tc := range []struct {
		name  string
		input string
		// want is every word the message has to contain: the field that is
		// wrong, and the fields that are right.
		want []string
	}{
		{
			name:  "a read",
			input: "struct P { a; b; }; let p = P { a: 1, b: 2 }; p.zzz;",
			want:  []string{"zzz", "a, b"},
		},
		{
			name:  "a write",
			input: "struct P { a; b; }; let p = P { a: 1, b: 2 }; p.zzz = 9;",
			want:  []string{"zzz", "a, b", "fixed by its declaration"},
		},
		{
			name:  "a compound write",
			input: "struct P { a; b; }; let p = P { a: 1, b: 2 }; p.zzz += 9;",
			want:  []string{"zzz", "a, b"},
		},
		{
			name:  "a read inside a function",
			input: "struct P { a; }; let p = P { a: 1 }; let f = fn() { return p.zzz; };",
			want:  []string{"zzz", "a"},
		},
		{
			name:  "a read in a nested write's target",
			input: "struct P { a; }; let p = P { a: 1 }; p.zzz[0] = 1;",
			want:  []string{"zzz", "a"},
		},
		{
			name: "a struct that declares nothing",
			// `struct E { }` has no fields, so every name is the wrong one and
			// there is no list to offer.
			input: "struct E { }; let e = E { }; e.anything;",
			want:  []string{"anything", "no fields"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := compileProgram(t, tc.input)
			if err == nil {
				t.Fatalf("%s compiled; a field the declaration does not contain has to be refused", tc.input)
			}
			for _, want := range tc.want {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("refusal %q does not mention %q", err, want)
				}
			}
		})
	}
}

func TestADeclaredFieldStillCompiles(t *testing.T) {
	for _, input := range []string{
		"struct P { a; b; }; let p = P { a: 1, b: 2 }; p.a;",
		"struct P { a; b; }; let p = P { a: 1, b: 2 }; p.b = 9;",
		"struct P { a; b; }; let p = P { a: 1, b: 2 }; p.b += 9;",
		"struct P { a; }; let p = P { a: 1 }; let f = fn() { return p.a; };",
		"struct P { a; }; let p = P { a: [1, 2] }; p.a[0] = 9;",

		// Only the first hop has a type anything here knows. `p.a` is a field
		// of P; what `p.a` itself holds is inference, which this deliberately
		// does not do, so `.zzz` on it is left to the engines.
		"struct Inner { z; }; struct Outer { i; }; let o = Outer { i: Inner { z: 1 } }; o.i.zzz;",
		"struct Inner { z; }; struct Outer { i; }; let o = Outer { i: Inner { z: 1 } }; o.i.zzz = 2;",

		// A receiver whose type is not provable is not refused here. This is
		// most real code: examples/binary/static_bin_analysis.mut reads every
		// one of its fields through a parameter.
		"struct P { a; }; let f = fn(rec) { return rec.zzz; };",
		"struct P { a; }; let f = fn() { return P { a: 1 }; }; f().zzz;",
		"struct P { a; }; let ps = [P { a: 1 }]; ps[0].zzz;",

		// An error's fields are not a struct's, and reading an unknown one is
		// still null -- object/error_field_test.go and vm/error_field_test.go
		// own that rule. Nothing here may reach it.
		"let v, err = to_int(\"x\"); err.no_such_field;",
	} {
		if err := compileProgram(t, input); err != nil {
			t.Errorf("%s was refused: %s", input, err)
		}
	}
}

// Every way a program can take the certainty away, each of which has to leave
// the read to the engines instead of refusing it.
//
// The planted line is always a rebinding or a write of p, and the read is always
// `p.zzz`, which P does not declare. Every one of these programs has to compile:
// after the plant, p is not provably a P at the read, and a Q with a zzz is a
// legal thing for it to hold.
//
// A construct the scan cannot walk fails this test the safe way round. It would
// not see the plant, so it would abandon the whole program's tracking and the
// read would compile anyway -- which is why this is the test that matters more
// than the refusals above.
func TestAnAssignmentAnywhereKeepsTheReadCompiling(t *testing.T) {
	const preamble = "struct P { a; }; struct Q { zzz; }; let p = P { a: 1 };"
	const read = " p.zzz;"

	for _, tc := range []struct{ name, plant string }{
		{"at the top level", " p = Q { zzz: 1 };"},
		{"in an if", " if (true) { p = Q { zzz: 1 }; }"},
		{"in an else", " if (false) { putln(1); } else { p = Q { zzz: 1 }; }"},
		{"in a while", " while (false) { p = Q { zzz: 1 }; }"},
		{"in a c-style for", " for (let i = 0; i < 0; i = i + 1) { p = Q { zzz: 1 }; }"},
		{"in a for-in body", " for (v in []) { p = Q { zzz: 1 }; }"},
		{"in a function body", " let f = fn() { p = Q { zzz: 1 }; };"},
		{"in a function returned from a function", " let f = fn() { return fn() { p = Q { zzz: 1 }; }; };"},
		{"in a call argument", " putln(fn() { p = Q { zzz: 1 }; return 1; }());"},
		{"in an array element", " let xs = [fn() { p = Q { zzz: 1 }; }];"},
		{"in a hash value", " let h = { \"k\": fn() { p = Q { zzz: 1 }; } };"},
		{"in a struct literal's field", " struct Box { f; }; let b = Box { f: fn() { p = Q { zzz: 1 }; } };"},
		{"in a match arm", " match (1) { 1 => { p = Q { zzz: 1 }; } }"},
		{"in a template hole", " let f = fn() { p = Q { zzz: 1 }; return 1; }; let s = \"${f()}\";"},
		{"in an index expression", " let xs = [1]; let i = xs[fn() { p = Q { zzz: 1 }; return 0; }()];"},
		{"in an infix operand", " let n = 1 + fn() { p = Q { zzz: 1 }; return 1; }();"},
		{"as a compound assignment", " p += 1;"},
		{"as a postfix increment", " p++;"},
		{"as a second let in a function's own scope", " let f = fn() { let p = Q { zzz: 1 }; return p.zzz; };"},
		{"as a for-in variable", " for (p in []) { putln(1); }"},
		{"as a function parameter", " let f = fn(p) { return 1; };"},

		// Two constructs are deliberately absent.
		//
		// A second `let p` in the SAME scope is refused before any of this is
		// reached -- "duplicate declaration of p ... assign to it instead" --
		// so it is not a way to take the certainty away. The cross-scope form
		// above is, and is here.
		//
		// A macro parameter cannot be one either: DefineMacros strips every
		// macro definition out of the program before the compiler is handed it,
		// so the scan never meets a macro literal in production. The walk has a
		// case for one anyway, for the paths that compile without expanding.
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Planted before the read and after it, because the scan's whole
			// reason for reading the program first is the assignment that comes
			// after the read it would otherwise have refused.
			if err := compileProgram(t, preamble+tc.plant+read); err != nil {
				t.Errorf("plant before the read was refused: %s", err)
			}
			if err := compileProgram(t, preamble+read+tc.plant); err != nil {
				t.Errorf("plant after the read was refused: %s", err)
			}
		})
	}
}

// A field written through the struct is a read of the struct, not a rebinding of
// it, so it must not take the certainty away. structs_example.mut does exactly
// this, and it is the shape most likely to be broken by a careless scan.
func TestAFieldWriteDoesNotUntrackTheName(t *testing.T) {
	input := "struct P { a; b; }; let p = P { a: 1, b: 2 }; p.b = 9; p.zzz;"
	err := compileProgram(t, input)
	if err == nil {
		t.Fatal("a field write made the name untracked; p is still a P after p.b = 9")
	}
	if !strings.Contains(err.Error(), "zzz") {
		t.Errorf("refusal %q does not name zzz", err)
	}
}

// One typo makes one of each fault, and naming only the missing field is what
// sent the author to look at a field they had not touched.
func TestTheStructLiteralRefusalNamesBothDirections(t *testing.T) {
	for _, tc := range []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "a name the declaration does not contain, in place of one it does",
			input: "struct P { a; b; }; P { a: 1, c: 3 };",
			want:  []string{"c", "b", "a, b"},
		},
		{
			name:  "a field nothing set",
			input: "struct P { a; b; }; P { a: 1 };",
			want:  []string{"b", "a, b"},
		},
		{
			name:  "a field the declaration does not contain, and nothing missing",
			input: "struct P { a; }; P { a: 1, c: 3 };",
			want:  []string{"c"},
		},
		{
			name:  "two of each",
			input: "struct P { a; b; c; }; P { a: 1, y: 2, z: 3 };",
			want:  []string{"y, z", "b, c"},
		},
		{
			name:  "an undeclared type is still its own refusal",
			input: "Undeclared { a: 1 };",
			want:  []string{"undefined struct type", "Undeclared"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := compileProgram(t, tc.input)
			if err == nil {
				t.Fatalf("%s compiled", tc.input)
			}
			for _, want := range tc.want {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("refusal %q does not mention %q", err, want)
				}
			}
		})
	}
}

// A repeated field name, which the removed field-count check used to catch by
// accident and two steps away from where the mistake was made.
//
// This is the one way the counts can differ while the name SETS agree, so it is
// the one thing reporting the names rather than the count would have let
// through. `struct P { a; a; }` with the literal `P { a: 1 }` was "struct P
// expects 2 fields, got 1" -- a true statement that named neither the real
// mistake nor the line it was on.
func TestARepeatedFieldNameIsRefusedWhereItWasWritten(t *testing.T) {
	for _, tc := range []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "a declaration naming one field twice",
			input: "struct P { a; a; };",
			want:  "struct P declares field a twice",
		},
		{
			name:  "a declaration naming one field twice among others",
			input: "struct P { a; b; a; };",
			want:  "struct P declares field a twice",
		},
		{
			name:  "a literal setting one field twice",
			input: "struct P { a; }; P { a: 1, a: 2 };",
			want:  "struct P sets field a twice",
		},
		{
			name:  "a literal setting one field twice and missing another",
			input: "struct P { a; b; }; P { a: 1, a: 2 };",
			want:  "struct P sets field a twice",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := compileProgram(t, tc.input)
			if err == nil {
				t.Fatalf("%s compiled", tc.input)
			}
			if err.Error() != tc.want {
				t.Errorf("refusal = %q, want %q", err, tc.want)
			}
		})
	}
}

// A correct literal still compiles however it is written, which is the thing the
// both-directions report could most easily have broken.
func TestACorrectStructLiteralStillCompiles(t *testing.T) {
	for _, input := range []string{
		"struct P { a; b; }; P { a: 1, b: 2 };",
		"struct P { a; b; }; P { b: 2, a: 1 };",
		"struct E { }; E { };",
		"struct P { a; }; P { a: P { a: 1 } };",
	} {
		if err := compileProgram(t, input); err != nil {
			t.Errorf("%s was refused: %s", input, err)
		}
	}
}

// Two modules may not declare one struct name, but they may each bind a value
// name. structBindingKey is what keeps module A's `let p = P{..}` from deciding
// what module B's own `p` is, and this is the unit that pins it.
func TestStructBindingsAreScopedToTheModuleThatBoundThem(t *testing.T) {
	c := New()
	c.structBindings["modA\x00p"] = "P"

	if _, tracked := c.structTypeOfBinding("p"); tracked {
		t.Fatal("a binding recorded for another module was read from this one")
	}
}
