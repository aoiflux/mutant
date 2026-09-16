package analyzer

import (
	"strings"
	"testing"
)

// The editor's view of L-5. A bitwise expression is always an int when it
// produces a value at all -- there is no float promotion to model, the way
// arithmetic has -- so hover, inlay hints and completion can say so.
func TestBitwiseExpressionsAreTypedAsInt(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want string
	}{
		{"and", "let x = 12 & 10;", "int"},
		{"or", "let x = 12 | 10;", "int"},
		{"xor", "let x = 12 ^ 10;", "int"},
		{"shift left", "let x = 1 << 4;", "int"},
		{"shift right", "let x = 256 >> 4;", "int"},
		{"complement", "let x = ~5;", "int"},
		{"mask of a bound int", "let f = 12;\nlet x = f & 3;", "int"},

		// A known non-integer operand means the expression errors at runtime.
		// Any is the honest type for something that will not yield a value --
		// claiming `int` there would put a wrong type in the hover card.
		{"float operand", "let x = 1.5 & 1;", ""},
		{"string operand", "let x = \"a\" & 1;", ""},
		{"float complement", "let x = ~1.5;", ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			line := uint32(0)
			if tc.name == "mask of a bound int" {
				line = 1
			}
			got := typeAt(t, tc.src, line, 4)
			if tc.want == "" {
				if got == "int" {
					t.Fatalf("inferred %q for %q; a non-integer operand must not be typed int", got, tc.src)
				}
				return
			}
			if got != tc.want {
				t.Fatalf("inferred %q for %q, want %q", got, tc.src, tc.want)
			}
		})
	}
}

// infixType and couldBeInt directly, including the case the table above cannot
// reach: an operand whose type nothing has pinned down. An unknown operand is
// consistent with being an integer, so the result is still int -- a hint on a
// mask expression is worth more than a shrug.
func TestBitwiseInfixTypeRules(t *testing.T) {
	tInt := Type{Kind: TypeInt}
	tFloat := Type{Kind: TypeFloat}

	for _, op := range []string{"&", "|", "^", "<<", ">>"} {
		if got := infixType(op, tInt, tInt); got.Kind != TypeInt {
			t.Errorf("int %s int inferred as %s, want int", op, got)
		}
		if got := infixType(op, tInt, AnyType); got.Kind != TypeInt {
			t.Errorf("int %s any inferred as %s, want int", op, got)
		}
		if got := infixType(op, tFloat, tInt); got.Kind != TypeAny {
			t.Errorf("float %s int inferred as %s, want any", op, got)
		}
	}
}

// The parameter solver reads its operand domains off the VM. `&` and its family
// admit integers and nothing else, so a parameter used as a mask is an int --
// which is what makes the hover card for `fn(flags)` say something useful. The
// arithmetic operators cannot narrow that far: they admit FLOAT too.
func TestSolverNarrowsABitwiseOperandToInteger(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "a flag test",
			src:  "let can = fn(flags) { return (flags & 4) != 0; };",
			want: "can(flags: INTEGER)",
		},
		{
			name: "a shift",
			src:  "let hi = fn(n) { return n >> 8; };",
			want: "hi(n: INTEGER)",
		},
		{
			name: "both operands of an or",
			src:  "let both = fn(a, b) { return a | b; };",
			want: "both(a: INTEGER, b: INTEGER)",
		},
		{
			name: "the complement",
			src:  "let inv = fn(n) { return ~n; };",
			want: "inv(n: INTEGER)",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if card := cardFor(t, test.src); !strings.Contains(card, test.want) {
				t.Errorf("card does not contain %q:\n%s", test.want, card)
			}
		})
	}
}
