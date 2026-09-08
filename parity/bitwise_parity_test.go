package parity

import (
	"strings"
	"testing"

	"mutant/object"
)

// L-5 added `& | ^ ~ << >>` and their compound assignment forms. The roadmap's
// done_when is that they "match Go semantics", so this table is written against
// Go: every expected value below is what the same expression evaluates to in
// Go with int64 operands.
//
// Both engines are asserted against the value, not merely against each other.
// Agreeing on a wrong answer is the failure mode a pure parity test cannot see,
// and the whole reason bitwise arithmetic is worth testing is that a
// sign-extension or shift-width mistake produces a plausible wrong number
// rather than an error.
func TestBitwiseOperatorSemantics(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		// and / or / xor
		{"12 & 10", "INTEGER(8)"},
		{"12 | 10", "INTEGER(14)"},
		{"12 ^ 10", "INTEGER(6)"},
		{"0 & 5", "INTEGER(0)"},
		{"0 | 5", "INTEGER(5)"},
		{"5 ^ 5", "INTEGER(0)"},

		// Negative operands are two's complement, because the VM's integers are
		// signed int64. -5 is ...11111011, so masking off the low two bits
		// leaves 3 -- not the 1 an unsigned reading would give.
		{"-5 & 3", "INTEGER(3)"},
		{"-1 & 255", "INTEGER(255)"},
		{"-2 | 1", "INTEGER(-1)"},
		{"-1 ^ -1", "INTEGER(0)"},

		// Shifts
		{"1 << 4", "INTEGER(16)"},
		{"256 >> 4", "INTEGER(16)"},
		{"5 >> 1", "INTEGER(2)"},
		{"7 >> 10", "INTEGER(0)"},
		{"0 << 10", "INTEGER(0)"},

		// `>>` is arithmetic: the sign bit is replicated. -8 >> 1 is -4, and
		// -1 stays -1 no matter how far it is shifted. A logical shift would
		// answer 9223372036854775804 and 9223372036854775807 here.
		{"-8 >> 1", "INTEGER(-4)"},
		{"-1 >> 63", "INTEGER(-1)"},
		{"-1 >> 62", "INTEGER(-1)"},

		// Shift counts of 64 and beyond are defined, not errors: Go shifts by
		// one that many times, so the value falls off the end.
		{"1 << 63", "INTEGER(-9223372036854775808)"},
		{"1 << 64", "INTEGER(0)"},
		{"1 << 100", "INTEGER(0)"},
		{"-1 >> 64", "INTEGER(-1)"},
		{"255 >> 100", "INTEGER(0)"},

		// Complement
		{"~0", "INTEGER(-1)"},
		{"~5", "INTEGER(-6)"},
		{"~-1", "INTEGER(0)"},
		{"~~7", "INTEGER(7)"},

		// Precedence, evaluated rather than merely parsed. `&` beats `==`, so
		// this is (12 & 4) != 0 and not 12 & (4 != 0), which would not even
		// have a type.
		{"12 & 4 == 4", "BOOLEAN(true)"},
		{"12 & 3 == 0", "BOOLEAN(true)"},
		{"1 << 2 + 1", "INTEGER(5)"},
		// `|` and `+` share a precedence level in Go, so this is `(1 | 2) + 1`,
		// left to right -- 4, not the 3 that reading `+` as tighter would give.
		{"1 | 2 + 1", "INTEGER(4)"},
		{"~3 & 15", "INTEGER(12)"},

		// The three real uses the roadmap named: a mask, a flag test, a shift.
		{"let flags = 12; (flags & 4) != 0", "BOOLEAN(true)"},
		{"let flags = 12; (flags & 2) != 0", "BOOLEAN(false)"},
		{"let b = 0; b = b | 4; b = b | 1; b", "INTEGER(5)"},
		{"let b = 7; b & ~2", "INTEGER(5)"},

		// Compound assignment, which desugars to `x = x op v`.
		{"let x = 12; x &= 10; x", "INTEGER(8)"},
		{"let x = 12; x |= 3; x", "INTEGER(15)"},
		{"let x = 12; x ^= 10; x", "INTEGER(6)"},
		{"let x = 1; x <<= 5; x", "INTEGER(32)"},
		{"let x = 64; x >>= 3; x", "INTEGER(8)"},
		{"let x = 1; x <<= 1; x <<= 1; x", "INTEGER(4)"},

		// Compound assignment through the other two lvalues.
		{"let a = [1, 2]; a[0] |= 6; a[0]", "INTEGER(7)"},
		{"let a = [8]; a[0] >>= 2; a[0]", "INTEGER(2)"},

		// Inside a function, so the local-slot path is covered too.
		{"let f = fn(x) { x & 0 }; f(9)", "INTEGER(0)"},
		{"let f = fn(x, n) { x << n }; f(3, 4)", "INTEGER(48)"},
		{"let f = fn(x) { let m = x; m |= 8; m }; f(1)", "INTEGER(9)"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			evaluated := normalize(evalViaEvaluator(tt.input))

			vmObj, vmErr := evalViaVM(t, tt.input)
			if vmErr != nil {
				t.Fatalf("VM refused %q: %v (evaluator gave %s)", tt.input, vmErr, evaluated)
			}
			compiled := normalize(vmObj)

			if evaluated != compiled {
				t.Fatalf("engines disagree on %q: evaluator %s, VM %s", tt.input, evaluated, compiled)
			}
			if evaluated != tt.want {
				t.Fatalf("both engines answered %s for %q, want %s", evaluated, tt.input, tt.want)
			}
		})
	}
}

// Every operand that is not an integer is refused, by both engines, with the
// same sentence. The message is asserted here rather than left to normalize()'s
// bare "ERROR" because it is the entire user-facing value of the check: a
// bitwise operator that quietly truncated a float would be the same class of
// silent wrong answer the bytes type was introduced to remove.
func TestBitwiseOperatorsRefuseNonIntegers(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"1.5 & 1", "bitwise operator & requires INTEGER operands, got FLOAT and INTEGER"},
		{"1 & 1.5", "bitwise operator & requires INTEGER operands, got INTEGER and FLOAT"},
		{"1.0 | 1", "bitwise operator | requires INTEGER operands, got FLOAT and INTEGER"},
		{"2.0 ^ 1", "bitwise operator ^ requires INTEGER operands, got FLOAT and INTEGER"},
		{"1 << 1.0", "bitwise operator << requires INTEGER operands, got INTEGER and FLOAT"},
		{"1 >> 1.0", "bitwise operator >> requires INTEGER operands, got INTEGER and FLOAT"},
		{`"a" & 1`, "bitwise operator & requires INTEGER operands, got STRING and INTEGER"},
		{`"a" & "b"`, "bitwise operator & requires INTEGER operands, got STRING and STRING"},
		{"true & 1", "bitwise operator & requires INTEGER operands, got BOOLEAN and INTEGER"},
		{"[1] | 1", "bitwise operator | requires INTEGER operands, got ARRAY and INTEGER"},

		// A negative shift count panics in Go. The VM must not: a panic on user
		// input is a crash, and a program that shifts by a computed value can
		// reach a negative one without anybody writing the minus sign.
		{"1 << -1", "negative shift count: -1"},
		{"1 >> -1", "negative shift count: -1"},
		{"let n = 0 - 2; 1 << n", "negative shift count: -2"},

		// The complement is integer-only for the same reason.
		{"~1.5", "bitwise complement requires an INTEGER, got FLOAT"},
		{`~"a"`, "bitwise complement requires an INTEGER, got STRING"},
		{"~true", "bitwise complement requires an INTEGER, got BOOLEAN"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			evaluated := evalViaEvaluator(tt.input)
			errObj, ok := evaluated.(*object.Error)
			if !ok {
				t.Fatalf("evaluator returned %s for %q, want an error", normalize(evaluated), tt.input)
			}
			if !strings.Contains(errObj.Message, tt.want) {
				t.Fatalf("evaluator said %q for %q, want %q", errObj.Message, tt.input, tt.want)
			}

			_, vmErr := evalViaVM(t, tt.input)
			if vmErr == nil {
				t.Fatalf("VM accepted %q, which the evaluator refused", tt.input)
			}
			if !strings.Contains(vmErr.Error(), tt.want) {
				t.Fatalf("VM said %q for %q, want %q", vmErr.Error(), tt.input, tt.want)
			}
		})
	}
}
