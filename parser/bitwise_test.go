package parser

import (
	"testing"

	"mutant/ast"
	"mutant/lexer"
)

func parseBitwise(t *testing.T, input string) *ast.Program {
	t.Helper()
	p := New(lexer.New(input))
	program := p.ParseProgram()
	if errs := p.Errors(); len(errs) != 0 {
		t.Fatalf("parser errors for %q: %v", input, errs)
	}
	return program
}

// Precedence is Go's, and these cases are the ones where Go and C disagree.
// `flags & MASK == 0` is the load-bearing one: in C it parses as
// `flags & (MASK == 0)` and is almost never what anybody meant.
func TestBitwiseOperatorPrecedence(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		// & binds like *, so it beats == and the additive operators.
		{"flags & mask == 0", "((flags & mask) == 0)"},
		{"a & b + c", "((a & b) + c)"},
		{"a + b & c", "(a + (b & c))"},

		// | and ^ bind like +, so they beat comparison but lose to & and shifts.
		{"a | b == c", "((a | b) == c)"},
		{"a | b & c", "(a | (b & c))"},
		{"a ^ b & c", "(a ^ (b & c))"},
		{"a | b ^ c", "((a | b) ^ c)"},
		{"a & b | c & d", "((a & b) | (c & d))"},

		// Shifts bind like *, so `a << 2 + 1` shifts by 2 and then adds --
		// the same trap, and the same answer Go gives.
		{"a << 2 + 1", "((a << 2) + 1)"},
		{"a << 1 << 2", "((a << 1) << 2)"},
		{"a >> 1 & 1", "((a >> 1) & 1)"},
		{"a * b << c", "((a * b) << c)"},

		// The complement is a prefix operator and binds tighter than any of them.
		{"~a & b", "((~a) & b)"},
		{"~a", "(~a)"},
		{"~~a", "(~(~a))"},
		{"-~a", "(-(~a))"},
		{"~(a | b)", "(~(a | b))"},

		// Shifts must not be confused with comparisons that happen to be adjacent.
		{"a < b", "(a < b)"},
		{"a << b", "(a << b)"},
		{"a >= b", "(a >= b)"},
		{"a >> b", "(a >> b)"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := parseBitwise(t, tt.input).String()
			if got != tt.expected {
				t.Fatalf("got %q, want %q", got, tt.expected)
			}
		})
	}
}

// The compound forms are sugar, exactly like `+=`: the parser records the base
// operator on the assignment and every engine evaluates `x = x op v`. If the
// base operator were dropped the assignment would silently overwrite instead of
// combining, which is a wrong answer rather than an error.
func TestCompoundBitwiseAssignmentCarriesItsBaseOperator(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"x &= 3;", "&"},
		{"x |= 3;", "|"},
		{"x ^= 3;", "^"},
		{"x <<= 3;", "<<"},
		{"x >>= 3;", ">>"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			program := parseBitwise(t, tt.input)
			if len(program.Statements) != 1 {
				t.Fatalf("got %d statements, want 1", len(program.Statements))
			}
			stmt, ok := program.Statements[0].(*ast.ExpressionStatement)
			if !ok {
				t.Fatalf("statement is %T, want *ast.ExpressionStatement", program.Statements[0])
			}
			assign, ok := stmt.Expression.(*ast.AssignExpression)
			if !ok {
				t.Fatalf("expression is %T, want *ast.AssignExpression", stmt.Expression)
			}
			if assign.Operator != tt.want {
				t.Fatalf("base operator is %q, want %q", assign.Operator, tt.want)
			}
		})
	}
}

// Compound assignment on a field and an index target, which are the two lvalues
// besides a plain identifier.
func TestCompoundBitwiseAssignmentAcceptsEveryLvalue(t *testing.T) {
	for _, input := range []string{"p.flags |= 4;", "a[0] &= 1;", "a[i] <<= 2;"} {
		t.Run(input, func(t *testing.T) {
			parseBitwise(t, input)
		})
	}
}
