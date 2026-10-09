package ast

import (
	"mutant/token"
	"testing"
)

func TestString(t *testing.T) {
	program := &Program{
		Statements: []Statement{
			&LetStatement{
				Token: token.Token{Type: token.LET, Literal: "let"},
				Name: &Identifier{
					Token: token.Token{Type: token.IDENT, Literal: "myVar"},
					Value: "myVar",
				},
				Value: &Identifier{
					Token: token.Token{Type: token.IDENT, Literal: "anotherVar"},
					Value: "anotherVar",
				},
			},
		},
	}

	if program.String() != "let myVar = anotherVar;" {
		t.Errorf("program.String() wrong. got=%q", program.String())
	}
}

// TestCallExpressionStringNilSafe keeps what this test was for -- String() does
// not panic on a nil child -- and moves what it expected.
//
// It wanted "(x)", which is the silent drop: a call whose function is missing
// and whose first argument is missing rendered as a complete one-argument call
// of something unnamed, and nothing in that text said otherwise. Printing the
// marker is the other half of M26-LEX-010: the panic was the half that was
// noticed, because it killed the language server, and this was the half that
// quietly answered the wrong shape to whoever printed a tree.
func TestCallExpressionStringNilSafe(t *testing.T) {
	call := &CallExpression{
		Token: token.Token{Type: token.LPAREN, Literal: "("},
		Arguments: []Expression{
			nil,
			&Identifier{Token: token.Token{Type: token.IDENT, Literal: "x"}, Value: "x"},
		},
	}

	const want = "<missing>(<missing>, x)"
	if got := call.String(); got != want {
		t.Fatalf("CallExpression.String() = %q, want %q", got, want)
	}
}
