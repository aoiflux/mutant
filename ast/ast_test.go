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

func TestCallExpressionStringNilSafe(t *testing.T) {
	call := &CallExpression{
		Token: token.Token{Type: token.LPAREN, Literal: "("},
		Arguments: []Expression{
			nil,
			&Identifier{Token: token.Token{Type: token.IDENT, Literal: "x"}, Value: "x"},
		},
	}

	if got := call.String(); got != "(x)" {
		t.Fatalf("CallExpression.String() = %q, want %q", got, "(x)")
	}
}
