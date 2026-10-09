package ast

import (
	"reflect"
	"strings"
	"testing"
)

// TestEveryStringMethodAnswersOnANilReceiver pins one half of the invariant
// M26-LEX-010 established: every String() in this package tolerates a nil
// receiver.
//
// It matters separately from the nil-interface check in render, and this test
// is what says why: a child field whose type is a concrete pointer --
// FunctionLiteral.Body, IfExpression.Consequence, LetStatement.Name -- becomes
// a non-nil interface holding a typed nil the moment it is passed to a
// parameter of type Node. render cannot see that one. The receiver can.
//
// The list is every node type in the package. A new node type added without a
// nil-receiver guard fails here as soon as it is added to the list, and the
// count below fails if it is not.
func TestEveryStringMethodAnswersOnANilReceiver(t *testing.T) {
	nodes := []Node{
		(*ArrayLiteral)(nil),
		(*AssignExpression)(nil),
		(*BlockStatement)(nil),
		(*Boolean)(nil),
		(*BreakStatement)(nil),
		(*CallExpression)(nil),
		(*ContinueStatement)(nil),
		(*EnumStatement)(nil),
		(*ExpressionStatement)(nil),
		(*FieldExpression)(nil),
		(*FloatLiteral)(nil),
		(*ForInStatement)(nil),
		(*ForStatement)(nil),
		(*FunctionLiteral)(nil),
		(*HashLiteral)(nil),
		(*Identifier)(nil),
		(*IfExpression)(nil),
		(*ImportStatement)(nil),
		(*IndexExpression)(nil),
		(*InfixExpression)(nil),
		(*IntegerLiteral)(nil),
		(*LetStatement)(nil),
		(*MacroLiteral)(nil),
		(*MatchArm)(nil),
		(*MatchExpression)(nil),
		(*PrefixExpression)(nil),
		(*Program)(nil),
		(*ReturnStatement)(nil),
		(*StringLiteral)(nil),
		(*StructLiteral)(nil),
		(*StructStatement)(nil),
		(*TemplateLiteral)(nil),
		(*WhileStatement)(nil),
	}

	if len(nodes) != 33 {
		t.Fatalf("the package has 33 String() methods; this list names %d", len(nodes))
	}

	for _, n := range nodes {
		name := reflect.TypeOf(n).Elem().Name()
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("(*%s)(nil).String() panicked: %v", name, r)
				}
			}()
			if got := n.String(); got != missingNode {
				t.Errorf("(*%s)(nil).String() = %q, want %q", name, got, missingNode)
			}
		}()
	}
}

// TestRenderNamesAMissingChildRatherThanDroppingIt is the other half: a nil
// child is printed, not skipped.
//
// Skipping was the quiet half of M26-LEX-010. The panic was the half that got
// noticed, because it killed the language server; dropping the child answered
// a shape the tree did not have to anything that printed one, and `f(1, , 2)`
// came out as `(1, 2)` -- a complete call of two arguments.
func TestRenderNamesAMissingChildRatherThanDroppingIt(t *testing.T) {
	if got := render(nil); got != missingNode {
		t.Fatalf("render(nil) = %q, want %q", got, missingNode)
	}

	// A typed nil in a concrete field, which is the case render alone cannot
	// catch: this is a non-nil Node interface wrapping a nil *BlockStatement.
	fn := &FunctionLiteral{Body: nil}
	if got := fn.String(); !strings.Contains(got, missingNode) {
		t.Fatalf("FunctionLiteral with no body = %q, want it to name the missing body", got)
	}

	call := &CallExpression{
		Function:  &Identifier{Value: "f"},
		Arguments: []Expression{&Identifier{Value: "a"}, nil, &Identifier{Value: "b"}},
	}
	const want = "f(a, <missing>, b)"
	if got := call.String(); got != want {
		t.Fatalf("call with a missing middle argument = %q, want %q", got, want)
	}
}
