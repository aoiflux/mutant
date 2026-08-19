package object

import (
	"fmt"
	"math"
)

// This file is the single source of truth for numeric infix-operator semantics,
// shared by the tree-walking evaluator and the WASM web REPL so their operator
// sets can never drift apart. The compiler/VM implements the same semantics over
// opcodes (see vm/vm.go execBinary{Integer,Float}Operation and
// exec{Integer,Float}Comparison); parity/parity_test.go asserts all three agree.

// IsNumeric reports whether an object participates in numeric arithmetic
// (INTEGER or FLOAT).
func IsNumeric(o Object) bool {
	return o != nil && (o.Type() == INTEGER_OBJ || o.Type() == FLOAT_OBJ)
}

func numericToFloat(o Object) float64 {
	if o.Type() == INTEGER_OBJ {
		return float64(o.(*Integer).Value)
	}
	return o.(*Float).Value
}

// NumericInfix evaluates an arithmetic or comparison operator on two numeric
// operands. Callers must ensure both operands satisfy IsNumeric. INTEGER op
// INTEGER yields an INTEGER (division/modulo by zero yield an *Error); if either
// operand is a FLOAT both are promoted to float64. Comparison operators yield a
// BOOLEAN. An unsupported operator yields an *Error.
func NumericInfix(operator string, left, right Object) Object {
	if left.Type() == INTEGER_OBJ && right.Type() == INTEGER_OBJ {
		return integerInfix(operator, left.(*Integer).Value, right.(*Integer).Value)
	}
	return floatInfix(operator, numericToFloat(left), numericToFloat(right))
}

func infixBool(b bool) *Boolean  { return &Boolean{Value: b} }
func infixError(msg string) *Error { return &Error{Message: msg} }

func integerInfix(operator string, l, r int64) Object {
	switch operator {
	case "+":
		return &Integer{Value: l + r}
	case "-":
		return &Integer{Value: l - r}
	case "*":
		return &Integer{Value: l * r}
	case "/":
		if r == 0 {
			return infixError("integer division by zero")
		}
		return &Integer{Value: l / r}
	case "%":
		if r == 0 {
			return infixError("integer modulo by zero")
		}
		return &Integer{Value: l % r}
	case "<":
		return infixBool(l < r)
	case ">":
		return infixBool(l > r)
	case "<=":
		return infixBool(l <= r)
	case ">=":
		return infixBool(l >= r)
	case "==":
		return infixBool(l == r)
	case "!=":
		return infixBool(l != r)
	default:
		return infixError(fmt.Sprintf("unknown operator: INTEGER %s INTEGER", operator))
	}
}

func floatInfix(operator string, l, r float64) Object {
	switch operator {
	case "+":
		return &Float{Value: l + r}
	case "-":
		return &Float{Value: l - r}
	case "*":
		return &Float{Value: l * r}
	case "/":
		return &Float{Value: l / r}
	case "%":
		return &Float{Value: math.Mod(l, r)}
	case "<":
		return infixBool(l < r)
	case ">":
		return infixBool(l > r)
	case "<=":
		return infixBool(l <= r)
	case ">=":
		return infixBool(l >= r)
	case "==":
		return infixBool(l == r)
	case "!=":
		return infixBool(l != r)
	default:
		return infixError(fmt.Sprintf("unknown operator: FLOAT %s FLOAT", operator))
	}
}
