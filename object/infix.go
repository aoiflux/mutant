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
	// A bitwise operator never promotes. Falling through to floatInfix would
	// mean `mask & 1.0` quietly answered something, and there is no sensible
	// answer: the bits of a float are not the bits of the number it denotes.
	if IsBitwiseOperator(operator) &&
		(left.Type() != INTEGER_OBJ || right.Type() != INTEGER_OBJ) {
		return BitwiseOperandError(operator, left, right)
	}
	if left.Type() == INTEGER_OBJ && right.Type() == INTEGER_OBJ {
		return integerInfix(operator, left.(*Integer).Value, right.(*Integer).Value)
	}
	return floatInfix(operator, numericToFloat(left), numericToFloat(right))
}

func infixBool(b bool) *Boolean    { return &Boolean{Value: b} }
func infixError(msg string) *Error { return &Error{Message: msg} }

func integerInfix(operator string, l, r int64) Object {
	if IsBitwiseOperator(operator) {
		return BitwiseInfix(operator, l, r)
	}
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

// ---------------------------------------------------------------------------
// Bitwise operators (L-5)
//
// These live here, next to the arithmetic, because the file's whole purpose is
// that the tree-walking evaluator and the WASM REPL cannot drift. The VM does
// not share this code path -- it dispatches on opcodes -- but it calls
// BitwiseInfix and BitwiseNot for the arithmetic itself, so all three engines
// compute from one implementation and report one set of messages. parity/
// asserts that they agree.
//
// The operands are the signed 64-bit integers the VM actually has, so `>>` is
// an arithmetic shift: the sign bit is replicated, and -8 >> 1 is -4, not a
// large positive number. A logical shift would need an unsigned type the
// language does not have.

// IsBitwiseOperator reports whether operator is one of `& | ^ << >>`.
//
// It exists so callers can reject a non-integer operand *before* the numeric
// path promotes it to float: `1.5 & 1` has no meaning, and silently rounding
// or truncating to make it work is exactly the class of plausible wrong answer
// the bytes type was introduced to stop.
func IsBitwiseOperator(operator string) bool {
	switch operator {
	case "&", "|", "^", "<<", ">>":
		return true
	}
	return false
}

// BitwiseOperandError is the error every engine reports when a bitwise operator
// meets an operand that is not an INTEGER.
func BitwiseOperandError(operator string, left, right Object) *Error {
	return infixError(fmt.Sprintf(
		"bitwise operator %s requires INTEGER operands, got %s and %s",
		operator, left.Type(), right.Type(),
	))
}

// BitwiseInfix evaluates a bitwise operator over two int64s. Callers must have
// established that both operands are integers; IsBitwiseOperator and
// BitwiseOperandError are how they do that.
//
// A shift count of 64 or more is not an error: Go defines it as shifting that
// many times by one, so `1 << 64` is 0 and `-1 >> 64` is -1, and reproducing
// Go is what L-5 asked for. A *negative* count is refused, because in Go it
// panics -- and a VM that panics on user input is a denial of service, not a
// language feature.
func BitwiseInfix(operator string, l, r int64) Object {
	switch operator {
	case "&":
		return &Integer{Value: l & r}
	case "|":
		return &Integer{Value: l | r}
	case "^":
		return &Integer{Value: l ^ r}
	case "<<":
		if r < 0 {
			return infixError(fmt.Sprintf("negative shift count: %d", r))
		}
		return &Integer{Value: l << uint64(r)}
	case ">>":
		if r < 0 {
			return infixError(fmt.Sprintf("negative shift count: %d", r))
		}
		return &Integer{Value: l >> uint64(r)}
	default:
		return infixError(fmt.Sprintf("unknown bitwise operator: %s", operator))
	}
}

// BitwiseNot evaluates the unary complement `~x`. Mutant spells the complement
// `~` rather than reusing `^` the way Go does, so the two forms are distinct
// tokens and the grammar never has to decide which one it is looking at.
func BitwiseNot(operand Object) Object {
	if operand == nil || operand.Type() != INTEGER_OBJ {
		kind := "NULL"
		if operand != nil {
			kind = string(operand.Type())
		}
		return infixError(fmt.Sprintf("bitwise complement requires an INTEGER, got %s", kind))
	}
	return &Integer{Value: ^operand.(*Integer).Value}
}
