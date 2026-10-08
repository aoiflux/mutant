package evaluator

import (
	"bytes"

	"mutant/ast"
	"mutant/object"
)

func evalExpressions(exps []ast.Expression, env *object.Environment) []object.Object {
	var result []object.Object

	for _, e := range exps {
		evaluated := eval(e, env)
		if isError(evaluated) {
			return []object.Object{evaluated}
		}
		result = append(result, evaluated)
	}

	return result
}

func evalPrefixExpression(operator string, right object.Object) object.Object {
	switch operator {
	case "!":
		return evalBangOperatorExpression(right)
	case "-":
		return evalMinusPrefixOperatorExpression(right)
	case "~":
		// object.BitwiseNot rather than a local switch: the VM calls the same
		// function, so the complement and its error message cannot drift.
		return object.BitwiseNot(right)
	default:
		return newError("unknown operator: %s%s", operator, right.Type())
	}
}

// evalBangOperatorExpression is the tree-walker's `!`, and it answers exactly what
// the VM's execBangOperation answers, because both ask object.IsTruthy.
//
// It used to switch on right.Inspect() against TRUE, FALSE and NULL's renderings,
// and a rendering is not an identity. object.Null renders as the EMPTY STRING, so
// the NULL arm caught `""` as well -- the right answer, by accident, and the reason
// this engine looked correct on the one value the VM got most visibly wrong. The
// FALSE arm caught the string "false", which is a non-empty string and therefore
// truthy, so `!"false"` was true here and false in the VM. 0 and 0.0 matched
// nothing and fell through to false, as in the VM.
//
// evalInfixExpression in this file already refuses to compare renderings -- for
// buffers, errors and enum values -- and says why. `!` was left on Inspect.
//
// A nil operand reached right.Inspect() and panicked; object.IsTruthy answers false
// for it, and applyFunction no longer produces one. See M26-VM-007, M26-EVL-020.
func evalBangOperatorExpression(right object.Object) object.Object {
	return nativeBoolToBoolObject(!object.IsTruthy(right))
}

func evalMinusPrefixOperatorExpression(right object.Object) object.Object {
	switch right.Type() {
	case object.INTEGER_OBJ:
		return &object.Integer{Value: -right.(*object.Integer).Value}
	case object.FLOAT_OBJ:
		return &object.Float{Value: -right.(*object.Float).Value}
	default:
		return newError("unknown operator: -%s", right.Type())
	}
}

func evalInfixExpression(operator string, left, right object.Object) object.Object {
	// Bitwise operators are integer-only. This check comes first so the refusal
	// is worded identically for every operand type -- NumericInfix only ever
	// sees the numeric ones, and a string would otherwise be turned away by
	// evalStringInfixExpression with a different sentence than the VM uses.
	if object.IsBitwiseOperator(operator) &&
		(left.Type() != object.INTEGER_OBJ || right.Type() != object.INTEGER_OBJ) {
		return object.BitwiseOperandError(operator, left, right)
	}

	switch {
	case object.IsNumeric(left) && object.IsNumeric(right):
		// Numeric arithmetic/comparison is shared with the WASM REPL via
		// object.NumericInfix so the two tree-walking interpreters can't drift.
		return object.NumericInfix(operator, left, right)
	// Bytes are compared before the Inspect fallback below, which would
	// otherwise make a buffer equal to the string spelling its own hex.
	case left.Type() == object.BYTES_OBJ || right.Type() == object.BYTES_OBJ:
		return evalBytesInfixExpression(operator, left, right)
	// Errors likewise: the Inspect fallback renders a position this engine
	// never stamps, so comparing rendered forms would answer differently here
	// than in the VM. object.Error.Equals is what both engines ask.
	case left.Type() == object.ERROR_OBJ || right.Type() == object.ERROR_OBJ:
		return evalErrorInfixExpression(operator, left, right)
	// Enum values, for the same reason as bytes: an enum renders as
	// `Status.Ok(0)`, so under the fallback a string spelling that text was
	// equal to the variant itself. Mirrors the VM's execEnumComparison.
	case left.Type() == object.ENUM_VALUE_OBJ || right.Type() == object.ENUM_VALUE_OBJ:
		return evalEnumInfixExpression(operator, left, right)
	// Structs, for the same reason: a struct renders as `P { b: 2, a: 1 }`, so
	// under the fallback a string spelling that text was equal to the record.
	// Mirrors the VM's execStructComparison.
	case left.Type() == object.STRUCT_OBJ || right.Type() == object.STRUCT_OBJ:
		return evalStructInfixExpression(operator, left, right)
	case operator == "==":
		return nativeBoolToBoolObject(left.Inspect() == right.Inspect())
	case operator == "!=":
		return nativeBoolToBoolObject(left.Inspect() != right.Inspect())
	case left.Type() != right.Type():
		return newError("type mismatch: %s%s%s", left.Type(), operator, right.Type())
	case (left.Type() == object.STRING_OBJ) && (right.Type() == object.STRING_OBJ):
		return evalStringInfixExpression(operator, left, right)
	default:
		return newError("unknown operator: %s%s%s", left.Type(), operator, right.Type())
	}
}

func evalStringInfixExpression(operator string, left, right object.Object) object.Object {
	if operator != "+" {
		return newError("unknown operator: %s%s%s", left.Type(), operator, right.Type())
	}
	lval := left.(*object.String).Value
	rval := right.(*object.String).Value
	return &object.String{Value: lval + rval}
}

// evalEnumInfixExpression handles every operator with an enum value on either
// side. Only `==` and `!=` are defined; two variants are equal when they are
// the same variant of the same enum, and an enum value is never equal to a
// value of another type. This mirrors the VM's execEnumComparison.
func evalEnumInfixExpression(operator string, left, right object.Object) object.Object {
	leftEnum, leftOK := left.(*object.EnumValue)
	rightEnum, rightOK := right.(*object.EnumValue)
	equal := leftOK && rightOK &&
		leftEnum.TypeName == rightEnum.TypeName &&
		leftEnum.Tag == rightEnum.Tag

	switch operator {
	case "==":
		return nativeBoolToBoolObject(equal)
	case "!=":
		return nativeBoolToBoolObject(!equal)
	}
	return newError("unknown operator: %s%s%s", left.Type(), operator, right.Type())
}

// evalStructInfixExpression handles every operator with a struct on either
// side. Only `==` and `!=` are defined; two structs are equal when they are the
// same type and every field holds an equal value, and a struct is never equal
// to a value of another type. This mirrors the VM's execStructComparison.
func evalStructInfixExpression(operator string, left, right object.Object) object.Object {
	leftStruct, leftOK := left.(*object.Struct)
	rightStruct, rightOK := right.(*object.Struct)
	equal := leftOK && rightOK && leftStruct.Equals(rightStruct)

	switch operator {
	case "==":
		return nativeBoolToBoolObject(equal)
	case "!=":
		return nativeBoolToBoolObject(!equal)
	}
	return newError("unknown operator: %s%s%s", left.Type(), operator, right.Type())
}

// evalMatchArmBody answers null when
// the body computed nothing -- a body ending in a `let`, a `for`, or nothing at
// all. eval of such a block returns Go nil, and a match is an expression, so
// returning that would hand a nil object.Object to whatever consumed the match.
// The VM reaches the same answer by emitting OpNull for the same shape of body.
// The arm's own scope is now the block's -- evalBlockStatement opens one for
// every block -- so this no longer encloses one itself. Enclosing twice was
// harmless but said that an arm's scope was special, and it is not: an arm is a
// block, which is what Go's case clauses are.
func evalMatchArmBody(arm *ast.MatchArm, env *object.Environment) object.Object {
	result := eval(arm.Body, env)
	if result == nil {
		return NULL
	}
	return result
}

// evalMatchExpression evaluates the subject once, then walks the arms in source
// order taking the first whose pattern equals it. Equality is the language's
// own `==` -- an arm means exactly what the comparison the author would have
// written by hand means.
//
// No arm matching is an error naming the value, matching the VM's OpMatchFail.
// A match is an expression, so returning null instead would flow on as though
// some arm had produced it.
func evalMatchExpression(node *ast.MatchExpression, env *object.Environment) object.Object {
	subject := eval(node.Subject, env)
	if isError(subject) {
		return subject
	}

	for _, arm := range node.Arms {
		if arm == nil || arm.Body == nil {
			continue
		}

		if arm.IsWildcard() {
			return evalMatchArmBody(arm, env)
		}

		for _, pattern := range arm.Patterns {
			value := eval(pattern, env)
			if isError(value) {
				return value
			}

			matched := evalInfixExpression("==", subject, value)
			if isError(matched) {
				return matched
			}
			if object.IsTruthy(matched) {
				return evalMatchArmBody(arm, env)
			}
		}
	}

	rendered := "null"
	if subject != nil {
		rendered = subject.Inspect()
	}
	return newError("no match arm matched %s", rendered)
}

// evalErrorInfixExpression handles every operator with an error on either side.
// Only `==` and `!=` are defined, and only two errors can be equal. This mirrors
// the VM's execErrorComparison; parity/ asserts they agree, which is the whole
// reason it exists -- the Inspect fallback would have answered differently in
// each engine because only one of them stamps a position.
func evalErrorInfixExpression(operator string, left, right object.Object) object.Object {
	leftErr, leftOK := left.(*object.Error)
	rightErr, rightOK := right.(*object.Error)
	equal := leftOK && rightOK && leftErr.Equals(rightErr)

	switch operator {
	case "==":
		return nativeBoolToBoolObject(equal)
	case "!=":
		return nativeBoolToBoolObject(!equal)
	}
	return newError("unknown operator: %s%s%s", left.Type(), operator, right.Type())
}

// evalBytesInfixExpression handles every operator with a bytes on either side:
// `+` concatenates two buffers, `==` and `!=` compare their contents, and a
// bytes is never equal to a value of another type. This mirrors the VM's
// execBinaryBytesOperation and execBytesComparison; parity/ asserts they agree.
func evalBytesInfixExpression(operator string, left, right object.Object) object.Object {
	leftBytes, leftOK := left.(*object.Bytes)
	rightBytes, rightOK := right.(*object.Bytes)

	switch operator {
	case "==":
		return nativeBoolToBoolObject(leftOK && rightOK && bytes.Equal(leftBytes.Value, rightBytes.Value))
	case "!=":
		return nativeBoolToBoolObject(!(leftOK && rightOK && bytes.Equal(leftBytes.Value, rightBytes.Value)))
	}

	if !leftOK || !rightOK {
		return newError("type mismatch: %s%s%s", left.Type(), operator, right.Type())
	}
	if operator != "+" {
		return newError("unknown operator: %s%s%s", left.Type(), operator, right.Type())
	}

	joined := make([]byte, 0, len(leftBytes.Value)+len(rightBytes.Value))
	joined = append(joined, leftBytes.Value...)
	joined = append(joined, rightBytes.Value...)
	// As in the VM: classified plaintext joined to anything is still
	// classified plaintext.
	return &object.Bytes{Value: joined,
		Classified: object.JoinClassification(leftBytes.Classified, rightBytes.Classified)}
}

func evalIfExpression(node *ast.IfExpression, env *object.Environment) object.Object {
	condition := eval(node.Condition, env)
	if isError(condition) {
		return condition
	}
	if object.IsTruthy(condition) {
		return evalBranchValue(node.Consequence, env)
	} else if node.Alternative != nil {
		return evalBranchValue(node.Alternative, env)
	}

	return NULL
}

// evalBranchValue runs one branch of a value-producing expression and answers
// null when the branch computed nothing -- a branch ending in a `let`, a loop,
// or nothing at all. eval of such a block returns Go nil, and an `if` is an
// expression here, so returning that would hand a nil object.Object to whatever
// consumed the `if`. The VM reaches the same answer by emitting OpNull for the
// same shape of branch.
func evalBranchValue(branch *ast.BlockStatement, env *object.Environment) object.Object {
	result := eval(branch, env)
	if result == nil {
		return NULL
	}
	return result
}

func evalArrayIndexExpression(array, index object.Object) object.Object {
	elements := array.(*object.Array).Elements
	at, ok := object.IndexOf(index.(*object.Integer).Value, len(elements))
	if !ok {
		return NULL
	}
	return elements[at]
}

func evalMultiValueIndexExpression(multiValue, index object.Object) object.Object {
	multi := multiValue.(*object.MultiValue)
	at, ok := object.IndexOf(index.(*object.Integer).Value, len(multi.Values))
	if !ok {
		return NULL
	}
	return multi.Values[at]
}

func evalHashIndexExpression(hash, index object.Object) object.Object {
	hashObject := hash.(*object.Hash)
	key, ok := index.(object.Hashable)
	if !ok {
		return newError("unusable as hash key: %s", index.Type())
	}
	pair, ok := hashObject.Pairs[key.HashKey()]
	if !ok {
		return NULL
	}
	return pair.Value
}

func evalIndexExpression(left, index object.Object) object.Object {
	switch {
	case left.Type() == object.ARRAY_OBJ && index.Type() == object.INTEGER_OBJ:
		return evalArrayIndexExpression(left, index)
	case left.Type() == object.MULTI_VALUE_OBJ && index.Type() == object.INTEGER_OBJ:
		return evalMultiValueIndexExpression(left, index)
	case left.Type() == object.BYTES_OBJ && index.Type() == object.INTEGER_OBJ:
		return evalBytesIndexExpression(left, index)
	case left.Type() == object.STRING_OBJ && index.Type() == object.INTEGER_OBJ:
		return evalStringIndexExpression(left, index)
	case left.Type() == object.HASH_OBJ:
		return evalHashIndexExpression(left, index)
	case left.Type() == object.ERROR_OBJ && index.Type() == object.STRING_OBJ:
		return evalErrorFieldIndexExpression(left, index)
	default:
		return newError("index operator not supported: %s", left.Type())
	}
}

// evalErrorFieldIndexExpression reads err["message"] through object.Error.Field,
// the same table err.message reads, matching the VM's execErrorField. An unknown
// name is null rather than an error: a program probing whether a field carries
// anything should not have to know which build it is running on.
func evalErrorFieldIndexExpression(errObj, index object.Object) object.Object {
	val, ok := errObj.(*object.Error).Field(index.(*object.String).Value)
	if !ok {
		return NULL
	}
	return val
}

// evalBytesIndexExpression yields the byte at i as an INTEGER 0-255, matching
// the VM's execBytesIndex.
func evalBytesIndexExpression(buf, index object.Object) object.Object {
	data := buf.(*object.Bytes).Value
	at, ok := object.IndexOf(index.(*object.Integer).Value, len(data))
	if !ok {
		return NULL
	}
	return &object.Integer{Value: int64(data[at])}
}

// evalStringIndexExpression yields the rune at i as a one-rune string, matching
// the VM's execStringIndex.
//
// This engine did not index strings at all until now: `s[0]` was "index operator
// not supported: STRING" here and a value in the VM, so one of the two was wrong
// about a program either way. It is not dead code -- this is the engine that
// computes unquote(...) during macro expansion -- and a divergence this wide is
// worth more than the one line it costs to close.
func evalStringIndexExpression(str, index object.Object) object.Object {
	char, ok := object.RuneAt(str.(*object.String).Value, index.(*object.Integer).Value)
	if !ok {
		return NULL
	}
	return &object.String{Value: char}
}
