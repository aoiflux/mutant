package evaluator

import (
	"bytes"

	"mutant/ast"
	"mutant/object"
)

func evalExpressions(exps []ast.Expression, env *object.Environment) []object.Object {
	var result []object.Object

	for _, e := range exps {
		evaluated := Eval(e, env)
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
	default:
		return newError("unknown operator: %s%s", operator, right.Type())
	}
}

func evalBangOperatorExpression(right object.Object) object.Object {
	switch right.Inspect() {
	case TRUE.Inspect():
		return FALSE
	case FALSE.Inspect():
		return TRUE
	case NULL.Inspect():
		return TRUE
	default:
		return FALSE
	}
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
	switch {
	case object.IsNumeric(left) && object.IsNumeric(right):
		// Numeric arithmetic/comparison is shared with the WASM REPL via
		// object.NumericInfix so the two tree-walking interpreters can't drift.
		return object.NumericInfix(operator, left, right)
	// Bytes are compared before the Inspect fallback below, which would
	// otherwise make a buffer equal to the string spelling its own hex.
	case left.Type() == object.BYTES_OBJ || right.Type() == object.BYTES_OBJ:
		return evalBytesInfixExpression(operator, left, right)
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
	return &object.Bytes{Value: joined}
}

func evalIfExpression(node *ast.IfExpression, env *object.Environment) object.Object {
	condition := Eval(node.Condition, env)
	if isError(condition) {
		return condition
	}
	if isTruthy(condition) {
		return Eval(node.Consequence, env)
	} else if node.Alternative != nil {
		return Eval(node.Alternative, env)
	}

	return NULL
}

func evalArrayIndexExpression(array, index object.Object) object.Object {
	arrayObject := array.(*object.Array)
	idx := index.(*object.Integer).Value
	max := int64(len(arrayObject.Elements) - 1)
	if idx < 0 || idx > max {
		return NULL
	}
	return arrayObject.Elements[idx]
}

func evalMultiValueIndexExpression(multiValue, index object.Object) object.Object {
	multi := multiValue.(*object.MultiValue)
	idx := index.(*object.Integer).Value
	max := int64(len(multi.Values) - 1)
	if idx < 0 || idx > max {
		return NULL
	}
	return multi.Values[idx]
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
//
// The evaluator has never indexed strings -- the VM does, and that divergence
// predates this type. Implementing bytes indexing in both engines is what stops
// the new type from inheriting it.
func evalBytesIndexExpression(buf, index object.Object) object.Object {
	data := buf.(*object.Bytes).Value
	i := index.(*object.Integer).Value
	max := int64(len(data) - 1)

	if i > max {
		return NULL
	}
	if i < 0 {
		if max+i+1 < 0 {
			return NULL
		}
		return &object.Integer{Value: int64(data[max+i+1])}
	}
	return &object.Integer{Value: int64(data[i])}
}
