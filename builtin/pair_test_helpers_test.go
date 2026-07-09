package builtin

import (
	"testing"

	"mutant/object"
)

func unwrapPair(t *testing.T, value object.Object) (object.Object, *object.Error) {
	t.Helper()

	pair, ok := value.(*object.MultiValue)
	if !ok {
		t.Fatalf("builtin result is not MultiValue. got=%T", value)
	}
	if len(pair.Values) != 2 {
		t.Fatalf("builtin pair arity mismatch. got=%d, want=2", len(pair.Values))
	}

	result := pair.Values[0]
	errValue := pair.Values[1]

	if errValue == nil {
		return result, nil
	}
	if errValue.Type() == object.NULL_OBJ {
		return result, nil
	}

	errObj, ok := errValue.(*object.Error)
	if !ok {
		t.Fatalf("builtin error slot must be Error or Null. got=%T", errValue)
	}
	return result, errObj
}
