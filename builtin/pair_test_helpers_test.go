package builtin

import (
	"testing"

	"mutant/object"
)

// unwrapPair extracts result and error from a MultiValue return
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

// unwrapSingleOrPair handles both single value returns and MultiValue returns
// For pure functions that return single values, it returns (value, nil)
// For fallible functions that return MultiValue, it extracts and returns (result, error)
func unwrapSingleOrPair(t *testing.T, value object.Object) (object.Object, *object.Error) {
	t.Helper()

	// If it's a MultiValue, treat it as a pair
	if pair, ok := value.(*object.MultiValue); ok {
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

	// Otherwise it's a single value return (or error)
	if err, ok := value.(*object.Error); ok {
		return nil, err
	}
	return value, nil
}
