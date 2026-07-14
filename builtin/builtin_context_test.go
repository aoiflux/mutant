package builtin

import (
	"testing"

	"mutant/object"
)

func TestBuiltinErrorContextUsesBuiltinNameForDirectError(t *testing.T) {
	fn := GetBuiltinByName("len")
	if fn == nil {
		t.Fatalf("expected len builtin")
	}

	result := fn.Fn(&object.Integer{Value: 1})
	errObj, ok := result.(*object.Error)
	if !ok {
		t.Fatalf("expected direct Error result, got=%T", result)
	}
	if errObj.Context != "builtin.len" {
		t.Fatalf("unexpected error context: got=%q want=%q", errObj.Context, "builtin.len")
	}
}

func TestBuiltinErrorContextUsesBuiltinNameForHelperError(t *testing.T) {
	fn := GetBuiltinByName("bytes_get")
	if fn == nil {
		t.Fatalf("expected bytes_get builtin")
	}

	result := fn.Fn(&object.String{Value: "abc"}, &object.String{Value: "not-int"})
	_, errObj := unwrapPair(t, result)
	if errObj == nil {
		t.Fatalf("expected error in pair")
	}
	if errObj.Context != "builtin.bytes_get" {
		t.Fatalf("unexpected helper error context: got=%q want=%q", errObj.Context, "builtin.bytes_get")
	}
}
