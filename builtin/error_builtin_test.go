package builtin

import (
	"strings"
	"testing"

	"mutant/object"
)

func callError(args ...object.Object) object.Object { return Error(args...) }

func errStr(v string) *object.String { return &object.String{Value: v} }

func TestErrorCarriesWhatItWasGiven(t *testing.T) {
	result := callError(errStr("boom"), errStr("parser"))

	errObj, ok := result.(*object.Error)
	if !ok {
		t.Fatalf("error() returned %T, want *object.Error", result)
	}
	if errObj.Message != "boom" {
		t.Errorf("message = %q, want %q", errObj.Message, "boom")
	}
	if errObj.Context != "parser" {
		t.Errorf("context = %q, want %q", errObj.Context, "parser")
	}
}

// The default context is "user" rather than empty. Every error the runtime
// raises names its origin, and an error whose origin could not be read off it
// would be the only kind that could not say where it came from.
func TestErrorDefaultsItsContextToUser(t *testing.T) {
	errObj := callError(errStr("boom")).(*object.Error)
	if errObj.Context != "user" {
		t.Errorf("context = %q, want %q", errObj.Context, "user")
	}
}

// Related is Object-valued so a fact keeps its type. Flattening an offset to
// text is exactly the loss the field exists to prevent, so the check is that
// each value comes back as the type it went in as.
func TestRelatedValuesKeepTheirTypes(t *testing.T) {
	hash := &object.Hash{Pairs: map[object.HashKey]object.HashPair{}}
	for _, pair := range []object.HashPair{
		{Key: errStr("path"), Value: errStr("/evidence/disk.img")},
		{Key: errStr("offset"), Value: &object.Integer{Value: 4096}},
		{Key: errStr("magic"), Value: &object.Bytes{Value: []byte{0x4d, 0x5a}}},
	} {
		hash.Pairs[pair.Key.(*object.String).HashKey()] = pair
	}

	errObj, ok := callError(errStr("bad record"), errStr("parser"), hash).(*object.Error)
	if !ok {
		t.Fatal("error() did not return an error")
	}
	if len(errObj.Related) != 3 {
		t.Fatalf("related has %d entries, want 3", len(errObj.Related))
	}
	if _, ok := errObj.Related["offset"].(*object.Integer); !ok {
		t.Errorf("offset came back as %T, want *object.Integer", errObj.Related["offset"])
	}
	if _, ok := errObj.Related["magic"].(*object.Bytes); !ok {
		t.Errorf("magic came back as %T, want *object.Bytes", errObj.Related["magic"])
	}
}

// Mutant hash keys may be STRING, INTEGER or BOOLEAN; Related is keyed by Go
// string. Rendering a non-string key would silently turn {1: "a"} into
// {"1": "a"} with no way for the program to learn it happened, so it is refused
// by name instead.
func TestRelatedRefusesANonStringKey(t *testing.T) {
	key := &object.Integer{Value: 1}
	hash := &object.Hash{Pairs: map[object.HashKey]object.HashPair{
		key.HashKey(): {Key: key, Value: errStr("a")},
	}}

	errObj, ok := callError(errStr("boom"), errStr("parser"), hash).(*object.Error)
	if !ok {
		t.Fatal("error() did not return an error")
	}
	if !strings.Contains(errObj.Message, "must have STRING keys") {
		t.Errorf("message does not name the problem: %q", errObj.Message)
	}
	if !strings.Contains(errObj.Message, "INTEGER") {
		t.Errorf("message does not name the offending key type: %q", errObj.Message)
	}
}

func TestErrorRejectsWhatItCannotBuildFrom(t *testing.T) {
	tests := []struct {
		name string
		args []object.Object
		want string
	}{
		{"no arguments", nil, "wrong number of arguments"},
		{"too many", []object.Object{errStr("a"), errStr("b"), errStr("c"), errStr("d")}, "wrong number of arguments"},
		{"message not a string", []object.Object{&object.Integer{Value: 1}}, "must be STRING"},
		{"context not a string", []object.Object{errStr("a"), &object.Integer{Value: 1}}, "must be STRING"},
		{"related not a hash", []object.Object{errStr("a"), errStr("b"), errStr("c")}, "must be HASH"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errObj, ok := callError(tt.args...).(*object.Error)
			if !ok {
				t.Fatal("error() did not return an error")
			}
			if !strings.Contains(errObj.Message, tt.want) {
				t.Errorf("message %q does not contain %q", errObj.Message, tt.want)
			}
		})
	}
}

// The evaluator asks this rather than checking for the name "error", so a
// second error-returning builtin would be covered without touching it. The test
// pins both halves: error() is in the set, and an ordinary builtin is not.
func TestReturnsErrorValueReadsTheContract(t *testing.T) {
	var errorBuiltin, typeOfBuiltin *BuiltIn
	for _, def := range Builtins {
		switch def.Name {
		case BuiltinNameError:
			errorBuiltin = def.Builtin
		case BuiltinNameTypeOf:
			typeOfBuiltin = def.Builtin
		}
	}
	if errorBuiltin == nil || typeOfBuiltin == nil {
		t.Fatal("registry is missing a builtin the test needs")
	}
	if !ReturnsErrorValue(errorBuiltin) {
		t.Error("error() should be recognised as returning an error value")
	}
	if ReturnsErrorValue(typeOfBuiltin) {
		t.Error("type_of() returns a string; an error from it is a failure")
	}
}
