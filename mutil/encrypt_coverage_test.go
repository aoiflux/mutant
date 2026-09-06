package mutil

import (
	"bytes"
	"reflect"
	"testing"

	"mutant/object"
	"mutant/serialize"
)

// How EncryptObject is expected to treat each object type.
//
//	"sealed"      the value comes back wrapped in an *object.Encrypted
//	"recursive"   a container is rebuilt with its children sealed
//	"passthrough" the value is returned as-is, deliberately
//
// The point of writing this down is that "passthrough" and "fell through to the
// default arm" are indistinguishable from outside: both leave the value in the
// clear, and both callers of EncryptObject discard the error and keep the
// plaintext object. So a type nobody classified used to become a silent leak.
// Now it becomes a test failure, and someone has to choose.
var encryptTreatment = map[object.ObjectType]string{
	object.INTEGER_OBJ:      "sealed",
	object.FLOAT_OBJ:        "sealed",
	object.BOOLEAN_OBJ:      "sealed",
	object.STRING_OBJ:       "sealed",
	object.BYTES_OBJ:        "sealed",
	object.NULL_OBJ:         "sealed",
	object.ERROR_OBJ:        "sealed",
	object.ARRAY_OBJ:        "recursive",
	object.HASH_OBJ:         "recursive",
	object.STRUCT_OBJ:       "recursive",
	object.ENUM_VALUE_OBJ:   "recursive",
	object.CLOSURE_OBJ:      "recursive",
	object.MULTI_VALUE_OBJ:  "recursive",
	object.LUA_PATCH_OBJ:    "recursive",
	object.ENCRYPTED_OBJ:    "passthrough",
	object.COMPILED_FN_OBJ:  "passthrough",
	object.BUILTIN_OBJ:      "passthrough",
	object.FUNCTION_OBJ:     "passthrough",
	object.MACRO_OBJ:        "passthrough",
	object.QUOTE_OBJ:        "passthrough",
	object.RETURN_VALUE_OBJ: "passthrough",
	object.BREAK_OBJ:        "passthrough",
	object.CONTINUE_OBJ:     "passthrough",
}

func treatmentOf(in, out object.Object) string {
	if _, ok := out.(*object.Encrypted); ok && in.Type() != object.ENCRYPTED_OBJ {
		return "sealed"
	}
	if reflect.ValueOf(in).Pointer() == reflect.ValueOf(out).Pointer() {
		return "passthrough"
	}
	return "recursive"
}

// TestEncryptObjectClassifiesEveryObjectType walks the same list the gob
// registration uses -- which serialize's own test proves is every implementation
// of object.Object -- and checks that each type reaches an arm chosen for it
// rather than the default.
//
// The default arm returns an error, and both call sites answer an error by
// storing the plaintext object. MULTI_VALUE and ERROR_OBJ were reaching it: a
// multi-value is what Mutant's (value, err) idiom produces, and an error carries
// the path that failed in its Message.
func TestEncryptObjectClassifiesEveryObjectType(t *testing.T) {
	for _, entry := range serialize.GobTypes() {
		obj, ok := entry.(object.Object)
		if !ok {
			continue // builtin.BuiltIn is covered by the BUILTIN_OBJ arm
		}

		want, classified := encryptTreatment[obj.Type()]
		if !classified {
			t.Errorf("%s has no entry in encryptTreatment: decide whether it should be "+
				"sealed, recursive or passthrough -- an unclassified type falls to the "+
				"default arm and is stored in plaintext", obj.Type())
			continue
		}

		out, err := EncryptObject(obj, 16, "pw")
		if err != nil {
			t.Errorf("EncryptObject(%s): %v", obj.Type(), err)
			continue
		}
		if got := treatmentOf(obj, out); got != want {
			t.Errorf("EncryptObject(%s) is %s, want %s", obj.Type(), got, want)
		}
	}
}

// TestEncryptTreatmentHasNoStaleEntries catches the reverse drift: a type
// removed from object/ but left in the table above.
func TestEncryptTreatmentHasNoStaleEntries(t *testing.T) {
	live := map[object.ObjectType]bool{object.BUILTIN_OBJ: true}
	for _, entry := range serialize.GobTypes() {
		if obj, ok := entry.(object.Object); ok {
			live[obj.Type()] = true
		}
	}
	for typ := range encryptTreatment {
		if !live[typ] {
			t.Errorf("encryptTreatment lists %s, which no longer implements object.Object", typ)
		}
	}
}

func roundTrip(t *testing.T, in object.Object) object.Object {
	t.Helper()

	enc, err := EncryptObject(in, 16, "pw")
	if err != nil {
		t.Fatalf("encrypt %s: %v", in.Type(), err)
	}
	out, err := DecryptObject(enc, 16, "pw")
	if err != nil {
		t.Fatalf("decrypt %s: %v", in.Type(), err)
	}
	return out
}

// An empty payload used to fail encryption, and a failed child failed the whole
// container -- so one empty string left every sibling element in the clear.
func TestEmptyPayloadsSealAndRestore(t *testing.T) {
	for _, in := range []object.Object{
		&object.String{Value: ""},
		&object.Bytes{Value: []byte{}},
	} {
		enc, err := EncryptObject(in, 16, "pw")
		if err != nil {
			t.Fatalf("encrypt empty %s: %v", in.Type(), err)
		}
		if _, ok := enc.(*object.Encrypted); !ok {
			t.Errorf("empty %s was not sealed: got %s", in.Type(), enc.Type())
		}

		out, err := DecryptObject(enc, 16, "pw")
		if err != nil {
			t.Fatalf("decrypt empty %s: %v", in.Type(), err)
		}
		if out.Type() != in.Type() || out.Inspect() != in.Inspect() {
			t.Errorf("empty %s round-tripped to %s %q", in.Type(), out.Type(), out.Inspect())
		}
	}
}

func TestArrayWithEmptyElementSealsEverySibling(t *testing.T) {
	in := &object.Array{Elements: []object.Object{
		&object.String{Value: ""},
		&object.String{Value: "secret"},
	}}

	enc, err := EncryptObject(in, 16, "pw")
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	for i, element := range enc.(*object.Array).Elements {
		if _, ok := element.(*object.Encrypted); !ok {
			t.Errorf("element %d left in the clear: %s %q", i, element.Type(), element.Inspect())
		}
	}

	out, err := DecryptObject(enc, 16, "pw")
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if out.Inspect() != in.Inspect() {
		t.Errorf("round-trip changed the array: %q, want %q", out.Inspect(), in.Inspect())
	}
}

func TestMultiValueRoundTrips(t *testing.T) {
	in := &object.MultiValue{Values: []object.Object{
		&object.Integer{Value: 7},
		&object.String{Value: "secret"},
	}}

	enc, err := EncryptObject(in, 16, "pw")
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	for i, value := range enc.(*object.MultiValue).Values {
		if _, ok := value.(*object.Encrypted); !ok {
			t.Errorf("value %d left in the clear: %s %q", i, value.Type(), value.Inspect())
		}
	}

	if out := roundTrip(t, in); out.Inspect() != in.Inspect() {
		t.Errorf("round-trip changed the multi-value: %q, want %q", out.Inspect(), in.Inspect())
	}
}

// The whole error is encoded rather than a chosen few fields, so this checks the
// ones most easily forgotten: the position, the copied source line and the stack.
//
// Related is deliberately populated with three different concrete types. It is
// the only interface-typed field on Error, so it is the only one that can fail
// for a reason the other fields cannot: gob refusing a type it was not told
// about. That failure is silent at this layer -- EncryptObject's callers keep
// the plaintext object -- so a round trip is the only thing that catches it.
func TestErrorRoundTripsWholeStruct(t *testing.T) {
	in := &object.Error{
		Message: "fs_read: open /etc/shadow: permission denied",
		Context: "builtin.fs_read",
		Related: map[string]object.Object{
			"path":  &object.String{Value: "/etc/shadow"},
			"errno": &object.Integer{Value: 13},
			"magic": &object.Bytes{Value: []byte{0x4d, 0x5a}},
		},
		File:       "prog.mut",
		Line:       12,
		Column:     5,
		EndLine:    12,
		EndColumn:  20,
		SourceLine: "let v, e = fs_read(\"/etc/shadow\");",
		Stack:      []string{"main", "load"},
	}

	enc, err := EncryptObject(in, 16, "pw")
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	sealed, ok := enc.(*object.Encrypted)
	if !ok {
		t.Fatalf("error was not sealed: got %s", enc.Type())
	}
	if bytes.Contains(sealed.Value, []byte("/etc/shadow")) {
		t.Error("the sealed payload still carries the path in the clear")
	}

	out, err := DecryptObject(enc, 16, "pw")
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	got, ok := out.(*object.Error)
	if !ok {
		t.Fatalf("decrypted to %s, want an error", out.Type())
	}
	if !reflect.DeepEqual(got, in) {
		t.Errorf("round-trip changed the error:\n got %+v\nwant %+v", got, in)
	}
}
