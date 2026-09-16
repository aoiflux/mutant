package object

import "testing"

// Every name the field list advertises has to resolve, and nothing outside it
// may. The list exists so the shape can be enumerated rather than probed one
// name at a time; a name in the list that Field does not answer would make the
// enumeration a lie.
func TestEveryAdvertisedFieldResolves(t *testing.T) {
	err := &Error{}

	for _, name := range ErrorFieldNames() {
		if _, ok := err.Field(name); !ok {
			t.Errorf("advertised field %q does not resolve", name)
		}
	}

	for _, name := range []string{"", "Message", "msg", "kind", "stack_trace"} {
		if _, ok := err.Field(name); ok {
			t.Errorf("unadvertised name %q resolved", name)
		}
	}
}

// A zero Error still answers every field, with the empty value of its type.
// This is the same guarantee a stripped build depends on, checked here at the
// layer that actually makes it.
func TestZeroErrorAnswersEveryFieldWithItsEmptyValue(t *testing.T) {
	err := &Error{}

	wantTypes := map[string]ObjectType{
		"message":     STRING_OBJ,
		"context":     STRING_OBJ,
		"related":     HASH_OBJ,
		"file":        STRING_OBJ,
		"line":        INTEGER_OBJ,
		"column":      INTEGER_OBJ,
		"end_line":    INTEGER_OBJ,
		"end_column":  INTEGER_OBJ,
		"source_line": STRING_OBJ,
		"stack":       ARRAY_OBJ,
	}

	for name, want := range wantTypes {
		got, ok := err.Field(name)
		if !ok {
			t.Fatalf("field %q missing", name)
		}
		if got.Type() != want {
			t.Errorf("field %q is %s, want %s", name, got.Type(), want)
		}
	}
}

// related has to hand back the values Related holds, not renderings of them.
// That is the whole reason Related is Object-valued: an offset that arrives as
// a string has already lost the thing the caller wanted it for.
func TestRelatedFieldPreservesValueTypes(t *testing.T) {
	err := &Error{Related: map[string]Object{
		"path":   &String{Value: "/etc/shadow"},
		"offset": &Integer{Value: 4096},
		"magic":  &Bytes{Value: []byte{0x4d, 0x5a}},
	}}

	value, _ := err.Field("related")
	hash, ok := value.(*Hash)
	if !ok {
		t.Fatalf("related is %T, want a hash", value)
	}
	if len(hash.Pairs) != 3 {
		t.Fatalf("related has %d pairs, want 3", len(hash.Pairs))
	}

	want := map[string]ObjectType{
		"path": STRING_OBJ, "offset": INTEGER_OBJ, "magic": BYTES_OBJ,
	}
	for name, wantType := range want {
		pair, ok := hash.Pairs[(&String{Value: name}).HashKey()]
		if !ok {
			t.Fatalf("related lost key %q", name)
		}
		if pair.Value.Type() != wantType {
			t.Errorf("related[%q] is %s, want %s", name, pair.Value.Type(), wantType)
		}
	}
}

// A nil value under a key is a bug in the raiser -- Inspect names it as null,
// and the field has to as well. A Go nil inside a hash is a panic waiting for
// whichever builtin walks it next.
func TestRelatedFieldTurnsANilValueIntoNull(t *testing.T) {
	err := &Error{Related: map[string]Object{"why": nil}}

	value, _ := err.Field("related")
	pair, ok := value.(*Hash).Pairs[(&String{Value: "why"}).HashKey()]
	if !ok {
		t.Fatal("related dropped the key with the nil value")
	}
	if pair.Value == nil || pair.Value.Type() != NULL_OBJ {
		t.Errorf("nil related value became %v, want NULL", pair.Value)
	}
}

// The composite fields are rebuilt per read, so a program that mutates what it
// read does not edit the error it read it from.
func TestCompositeFieldsAreCopies(t *testing.T) {
	err := &Error{
		Related: map[string]Object{"path": &String{Value: "/etc/shadow"}},
		Stack:   []string{"main"},
	}

	first, _ := err.Field("related")
	delete(first.(*Hash).Pairs, (&String{Value: "path"}).HashKey())
	if second, _ := err.Field("related"); len(second.(*Hash).Pairs) != 1 {
		t.Error("mutating the related hash edited the error")
	}

	stack, _ := err.Field("stack")
	stack.(*Array).Elements[0] = &String{Value: "forged"}
	if again, _ := err.Field("stack"); again.(*Array).Elements[0].Inspect() != "main" {
		t.Error("mutating the stack array edited the error")
	}
}

// Field is reached through a type assertion in both engines, and a nil *Error
// satisfies that assertion. Reporting no field beats panicking inside the
// report that was explaining an earlier failure.
func TestFieldOnANilErrorReportsNothing(t *testing.T) {
	var err *Error

	if _, ok := err.Field("message"); ok {
		t.Error("a nil error answered a field")
	}
}

// Equality compares what went wrong, not where. Position is excluded because
// only one of the two engines stamps one: comparing rendered errors -- which is
// what the Inspect fallback did -- made `error("a") == error("a")` true in the
// tree-walking evaluator and false in the VM.
func TestErrorEqualityComparesTheFailureNotThePosition(t *testing.T) {
	at := func(line int) *Error {
		return &Error{Message: "boom", Context: "parser", File: "a.mut", Line: line}
	}
	if !at(1).Equals(at(99)) {
		t.Error("two identical failures at different lines compare unequal")
	}

	tests := []struct {
		name string
		a, b *Error
		want bool
	}{
		{"same", &Error{Message: "a", Context: "c"}, &Error{Message: "a", Context: "c"}, true},
		{"message differs", &Error{Message: "a"}, &Error{Message: "b"}, false},
		{"context differs", &Error{Message: "a", Context: "x"}, &Error{Message: "a", Context: "y"}, false},
		{"nil both", nil, nil, true},
		{"nil one", nil, &Error{Message: "a"}, false},
		{
			"related differs by value",
			&Error{Related: map[string]Object{"n": &Integer{Value: 1}}},
			&Error{Related: map[string]Object{"n": &Integer{Value: 2}}},
			false,
		},
		{
			"related differs by key",
			&Error{Related: map[string]Object{"n": &Integer{Value: 1}}},
			&Error{Related: map[string]Object{"m": &Integer{Value: 1}}},
			false,
		},
		{
			"related differs by size",
			&Error{Related: map[string]Object{"n": &Integer{Value: 1}}},
			&Error{},
			false,
		},
		{
			// A bytes and the string spelling its own hex render alike through
			// Inspect, so related values are compared by rendering *and* the
			// values themselves must not be allowed to collapse types silently.
			"related matches by value",
			&Error{Related: map[string]Object{"b": &Bytes{Value: []byte{0x4d, 0x5a}}}},
			&Error{Related: map[string]Object{"b": &Bytes{Value: []byte{0x4d, 0x5a}}}},
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.a.Equals(tt.b); got != tt.want {
				t.Errorf("Equals = %t, want %t", got, tt.want)
			}
			if got := tt.b.Equals(tt.a); got != tt.want {
				t.Errorf("Equals is not symmetric: reversed gave %t, want %t", got, tt.want)
			}
		})
	}
}
