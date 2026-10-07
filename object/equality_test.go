package object

import "testing"

func intFields(values map[string]int64) map[string]Object {
	fields := make(map[string]Object, len(values))
	for name, value := range values {
		fields[name] = &Integer{Value: value}
	}
	return fields
}

// The first thing ValuesEqual must do is refuse to compare across types. The
// fallback at the bottom compares rendered forms, and that is exactly how a
// string spelling `P { a: 1 }` came to be equal to the struct spelling it.
func TestValuesEqualRefusesToCompareAcrossTypes(t *testing.T) {
	record := &Struct{TypeName: "P", FieldOrder: []string{"a"}, Fields: intFields(map[string]int64{"a": 1})}
	spelled := &String{Value: record.Inspect()}

	if ValuesEqual(record, spelled) {
		t.Errorf("a struct is equal to the string spelling it: %q", spelled.Value)
	}
	if ValuesEqual(spelled, record) {
		t.Error("...and in the other direction too")
	}
}

// No numeric promotion. `contains`, `index_of` and `unique` already answered
// that an integer is not a float, and widening it here would silently
// reclassify an element a program had been told was absent.
func TestValuesEqualDoesNotPromoteNumbers(t *testing.T) {
	if ValuesEqual(&Integer{Value: 1}, &Float{Value: 1.0}) {
		t.Error("integer 1 compared equal to float 1.0")
	}
}

func TestValuesEqualComparesByValue(t *testing.T) {
	cases := []struct {
		name  string
		a, b  Object
		equal bool
	}{
		{"equal integers", &Integer{Value: 7}, &Integer{Value: 7}, true},
		{"unequal integers", &Integer{Value: 7}, &Integer{Value: 8}, false},
		{"equal floats", &Float{Value: 1.5}, &Float{Value: 1.5}, true},
		{"unequal floats", &Float{Value: 1.5}, &Float{Value: 2.5}, false},
		{"equal strings", &String{Value: "x"}, &String{Value: "x"}, true},
		{"unequal strings", &String{Value: "x"}, &String{Value: "y"}, false},
		{"equal booleans", &Boolean{Value: true}, &Boolean{Value: true}, true},
		{"unequal booleans", &Boolean{Value: true}, &Boolean{Value: false}, false},
		{"two nulls", &Null{}, &Null{}, true},
		{"equal buffers", &Bytes{Value: []byte{1, 2}}, &Bytes{Value: []byte{1, 2}}, true},
		{"unequal buffers", &Bytes{Value: []byte{1, 2}}, &Bytes{Value: []byte{1, 3}}, false},
		{"equal arrays", &Array{Elements: []Object{&Integer{Value: 1}}}, &Array{Elements: []Object{&Integer{Value: 1}}}, true},
		{"unequal arrays", &Array{Elements: []Object{&Integer{Value: 1}}}, &Array{Elements: []Object{&Integer{Value: 2}}}, false},
		{"a string is not a buffer", &String{Value: "ab"}, &Bytes{Value: []byte("ab")}, false},
	}

	for _, c := range cases {
		if got := ValuesEqual(c.a, c.b); got != c.equal {
			t.Errorf("%s: ValuesEqual = %t, want %t", c.name, got, c.equal)
		}
	}
}

// The Classified mark records where a buffer came from, not what it holds, and
// bytesObj.go says so: Inspect is deliberately not told about it, because a
// classification-aware identity would make two equal buffers unequal in
// equality, dedup, containment and hash ordering all at once. The VM's
// execBytesComparison ignores it for the same reason, so this must too.
func TestValuesEqualIgnoresTheClassifiedMarkOnBytes(t *testing.T) {
	plain := &Bytes{Value: []byte{9, 9}}
	marked := &Bytes{Value: []byte{9, 9}, Classified: &Classification{RecordUID: "r", Tags: []string{"t"}}}

	if !ValuesEqual(plain, marked) {
		t.Error("the Classified mark changed what a buffer holds")
	}
}

// A variant is identified by its type and tag. The payload is the ordinal, which
// both engines leave out of the comparison.
func TestValuesEqualComparesEnumValuesByTag(t *testing.T) {
	ok := &EnumValue{TypeName: "Status", Tag: "Ok", Value: &Integer{Value: 0}}
	sameTag := &EnumValue{TypeName: "Status", Tag: "Ok", Value: &Integer{Value: 7}}
	otherTag := &EnumValue{TypeName: "Status", Tag: "Failed", Value: &Integer{Value: 0}}
	otherEnum := &EnumValue{TypeName: "Grade", Tag: "Ok", Value: &Integer{Value: 0}}

	if !ValuesEqual(ok, sameTag) {
		t.Error("one variant compared unequal to itself over its payload")
	}
	if ValuesEqual(ok, otherTag) {
		t.Error("two variants of one enum compared equal")
	}
	if ValuesEqual(ok, otherEnum) {
		t.Error("variants of two different enums compared equal")
	}
}

func TestValuesEqualHandlesAbsentValues(t *testing.T) {
	if !ValuesEqual(nil, nil) {
		t.Error("two absent values compared unequal")
	}
	if ValuesEqual(nil, &Integer{Value: 1}) || ValuesEqual(&Integer{Value: 1}, nil) {
		t.Error("an absent value compared equal to a present one")
	}
}

// Two structs are the same value when they are the same type and every field
// holds an equal value -- not when they render the same. Comparing renders is
// what made this a coin toss, and with an order it would still make a string
// spelling the struct equal to it.
func TestStructEqualsComparesFieldsRatherThanRenders(t *testing.T) {
	base := &Struct{TypeName: "P", FieldOrder: []string{"a", "b"}, Fields: intFields(map[string]int64{"a": 1, "b": 2})}

	cases := []struct {
		name  string
		other *Struct
		equal bool
	}{
		{"the same fields", &Struct{TypeName: "P", FieldOrder: []string{"a", "b"}, Fields: intFields(map[string]int64{"a": 1, "b": 2})}, true},
		{"a different type name", &Struct{TypeName: "Q", FieldOrder: []string{"a", "b"}, Fields: intFields(map[string]int64{"a": 1, "b": 2})}, false},
		{"a different value", &Struct{TypeName: "P", FieldOrder: []string{"a", "b"}, Fields: intFields(map[string]int64{"a": 1, "b": 9})}, false},
		{"one field fewer", &Struct{TypeName: "P", FieldOrder: []string{"a"}, Fields: intFields(map[string]int64{"a": 1})}, false},
		{"one field more", &Struct{TypeName: "P", FieldOrder: []string{"a", "b", "c"}, Fields: intFields(map[string]int64{"a": 1, "b": 2, "c": 3})}, false},
		{"a field under another name", &Struct{TypeName: "P", FieldOrder: []string{"a", "z"}, Fields: intFields(map[string]int64{"a": 1, "z": 2})}, false},
		// FieldOrder takes no part. Two structs of one type always hold one
		// order, so a difference in it is a defect in whatever built them
		// rather than a difference in the value they hold.
		{"the same fields under another recorded order", &Struct{TypeName: "P", FieldOrder: []string{"b", "a"}, Fields: intFields(map[string]int64{"a": 1, "b": 2})}, true},
	}

	for _, c := range cases {
		if got := base.Equals(c.other); got != c.equal {
			t.Errorf("%s: Equals = %t, want %t", c.name, got, c.equal)
		}
		if got := c.other.Equals(base); got != c.equal {
			t.Errorf("%s, the other way round: Equals = %t, want %t", c.name, got, c.equal)
		}
	}
}

// A field holding a struct is compared the same way, all the way down.
func TestStructEqualsRecursesIntoFields(t *testing.T) {
	outer := func(v int64) *Struct {
		inner := &Struct{TypeName: "Inner", FieldOrder: []string{"v"}, Fields: intFields(map[string]int64{"v": v})}
		return &Struct{TypeName: "Outer", FieldOrder: []string{"i"}, Fields: map[string]Object{"i": inner}}
	}

	if !outer(1).Equals(outer(1)) {
		t.Error("two equal nested structs compared unequal")
	}
	if outer(1).Equals(outer(2)) {
		t.Error("two different nested structs compared equal")
	}
}

func TestStructEqualsHandlesAbsentStructs(t *testing.T) {
	var absent *Struct
	present := &Struct{TypeName: "P", Fields: map[string]Object{}}

	if !absent.Equals(nil) {
		t.Error("two absent structs compared unequal")
	}
	if absent.Equals(present) || present.Equals(absent) {
		t.Error("an absent struct compared equal to a present one")
	}
}
