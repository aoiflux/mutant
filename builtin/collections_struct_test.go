package builtin

import (
	"testing"

	"mutant/object"
)

// contains, index_of and unique all ask "is this the same value?", and all three
// asked it of a struct by comparing rendered forms. Struct.Inspect ranged a Go
// map, so a search for a record that was present found it about half the time
// and unique kept both copies of one record about half the time -- which is a
// wrong answer a caller has no way to notice.
//
// Every assertion here repeats, because the wrong answer was the likely one
// rather than the certain one: a single run passed often enough to look fine.
const structSearchRepeats = 50

func structValue(typeName string, order []string, values map[string]int64) *object.Struct {
	fields := make(map[string]object.Object, len(values))
	for name, value := range values {
		fields[name] = &object.Integer{Value: value}
	}
	return &object.Struct{TypeName: typeName, FieldOrder: order, Fields: fields}
}

func sixFieldRecord() *object.Struct {
	return structValue("Record",
		[]string{"a", "b", "c", "d", "e", "f"},
		map[string]int64{"a": 1, "b": 2, "c": 3, "d": 4, "e": 5, "f": 6},
	)
}

func TestContainsFindsAnEqualStruct(t *testing.T) {
	for i := 0; i < structSearchRepeats; i++ {
		got := Contains(arr(sixFieldRecord()), sixFieldRecord())
		b, ok := got.(*object.Boolean)
		if !ok {
			t.Fatalf("contains returned %T (%s)", got, got.Inspect())
		}
		if !b.Value {
			t.Fatalf("run %d: contains did not find an equal struct", i)
		}
	}
}

func TestIndexOfFindsAnEqualStruct(t *testing.T) {
	for i := 0; i < structSearchRepeats; i++ {
		got := IndexOf(arr(&object.Integer{Value: 7}, sixFieldRecord()), sixFieldRecord())
		n, ok := got.(*object.Integer)
		if !ok {
			t.Fatalf("index_of returned %T (%s)", got, got.Inspect())
		}
		if n.Value != 1 {
			t.Fatalf("run %d: index_of returned %d, want 1", i, n.Value)
		}
	}
}

func TestUniqueKeepsOneOfTwoEqualStructs(t *testing.T) {
	for i := 0; i < structSearchRepeats; i++ {
		got := mustArray(t, Unique(arr(sixFieldRecord(), sixFieldRecord())))
		if len(got.Elements) != 1 {
			t.Fatalf("run %d: unique kept %d of two equal structs, want 1", i, len(got.Elements))
		}
	}
}

// Two records that differ must stay two records, which is what makes the test
// above an assertion about equality rather than about always answering one.
func TestUniqueKeepsTwoDifferentStructs(t *testing.T) {
	other := structValue("Record",
		[]string{"a", "b", "c", "d", "e", "f"},
		map[string]int64{"a": 1, "b": 2, "c": 3, "d": 4, "e": 5, "f": 9},
	)

	got := mustArray(t, Unique(arr(sixFieldRecord(), other)))
	if len(got.Elements) != 2 {
		t.Fatalf("unique kept %d of two different structs, want 2", len(got.Elements))
	}
}

// A string spelling the record is not the record. This is the half that giving
// Inspect an order does not fix, and the reason objectsEqual asks
// object.ValuesEqual rather than comparing two renders.
func TestContainsDoesNotFindAStringSpellingTheStruct(t *testing.T) {
	record := sixFieldRecord()
	spelled := &object.String{Value: record.Inspect()}

	if got := Contains(arr(record), spelled); got.Inspect() != "false" {
		t.Errorf("contains found a struct by its spelling: %q", spelled.Value)
	}
	if got := Contains(arr(spelled), record); got.Inspect() != "false" {
		t.Error("...and in the other direction too")
	}
}

// A struct and a string that spell the same text are two values, so a dedup must
// keep both.
func TestUniqueKeepsAStructAndTheStringSpellingIt(t *testing.T) {
	record := sixFieldRecord()
	spelled := &object.String{Value: record.Inspect()}

	got := mustArray(t, Unique(arr(record, spelled)))
	if len(got.Elements) != 2 {
		t.Fatalf("unique kept %d of a struct and the string spelling it, want 2", len(got.Elements))
	}
}
