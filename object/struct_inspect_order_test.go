package object

import (
	"strings"
	"testing"
)

func buildStruct(order []string, values map[string]int64) *Struct {
	fields := make(map[string]Object, len(values))
	for name, value := range values {
		fields[name] = &Integer{Value: value}
	}
	return &Struct{TypeName: "P", FieldOrder: order, Fields: fields}
}

// Fields are stored in a Go map, and ranging a map gives a different order on
// every call -- not merely on every run. Printing straight from that range made
// one struct print two ways inside a single statement, and because Inspect was
// the identity equality compared, it also made a struct unequal to itself.
//
// This is the struct half of what TestHashInspectIsStableAcrossRuns pins for
// hashes. Six fields, because two agree by chance half the time.
func TestStructInspectIsStableAcrossCalls(t *testing.T) {
	s := buildStruct(
		[]string{"a", "b", "c", "d", "e", "f"},
		map[string]int64{"a": 1, "b": 2, "c": 3, "d": 4, "e": 5, "f": 6},
	)

	first := s.Inspect()
	for i := 0; i < 200; i++ {
		if got := s.Inspect(); got != first {
			t.Fatalf("Inspect changed between calls:\n first: %s\n now:   %s", first, got)
		}
	}
}

// A hash sorts its keys because a hash has no authored order. A struct has one
// and renders in it: the declaration decides, not the alphabet and not the
// order the literal happened to be written in.
func TestStructInspectFollowsTheDeclarationOrder(t *testing.T) {
	s := buildStruct(
		[]string{"zeta", "alpha", "mu"},
		map[string]int64{"alpha": 1, "mu": 2, "zeta": 3},
	)

	if got, want := s.Inspect(), "P { zeta: 3, alpha: 1, mu: 2 }"; got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
}

// Two structs of one type hold one order, so holding the same values means
// printing the same text. The maps are filled in opposite orders so that any
// dependence on how the map was built shows up.
func TestEqualStructsPrintIdentically(t *testing.T) {
	order := []string{"first", "second", "third", "fourth"}
	forward := buildStruct(order, map[string]int64{"first": 1, "second": 2, "third": 3, "fourth": 4})

	backward := &Struct{TypeName: "P", FieldOrder: order, Fields: map[string]Object{}}
	for name, value := range forward.Fields {
		backward.Fields[name] = value
	}

	if forward.Inspect() != backward.Inspect() {
		t.Fatalf("the same fields printed two ways:\n %s\n %s", forward.Inspect(), backward.Inspect())
	}
}

// A field in Fields that FieldOrder does not name still has to be shown, and in
// a definite place. Nothing written through the compiler reaches this -- it
// fills exactly the declared fields -- but OpSetField will create a field that
// was never declared, and dropping a value from the one function whose job is to
// show it would hide it.
func TestAnUndeclaredFieldIsShownLastAndSorted(t *testing.T) {
	s := buildStruct(
		[]string{"declared"},
		map[string]int64{"declared": 1, "later": 2, "earlier": 3},
	)

	if got, want := s.Inspect(), "P { declared: 1, earlier: 3, later: 2 }"; got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
}

// FieldOrder is derived rather than authoritative: Fields is the value. A name
// recorded with no field behind it is skipped rather than rendered as a hole,
// and a name recorded twice is rendered once.
func TestInspectTreatsFieldsAsTheValueAndOrderAsAdvice(t *testing.T) {
	s := &Struct{
		TypeName:   "P",
		FieldOrder: []string{"a", "gone", "a", "b"},
		Fields:     map[string]Object{"a": &Integer{Value: 1}, "b": &Integer{Value: 2}},
	}

	if got, want := s.Inspect(), "P { a: 1, b: 2 }"; got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
}

// A struct with no order recorded at all still prints every field it holds, and
// prints it the same way every time. This is what a literal naming a type that
// was never declared gets from the evaluator, which accepts one where the
// compiler refuses it.
func TestAStructWithNoRecordedOrderStillPrintsEveryField(t *testing.T) {
	s := &Struct{
		TypeName: "P",
		Fields:   map[string]Object{"b": &Integer{Value: 2}, "a": &Integer{Value: 1}},
	}

	first := s.Inspect()
	for i := 0; i < 100; i++ {
		if got := s.Inspect(); got != first {
			t.Fatalf("an unordered struct is not stable:\n first: %s\n now:   %s", first, got)
		}
	}
	for _, want := range []string{"a: 1", "b: 2"} {
		if !strings.Contains(first, want) {
			t.Fatalf("%q missing from %s", want, first)
		}
	}
}

// Unchanged by the ordering fix, and pinned so it stays that way: a struct with
// no fields renders its braces with the separating spaces still in them.
func TestEmptyStructStillPrints(t *testing.T) {
	s := &Struct{TypeName: "P", Fields: map[string]Object{}}
	if got, want := s.Inspect(), "P {  }"; got != want {
		t.Fatalf("empty struct printed as %q, want %q", got, want)
	}
}
