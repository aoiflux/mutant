package object

import (
	"bytes"
	"fmt"
	"sort"
	"strings"
)

type Struct struct {
	TypeName string

	// FieldOrder is the order the struct's own declaration gave its fields.
	//
	// Fields is a map and a map has no order, so without this the only orders
	// available were "whatever this range happened to yield" and alphabetical.
	// A struct differs from a hash in having an authored order, and a report
	// that prints a record should read the way the record was declared.
	//
	// It is derived, not authoritative: Fields is the value. A name in one and
	// not the other is handled by Inspect rather than trusted, because the two
	// are filled by separate statements in both engines.
	FieldOrder []string

	Fields map[string]Object
}

func (s *Struct) Type() ObjectType {
	return STRUCT_OBJ
}

// Inspect renders the struct with its fields in declaration order.
//
// It used to range Fields directly. Ranging a Go map yields a different order on
// every call -- not merely on every run -- and Inspect was the identity both
// engines compared structs by, so two structs built from the same literal were
// usually unequal, a struct was usually unequal to itself, and a printed struct
// differed between runs of the same program on the same input.
//
// Hash.Inspect was given a stable order for the printing half of the same defect
// and sorts its keys, because a hash has no authored order to render in. A
// struct has one, so it renders in that: `P { b: 2, a: 1 }` for a struct that
// declares b before a, however the literal was written.
//
// A name Fields holds that FieldOrder does not comes last, in sorted order.
// Nothing a program can write reaches that today -- the compiler fills exactly
// the declared fields -- but dropping a field that is there would hide a value
// from the one function whose job is to show it.
func (s *Struct) Inspect() string {
	var out bytes.Buffer

	fields := make([]string, 0, len(s.Fields))
	shown := make(map[string]bool, len(s.Fields))
	for _, name := range s.FieldOrder {
		value, declared := s.Fields[name]
		if !declared || shown[name] {
			continue
		}
		shown[name] = true
		fields = append(fields, fmt.Sprintf("%s: %s", name, value.Inspect()))
	}

	if len(shown) != len(s.Fields) {
		rest := make([]string, 0, len(s.Fields)-len(shown))
		for name := range s.Fields {
			if !shown[name] {
				rest = append(rest, name)
			}
		}
		sort.Strings(rest)
		for _, name := range rest {
			fields = append(fields, fmt.Sprintf("%s: %s", name, s.Fields[name].Inspect()))
		}
	}

	out.WriteString(s.TypeName)
	out.WriteString(" { ")
	out.WriteString(strings.Join(fields, ", "))
	out.WriteString(" }")

	return out.String()
}

// Equals reports whether two structs are the same value: the same type, the same
// field names, and a field-by-field equal value.
//
// `==` compared Inspect, which is how comparing two structs became a coin toss.
// Comparing the rendered forms would answer correctly now that Inspect has an
// order, and it would still be wrong in the way it is wrong for buffers, errors
// and enum values: a string spelling `P { a: 1 }` would be equal to the struct.
// It would also cost a full recursive render of both sides to answer a question
// that can stop at the first field that differs.
//
// FieldOrder takes no part. Two structs of one type always have one order, and a
// difference in it would be a defect in whatever built them rather than a
// difference in the value they hold.
func (s *Struct) Equals(other *Struct) bool {
	if s == nil || other == nil {
		return s == other
	}
	if s.TypeName != other.TypeName || len(s.Fields) != len(other.Fields) {
		return false
	}
	for name, value := range s.Fields {
		otherValue, present := other.Fields[name]
		if !present || !ValuesEqual(value, otherValue) {
			return false
		}
	}
	return true
}
