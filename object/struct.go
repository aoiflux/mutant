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
// FieldNames returns the struct's field names in the order Inspect renders
// them: the declaration's order first, then any name Fields holds that
// FieldOrder does not, sorted.
//
// Nothing a program can write reaches that second group today -- the compiler
// fills exactly the declared fields, and since 2.6.0 nothing may add one -- but
// dropping a field that is there would hide a value from the two functions
// whose job is to show it.
func (s *Struct) FieldNames() []string {
	names := make([]string, 0, len(s.Fields))
	shown := make(map[string]bool, len(s.Fields))
	for _, name := range s.FieldOrder {
		if _, declared := s.Fields[name]; !declared || shown[name] {
			continue
		}
		shown[name] = true
		names = append(names, name)
	}

	if len(shown) != len(s.Fields) {
		rest := make([]string, 0, len(s.Fields)-len(shown))
		for name := range s.Fields {
			if !shown[name] {
				rest = append(rest, name)
			}
		}
		sort.Strings(rest)
		names = append(names, rest...)
	}
	return names
}

// The order is FieldNames', which every refusal that lists the fields also
// reads, so a message and the value it is about never disagree.
func (s *Struct) Inspect() string {
	var out bytes.Buffer

	names := s.FieldNames()
	fields := make([]string, 0, len(names))
	for _, name := range names {
		fields = append(fields, fmt.Sprintf("%s: %s", name, s.Fields[name].Inspect()))
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

// A field a struct does not declare is refused, and these are the words every
// decider refuses it with.
//
// One set of words rather than one per engine. The compiler refuses this where
// it can prove the receiver's type, both engines refuse it where it cannot, and
// the editor says it before either runs -- four wordings for one mistake is how
// parity/ gets its rows. The evaluator's enum refusal records the alternative
// taken there: "the VM's words, because they are the same refusal", copied by
// hand into the other engine.
//
// Each takes the declared names rather than reading them off a value, because
// the compiler has a declaration and no value, while the engines have a value
// whose field set that declaration fixed.

// UnknownStructFieldMessage is a read of a field the type does not declare.
func UnknownStructFieldMessage(typeName, field string, declared []string) string {
	return fmt.Sprintf("struct %s has no field %s: %s", typeName, field, declaresClause(declared))
}

// UnknownStructFieldWriteMessage is a write to one.
//
// A write says more than a read, because until 2.6.0 it silently created the
// field: the author may be expecting it to, so the message says the field set is
// fixed rather than only that the name is unknown.
func UnknownStructFieldWriteMessage(typeName, field string, declared []string) string {
	return fmt.Sprintf(
		"cannot set field %s on struct %s: %s, and a struct's fields are fixed by its declaration",
		field, typeName, declaresClause(declared))
}

// StructLiteralRefusal is a literal whose field names are not the declaration's.
//
// Both directions in one message, because one typo makes one of each: a field
// the declaration does not contain, and a declared field nothing set. Reporting
// only the second is what `P { a: 1, c: 3 }` used to do -- it said "missing
// field b", which sent the author to look at a field they had not touched.
func StructLiteralRefusal(typeName string, unknown, missing, declared []string) string {
	var faults []string
	if len(unknown) > 0 {
		faults = append(faults, fmt.Sprintf("has no %s %s",
			pluralField(len(unknown)), strings.Join(unknown, ", ")))
	}
	if len(missing) > 0 {
		faults = append(faults, fmt.Sprintf("needs %s for %s %s",
			pluralValue(len(missing)), pluralField(len(missing)), strings.Join(missing, ", ")))
	}
	if len(faults) == 0 {
		// Unreachable from a caller that checked first; an empty refusal would
		// be worse than a vague one.
		return fmt.Sprintf("struct %s: %s", typeName, declaresClause(declared))
	}
	return fmt.Sprintf("struct %s %s: %s",
		typeName, strings.Join(faults, " and "), declaresClause(declared))
}

// A field name written twice. Two messages because they are two mistakes: a
// declaration that repeats one is incoherent, and a literal that sets one twice
// has a value it silently drops.
//
// They exist because the struct-literal refusal reports the field NAMES that
// differ rather than the field COUNT, and a repeated name is the one way the
// counts can differ while the name sets agree. Refusing a repeat at its own
// source is what makes "a count that differs means the names differ" true.

func DuplicateStructFieldDeclarationMessage(typeName, field string) string {
	return fmt.Sprintf("struct %s declares field %s twice", typeName, field)
}

func DuplicateStructFieldLiteralMessage(typeName, field string) string {
	return fmt.Sprintf("struct %s sets field %s twice", typeName, field)
}

func declaresClause(declared []string) string {
	if len(declared) == 0 {
		return "it declares no fields"
	}
	return "it declares " + strings.Join(declared, ", ")
}

func pluralField(n int) string {
	if n == 1 {
		return "field"
	}
	return "fields"
}

func pluralValue(n int) string {
	if n == 1 {
		return "a value"
	}
	return "values"
}
