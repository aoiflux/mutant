package mutil

import (
	"bytes"
	"fmt"
	"sort"
	"testing"

	"mutant/global"
	"mutant/object"
	"mutant/security"
)

// M26-VM-001: the seal path takes a derived key from a caller that already has
// one, instead of deriving it again in every arm. Two SHA-256 hashes per eight
// bytes of payload was the cost of a container load, and the VM derives the
// same (seed, password) stream for its instructions anyway.
//
// Two things have to hold for that to be a performance change rather than a
// behaviour change. What is stored must be byte for byte what deriving would
// have stored, so a value is readable by any path that opens it; and a stream
// must answer only for the seed it was derived under, because a stored value
// records its own seed and the REPL routinely reads one sealed under a seed its
// current VM does not have.
const (
	sealTestSeed     = 1234
	sealTestPassword = "a password for the seal path"
)

type sealShape struct {
	name  string
	value object.Object
}

// sealShapes is one value of every shape the seal path has an arm for, so the
// equivalence below is not a claim about strings.
func sealShapes() []sealShape {
	key := &object.String{Value: "a"}
	return []sealShape{
		{"an integer", &object.Integer{Value: -42}},
		{"a string", &object.String{Value: "secret"}},
		{"an empty string", &object.String{Value: ""}},
		{"a buffer", &object.Bytes{Value: []byte{0, 1, 2, 250}}},
		{"a classified buffer", &object.Bytes{Value: []byte{7, 7}, Classified: &object.Classification{
			RecordUID: "rec-1", Tags: []string{"tag"}, Labels: []string{"label"},
		}}},
		{"a boolean", &object.Boolean{Value: true}},
		{"a float", &object.Float{Value: 3.5}},
		{"null", global.Null},
		{"an array holding an empty string", &object.Array{Elements: []object.Object{
			&object.Integer{Value: 1}, &object.String{Value: ""}, &object.String{Value: "secret"},
		}}},
		{"a nested array", &object.Array{Elements: []object.Object{
			&object.Array{Elements: []object.Object{&object.Integer{Value: 2}}},
		}}},
		{"a hash", &object.Hash{Pairs: map[object.HashKey]object.HashPair{
			key.HashKey(): {Key: key, Value: &object.String{Value: "secret"}},
		}}},
		{"a struct", &object.Struct{TypeName: "P", Fields: map[string]object.Object{
			"x": &object.Integer{Value: 1},
			"y": &object.String{Value: "secret"},
		}}},
		{"a multi-value", &object.MultiValue{Values: []object.Object{
			&object.Integer{Value: 1}, &object.String{Value: "secret"},
		}}},
		{"an enum value", &object.EnumValue{TypeName: "E", Tag: "Tag",
			Value: &object.Integer{Value: 7}}},
		{"an error", &object.Error{Message: "boom", Context: "ctx", Line: 3}},
	}
}

// canonical renders a value so that two of them can be compared.
//
// Inspect() cannot do it: object.Struct and object.Hash render by walking a Go
// map, so the field order is whatever that walk gives this time, and an opened
// copy is a different map from the original. Comparing the two strings was a
// test that passed about half the time it ran.
func canonical(obj object.Object) string {
	switch v := obj.(type) {
	case *object.Array:
		return "array[" + canonicalList(v.Elements) + "]"
	case *object.MultiValue:
		return "multi[" + canonicalList(v.Values) + "]"
	case *object.Hash:
		parts := make([]string, 0, len(v.Pairs))
		for _, pair := range v.Pairs {
			parts = append(parts, canonical(pair.Key)+"="+canonical(pair.Value))
		}
		sort.Strings(parts)
		return "hash{" + fmt.Sprint(parts) + "}"
	case *object.Struct:
		parts := make([]string, 0, len(v.Fields))
		for name, field := range v.Fields {
			parts = append(parts, name+"="+canonical(field))
		}
		sort.Strings(parts)
		return v.TypeName + "{" + fmt.Sprint(parts) + "}"
	case *object.EnumValue:
		inner := "-"
		if v.Value != nil {
			inner = canonical(v.Value)
		}
		return v.TypeName + "." + v.Tag + "(" + inner + ")"
	case *object.Error:
		return fmt.Sprintf("error(%s/%s/%d)", v.Message, v.Context, v.Line)
	case *object.Bytes:
		return fmt.Sprintf("bytes(%x/%v)", v.Value, v.Classified)
	default:
		return string(obj.Type()) + "(" + obj.Inspect() + ")"
	}
}

func canonicalList(values []object.Object) string {
	parts := make([]string, 0, len(values))
	for _, value := range values {
		parts = append(parts, canonical(value))
	}
	return fmt.Sprint(parts)
}

// payloads collects every sealed payload in a stored value, sorted, so two
// stored forms can be compared without depending on the order a map is walked
// in.
func payloads(obj object.Object) []string {
	var found []string
	var walk func(object.Object)
	walk = func(o object.Object) {
		switch v := o.(type) {
		case *object.Encrypted:
			found = append(found, fmt.Sprintf("%s/%v:%x", v.EncType, v.Classified, v.Value))
		case *object.Array:
			for _, element := range v.Elements {
				walk(element)
			}
		case *object.MultiValue:
			for _, element := range v.Values {
				walk(element)
			}
		case *object.Hash:
			for _, pair := range v.Pairs {
				walk(pair.Key)
				walk(pair.Value)
			}
		case *object.Struct:
			for _, field := range v.Fields {
				walk(field)
			}
		case *object.EnumValue:
			if v.Value != nil {
				walk(v.Value)
			}
		case *object.LuaPatch:
			found = append(found, fmt.Sprintf("lua:%x", v.EncryptedPayload))
		default:
			found = append(found, fmt.Sprintf("clear:%s", o.Inspect()))
		}
	}
	walk(obj)
	sort.Strings(found)
	return found
}

func TestHandingInTheStreamChangesNothingAboutWhatIsStored(t *testing.T) {
	stream := security.NewXORStream(sealTestSeed, sealTestPassword)

	for _, shape := range sealShapes() {
		t.Run(shape.name, func(t *testing.T) {
			derived, err := EncryptObject(shape.value, sealTestSeed, sealTestPassword)
			if err != nil {
				t.Fatalf("seal by deriving: %s", err)
			}
			streamed, err := EncryptObjectWithStream(shape.value, sealTestSeed,
				sealTestPassword, stream)
			if err != nil {
				t.Fatalf("seal with the stream: %s", err)
			}

			want := payloads(derived)
			got := payloads(streamed)
			if len(want) == 0 {
				t.Fatal("nothing was sealed; the comparison proves nothing")
			}
			if fmt.Sprint(got) != fmt.Sprint(want) {
				t.Errorf("the stream stored\n  %v\nwhere deriving stores\n  %v", got, want)
			}
		})
	}
}

func TestAStreamOpensWhatDerivingSealedAndTheOtherWayRound(t *testing.T) {
	stream := security.NewXORStream(sealTestSeed, sealTestPassword)

	for _, shape := range sealShapes() {
		t.Run(shape.name, func(t *testing.T) {
			want := canonical(shape.value)

			sealed, err := EncryptObject(shape.value, sealTestSeed, sealTestPassword)
			if err != nil {
				t.Fatalf("seal by deriving: %s", err)
			}
			opened, err := DecryptObjectWithStream(sealed, sealTestSeed, sealTestPassword, stream)
			if err != nil {
				t.Fatalf("open with the stream: %s", err)
			}
			if canonical(opened) != want {
				t.Errorf("the stream opened it as %s, want %s", canonical(opened), want)
			}

			sealed, err = EncryptObjectWithStream(shape.value, sealTestSeed,
				sealTestPassword, stream)
			if err != nil {
				t.Fatalf("seal with the stream: %s", err)
			}
			opened, err = DecryptObject(sealed, sealTestSeed, sealTestPassword)
			if err != nil {
				t.Fatalf("open by deriving: %s", err)
			}
			if canonical(opened) != want {
				t.Errorf("deriving opened it as %s, want %s", canonical(opened), want)
			}
		})
	}
}

// TestAValueKeepsTheSeedItWasSealedUnder is the REPL's case, and the one way
// this change could have corrupted data in silence.
//
// The REPL compiles a new program per line and keeps one global store, so the
// seed -- the instruction length -- moves while the values do not. A stream
// that answered for a seed it was not derived under would not fail; it would
// return plausible bytes, and an integer would come back as a different
// integer.
func TestAValueKeepsTheSeedItWasSealedUnder(t *testing.T) {
	const earlier, later = 100, 200

	shapes := []sealShape{
		{"a string", &object.String{Value: "from an earlier line"}},
		{"an integer", &object.Integer{Value: 777}},
		{"an array", &object.Array{Elements: []object.Object{
			&object.Integer{Value: 1}, &object.String{Value: "two"},
		}}},
	}

	for _, shape := range shapes {
		t.Run(shape.name, func(t *testing.T) {
			want := canonical(shape.value)

			// Sealed by the earlier line, read by the later one.
			sealed, err := EncryptObject(shape.value, earlier, sealTestPassword)
			if err != nil {
				t.Fatalf("seal: %s", err)
			}
			opened, err := DecryptObjectWithStream(sealed, later, sealTestPassword,
				security.NewXORStream(later, sealTestPassword))
			if err != nil {
				t.Fatalf("open with a later line's stream: %s", err)
			}
			if canonical(opened) != want {
				t.Errorf("read back as %s, want %s", canonical(opened), want)
			}

			// And the other direction: sealed with a stream, read by a VM that
			// derives for its own seed.
			sealed, err = EncryptObjectWithStream(shape.value, earlier, sealTestPassword,
				security.NewXORStream(earlier, sealTestPassword))
			if err != nil {
				t.Fatalf("seal with the stream: %s", err)
			}
			opened, err = DecryptObject(sealed, later, sealTestPassword)
			if err != nil {
				t.Fatalf("open by deriving: %s", err)
			}
			if canonical(opened) != want {
				t.Errorf("read back as %s, want %s", canonical(opened), want)
			}
		})
	}
}

// TestSealKeyUsesTheStreamOnlyForItsOwnSeed says the same thing one layer down,
// where the decision is actually made.
func TestSealKeyUsesTheStreamOnlyForItsOwnSeed(t *testing.T) {
	key := sealKey{
		length:   sealTestSeed,
		password: sealTestPassword,
		stream:   security.NewXORStream(sealTestSeed, sealTestPassword),
	}
	data := []byte("eight by.")

	own, err := key.xorAtSeed(data, sealTestSeed)
	if err != nil {
		t.Fatalf("its own seed: %s", err)
	}
	want, err := security.SecureXOR(data, sealTestSeed, sealTestPassword)
	if err != nil {
		t.Fatalf("derive: %s", err)
	}
	if !bytes.Equal(own, want) {
		t.Errorf("the stream gave %x for its own seed, deriving gives %x", own, want)
	}

	foreign, err := key.xorAtSeed(data, 7)
	if err != nil {
		t.Fatalf("a foreign seed: %s", err)
	}
	want, err = security.SecureXOR(data, 7, sealTestPassword)
	if err != nil {
		t.Fatalf("derive: %s", err)
	}
	if !bytes.Equal(foreign, want) {
		t.Errorf("a foreign seed gave %x, deriving for it gives %x", foreign, want)
	}
}

// TestANilStreamDerivesAsItAlwaysDid keeps the new entry points usable by a
// caller that has no stream, which is every caller but the VM.
func TestANilStreamDerivesAsItAlwaysDid(t *testing.T) {
	value := &object.String{Value: "secret"}

	derived, err := EncryptObject(value, sealTestSeed, sealTestPassword)
	if err != nil {
		t.Fatalf("seal: %s", err)
	}
	withNil, err := EncryptObjectWithStream(value, sealTestSeed, sealTestPassword, nil)
	if err != nil {
		t.Fatalf("seal with no stream: %s", err)
	}
	if fmt.Sprint(payloads(withNil)) != fmt.Sprint(payloads(derived)) {
		t.Error("a nil stream stored something other than what deriving stores")
	}

	opened, err := DecryptObjectWithStream(derived, sealTestSeed, sealTestPassword, nil)
	if err != nil {
		t.Fatalf("open with no stream: %s", err)
	}
	if canonical(opened) != canonical(value) {
		t.Errorf("read back as %s, want %s", canonical(opened), canonical(value))
	}
}

// TestAnEmptyPayloadInsideAContainerStillCoversItsSiblings re-asserts the bug
// the xorPayload comment describes, through the stream path: the empty-payload
// short-circuit moved onto sealKey, and losing it would leave every sibling of
// an empty string in the clear.
func TestAnEmptyPayloadInsideAContainerStillCoversItsSiblings(t *testing.T) {
	value := &object.Array{Elements: []object.Object{
		&object.String{Value: ""}, &object.String{Value: "secret"},
	}}

	sealed, err := EncryptObjectWithStream(value, sealTestSeed, sealTestPassword,
		security.NewXORStream(sealTestSeed, sealTestPassword))
	if err != nil {
		t.Fatalf("seal with the stream: %s", err)
	}

	stored, ok := sealed.(*object.Array)
	if !ok {
		t.Fatalf("an array sealed into %T", sealed)
	}
	for i, element := range stored.Elements {
		if _, sealed := element.(*object.Encrypted); !sealed {
			t.Errorf("element %d is %s in the clear: %s", i, element.Type(), element.Inspect())
		}
	}
}
