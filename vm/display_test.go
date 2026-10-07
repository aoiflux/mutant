package vm

// The runtime's own output, held to two rules: it does not print classified
// plaintext, and it prints the value the program has rather than the bytes the
// value is stored as.
//
// Both renderers used to be separate copies of the same code, so a case that
// held for one proved nothing about the other. Every case here runs at both
// caps, which is what makes that true now rather than true today.

import (
	"strings"
	"testing"

	"mutant/code"
	"mutant/compiler"
	"mutant/object"
)

func displayMark() *object.Classification {
	return &object.Classification{
		RecordUID: "rec-0ea1",
		Tags:      []string{"7f3a9c1e5b8d2406"},
		Labels:    []string{"pii"},
	}
}

// displayPlaintext is long enough that a 48-character cap truncates it and a
// 256-character cap does not, which is how the two caps were measured to leak
// different amounts of it.
const displayPlaintext = "TOP-SECRET-PLAINTEXT-0123456789"

func displaySecret() *object.Bytes {
	return &object.Bytes{Value: []byte(displayPlaintext), Classified: displayMark()}
}

// leaks reports whether text carries the plaintext, as text or as the hex
// Inspect renders a buffer in. Eight bytes is enough to be certain and short
// enough to survive a cap.
func leaks(text string) bool {
	const hexDigits = "0123456789abcdef"
	var hex strings.Builder
	for _, b := range []byte(displayPlaintext[:8]) {
		hex.WriteByte(hexDigits[b>>4])
		hex.WriteByte(hexDigits[b&0x0f])
	}
	return strings.Contains(text, displayPlaintext[:8]) || strings.Contains(text, hex.String())
}

// classifiedShapes are every way a marked buffer reaches a renderer. Four of
// them never pass through the *object.Bytes branch at all, which is why
// guarding that branch alone would not have been a fix: a cell, an array, a
// struct field and an error each fall through to Inspect, and a buffer's
// Inspect is its entire hex.
func classifiedShapes() []struct {
	label string
	obj   object.Object
} {
	hash := &object.Hash{Pairs: map[object.HashKey]object.HashPair{}}
	key := &object.String{Value: "header"}
	hash.Pairs[key.HashKey()] = object.HashPair{Key: key, Value: displaySecret()}

	return []struct {
		label string
		obj   object.Object
	}{
		{"the buffer itself", displaySecret()},
		{"a captured variable's cell", &object.Cell{Value: displaySecret()}},
		{"an array holding it", &object.Array{Elements: []object.Object{displaySecret()}}},
		{"a hash value", hash},
		{"a struct field", &object.Struct{TypeName: "Exhibit", FieldOrder: []string{"header"},
			Fields: map[string]object.Object{"header": displaySecret()}}},
		{"an error's related value", &object.Error{Message: "did not parse", Context: "triage",
			Related: map[string]object.Object{"header": displaySecret()}}},
		{"an enum payload", &object.EnumValue{TypeName: "Found", Tag: "yes", Value: displaySecret()}},
		{"a returned value", &object.ReturnValue{Value: displaySecret()}},
		{"a multi-value", &object.MultiValue{Values: []object.Object{displaySecret()}}},
		{"a value still sealed", &object.Encrypted{Value: []byte{0x9a, 0x3f, 0x01},
			EncType: object.BYTES_OBJ, Classified: displayMark()}},
		{"a cell holding a sealed value", &object.Cell{Value: &object.Encrypted{
			Value: []byte{0x9a, 0x3f, 0x01}, EncType: object.BYTES_OBJ, Classified: displayMark()}}},
	}
}

// Both caps, for every shape. maxRenderedArgValue is the traceback's and
// maxDebugValue is the variables pane's; the pane was the worse of the two,
// because 256 characters is enough room to print a 31-byte buffer whole.
var displayCaps = []struct {
	name  string
	limit int
}{
	{"traceback", maxRenderedArgValue},
	{"debug pane", maxDebugValue},
}

func TestNoShapeOfAClassifiedBufferIsRendered(t *testing.T) {
	for _, cap := range displayCaps {
		for _, shape := range classifiedShapes() {
			out := renderForDisplay(shape.obj, cap.limit)
			if leaks(out) {
				t.Errorf("%s (cap %d): %s rendered the plaintext: %s",
					cap.name, cap.limit, shape.label, out)
			}
			// A renderer that printed nothing would also not leak, so the
			// replacement has to say which record it stood in for. This is
			// why the notice is exempt from the cap: at 48 characters the
			// description truncated before reaching the record uid, and a
			// notice that names no record is not worth printing.
			if !strings.Contains(out, "rec-0ea1") {
				t.Errorf("%s (cap %d): %s does not name the record it withheld: %s",
					cap.name, cap.limit, shape.label, out)
			}
			// Bounded, though not by the cap: a fixed sentence, a record uid
			// and a class name, and nothing whose size the program chose.
			if len(out) > 200 {
				t.Errorf("%s (cap %d): %s rendered a %d-character notice: %s",
					cap.name, cap.limit, shape.label, len(out), out)
			}
			// Both renderers say the same thing about the same value, which is
			// the property the two separate copies could not have had.
			if other := renderForDisplay(shape.obj, maxDebugValue); other != out {
				t.Errorf("%s: %s renders differently at the two caps: %q vs %q",
					cap.name, shape.label, out, other)
			}
		}
	}
}

// The two renderers are the same renderer, so a shape fixed in one is fixed in
// the other. This is the property that the duplicated code could not have.
func TestTheTracebackAndThePaneAgree(t *testing.T) {
	for _, shape := range classifiedShapes() {
		if got := renderArgValue(shape.obj); leaks(got) {
			t.Errorf("renderArgValue leaked on %s: %s", shape.label, got)
		}
		if got := renderDebugValue(shape.obj); leaks(got) {
			t.Errorf("renderDebugValue leaked on %s: %s", shape.label, got)
		}
	}
}

// A value nested past the walk's depth is not rendered either. The sinks refuse
// one for the same reason: a value that could not be checked has not been
// found clean.
func TestAValueTooDeepToCheckIsNotRendered(t *testing.T) {
	deep := object.Object(displaySecret())
	for i := 0; i < 200; i++ {
		deep = &object.Array{Elements: []object.Object{deep}}
	}
	out := renderForDisplay(deep, maxDebugValue)
	if leaks(out) {
		t.Fatalf("a deeply nested buffer was rendered: %s", out)
	}
	if !strings.Contains(out, "too deeply nested") {
		t.Fatalf("a value too deep to check should say so, got: %s", out)
	}
}

// Nothing else changes. An unmarked value renders as it did, including the two
// behaviours the old renderers had: a buffer previews rather than printing its
// whole hex, and a value whose Inspect is empty falls back to its type.
func TestAnUnmarkedValueRendersAsBefore(t *testing.T) {
	for _, c := range []struct {
		label string
		obj   object.Object
		want  string
	}{
		{"integer", &object.Integer{Value: 2999}, "2999"},
		{"string", &object.String{Value: "triage"}, "triage"},
		{"boolean", &object.Boolean{Value: true}, "true"},
		{"nil", nil, "<unset>"},
	} {
		if got := renderForDisplay(c.obj, maxRenderedArgValue); got != c.want {
			t.Errorf("%s rendered %q, want %q", c.label, got, c.want)
		}
	}

	// An unmarked buffer still previews: Inspect would render the whole hex,
	// and a display only ever wanted the front of it.
	unmarked := &object.Bytes{Value: []byte(displayPlaintext)}
	out := renderForDisplay(unmarked, maxRenderedArgValue)
	if len(out) > maxRenderedArgValue {
		t.Errorf("an unmarked buffer rendered %d characters: %s", len(out), out)
	}
	if !strings.HasPrefix(out, "bytes(") {
		t.Errorf("an unmarked buffer should preview as bytes(N) ...: %s", out)
	}
}

// Multi-line values are rendered on one line, because a traceback line and a
// pane row each get one.
func TestARenderedValueIsOneLine(t *testing.T) {
	multi := &object.String{Value: "first\nsecond\tthird"}
	out := renderForDisplay(multi, maxDebugValue)
	if strings.ContainsAny(out, "\n\t") {
		t.Fatalf("rendered across lines: %q", out)
	}
}

// unwrapForDisplay: the cell comes off before the decrypt, and never after.
//
// A cell is a storage location that mutil.DecryptObject hands back by pointer
// without opening, so decrypting first returns the same cell with its
// ciphertext still inside, and Cell.Inspect renders that. The invariant is that
// what comes back is never a cell.
func TestUnwrapForDisplayTakesTheCellOff(t *testing.T) {
	machine := New(&compiler.ByteCode{Instructions: code.Instructions{}, Constants: nil})

	if got := machine.unwrapForDisplay(nil); got != nil {
		t.Errorf("nil unwrapped to %#v", got)
	}
	if got := machine.unwrapForDisplay(&object.Cell{Value: nil}); got != nil {
		t.Errorf("an empty cell unwrapped to %#v, want nil", got)
	}

	for _, c := range []struct {
		label string
		raw   object.Object
	}{
		{"a cell holding an integer", &object.Cell{Value: &object.Integer{Value: 2999}}},
		{"a cell holding a cell's worth of ciphertext", &object.Cell{Value: &object.Encrypted{
			Value: []byte{0x9a, 0x3f, 0x01}, EncType: object.BYTES_OBJ}}},
		{"an integer, not in a cell", &object.Integer{Value: 7}},
	} {
		got := machine.unwrapForDisplay(c.raw)
		if _, isCell := got.(*object.Cell); isCell {
			t.Errorf("%s unwrapped to a cell again: %#v", c.label, got)
		}
	}

	// The value itself survives: a captured integer reads as the integer, which
	// is what the traceback printed as ciphertext before.
	got := machine.unwrapForDisplay(&object.Cell{Value: &object.Integer{Value: 2999}})
	if integer, ok := got.(*object.Integer); !ok || integer.Value != 2999 {
		t.Fatalf("a captured 2999 unwrapped to %#v", got)
	}
	if rendered := renderForDisplay(got, maxRenderedArgValue); rendered != "2999" {
		t.Fatalf("a captured 2999 renders as %q", rendered)
	}
}
