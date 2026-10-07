package builtin

// Two carriers the walk did not know about, and the wording the runtime's own
// output uses when it withholds a value.
//
// Every one of these uses the disclosure fixture's real record rather than a
// hand-made Classification, because the mark being real is what the shapes are
// about: a hand-made one would also have been found by a walk that got the
// provenance wrong.

import (
	"strings"
	"testing"

	"mutant/object"
)

// carriers are the ways a classified buffer travels inside another value. The
// first six were already found. The last three were not: an error carries its
// buffer in Related, which the walk had no arm for at all, and a value at rest
// carries the mark beside its ciphertext, which nothing read.
func carriers(buffer *object.Bytes) []struct {
	label string
	obj   object.Object
} {
	sealed := &object.Encrypted{
		Value:      []byte{0x9a, 0x3f, 0x01, 0x77},
		EncType:    object.BYTES_OBJ,
		Classified: buffer.Classified,
	}
	hash := makeHashObject(map[string]object.Object{"payload": buffer})

	return []struct {
		label string
		obj   object.Object
	}{
		{"the buffer", buffer},
		{"an array", &object.Array{Elements: []object.Object{buffer}}},
		{"a hash value", hash},
		{"a struct field", &object.Struct{TypeName: "Exhibit", FieldOrder: []string{"header"},
			Fields: map[string]object.Object{"header": buffer}}},
		{"a cell", &object.Cell{Value: buffer}},
		{"a multi-value", &object.MultiValue{Values: []object.Object{buffer}}},

		{"an error's related value", &object.Error{Message: "did not parse",
			Context: "triage", Related: map[string]object.Object{"header": buffer}}},
		{"an error inside an array", &object.Array{Elements: []object.Object{
			&object.Error{Message: "did not parse",
				Related: map[string]object.Object{"header": buffer}}}}},
		{"a value still sealed", sealed},
		{"a cell holding a sealed value", &object.Cell{Value: sealed}},
		{"an array of cells of sealed values", &object.Array{Elements: []object.Object{
			&object.Cell{Value: sealed}}}},
	}
}

func TestEveryCarrierOfAClassifiedBufferIsFound(t *testing.T) {
	_, buffer := classifiedRead(t)
	for _, c := range carriers(buffer) {
		found, deep := FindClassified(c.obj)
		if found == nil {
			t.Errorf("%s: the walk does not find the buffer inside it", c.label)
			continue
		}
		if deep {
			t.Errorf("%s: reported too deep at one level", c.label)
		}
		if found.Classified != buffer.Classified {
			t.Errorf("%s: found a different mark than the one that is there", c.label)
		}
		// The description is what every refusal and every withheld notice is
		// built from, so no carrier may make it carry plaintext.
		assertNoPlaintext(t, c.label, DescribeClassified(found), buffer.Value)
		if !strings.Contains(DescribeClassified(found), buffer.Classified.RecordUID) {
			t.Errorf("%s: the description does not name the record", c.label)
		}
	}
}

// The sinks call the walk, so a carrier the walk now understands is refused by
// all sixteen of them. Three are driven here as the wiring check;
// TestEverySinkRefusesClassifiedPlaintext is what holds the other thirteen to
// calling refuseClassified at all.
func TestSinksRefuseAnErrorCarryingClassifiedPlaintext(t *testing.T) {
	_, buffer := classifiedRead(t)
	wrapped := &object.Error{Message: "did not parse", Context: "triage",
		Related: map[string]object.Object{"header": buffer}}

	var printed strings.Builder
	restore := SetOutput(&printed)
	defer restore()

	// The three sinks driven here take a value of any type, which is what an
	// error carrier needs. A sink whose parameter is typed -- fs_write takes
	// BYTES or STRING -- refuses an error before the walk is reached, for a
	// different and also correct reason, so it proves nothing about this.
	for name, call := range map[string]func() object.Object{
		"putln": func() object.Object { return Putln(stringObj("value:"), wrapped) },
		"putf":  func() object.Object { return Putf(stringObj("%v"), wrapped) },
		"case_note": func() object.Object {
			return CaseNote(stringObj("read the pii"), &object.Array{Elements: []object.Object{wrapped}})
		},
	} {
		result := call()
		message := ""
		switch v := result.(type) {
		case *object.Error:
			message = v.Message
		default:
			if _, errObj := unwrapPairNoFatal(result); errObj != nil {
				message = errObj.Message
			}
		}
		if message == "" {
			t.Errorf("%s accepted an error carrying classified plaintext", name)
			continue
		}
		assertNoPlaintext(t, name, message, buffer.Value)
		if !strings.Contains(message, buffer.Classified.RecordUID) ||
			!strings.Contains(message, "record_release") {
			t.Errorf("%s refused without naming the record and the way out: %s", name, message)
		}
	}

	// Nothing of the buffer reached the output on the way to being refused.
	assertNoPlaintext(t, "stdout", printed.String(), buffer.Value)
}

// WithheldEcho is what runner, repl and dap print in place of a program's last
// value. One wording, so the three cannot drift.
func TestWithheldEchoNamesTheRecordAndNotTheBytes(t *testing.T) {
	_, buffer := classifiedRead(t)

	for _, c := range carriers(buffer) {
		line, withheld := WithheldEcho(c.obj)
		if !withheld {
			t.Errorf("%s: would have been echoed as it is", c.label)
			continue
		}
		assertNoPlaintext(t, c.label, line, buffer.Value)
		if !strings.Contains(line, buffer.Classified.RecordUID) {
			t.Errorf("%s: the notice does not name the record: %s", c.label, line)
		}
		if !strings.Contains(line, "record_release") {
			t.Errorf("%s: the notice does not name the way out: %s", c.label, line)
		}
	}

	// A value with no mark on it is echoed as it is, which is the whole of what
	// an ordinary program sees.
	for _, clean := range []object.Object{
		&object.Integer{Value: 2999},
		stringObj("triage"),
		&object.Bytes{Value: []byte("not classified")},
		&object.Array{Elements: []object.Object{&object.Integer{Value: 1}}},
		&object.Error{Message: "ordinary failure",
			Related: map[string]object.Object{"path": stringObj("/tmp/x")}},
		nil,
	} {
		if line, withheld := WithheldEcho(clean); withheld {
			t.Errorf("an unmarked %T was withheld: %s", clean, line)
		}
	}
}

// A value too deeply nested to walk is withheld too, and says so. The sinks
// refuse one for the same reason: a value that could not be checked has not
// been found clean.
func TestAValueTooDeepToCheckIsWithheld(t *testing.T) {
	_, buffer := classifiedRead(t)
	deep := object.Object(buffer)
	for i := 0; i < classifiedWalkDepth+2; i++ {
		deep = &object.Array{Elements: []object.Object{deep}}
	}
	line, withheld := WithheldEcho(deep)
	if !withheld {
		t.Fatal("a value too deep to check would have been echoed")
	}
	assertNoPlaintext(t, "deep", line, buffer.Value)
	if !strings.Contains(line, "too deep") {
		t.Fatalf("the notice does not say why it was withheld: %s", line)
	}
}

// A mark found on a value still sealed cannot state a plaintext length, and
// says "a sealed value" rather than reporting zero bytes -- which would have
// been a false statement about a buffer that is not empty. An empty buffer read
// out of a record is a legitimate result and is distinguishable, because it is
// an empty slice rather than a nil one.
func TestASealedValueDoesNotClaimALength(t *testing.T) {
	_, buffer := classifiedRead(t)

	sealed := &object.Encrypted{Value: []byte{0x9a, 0x3f}, EncType: object.BYTES_OBJ,
		Classified: buffer.Classified}
	found, _ := FindClassified(sealed)
	if found == nil {
		t.Fatal("a sealed value's mark was not found")
	}
	description := DescribeClassified(found)
	if !strings.Contains(description, "a sealed value") {
		t.Fatalf("a sealed value should say so: %s", description)
	}
	if strings.Contains(description, "0 bytes") {
		t.Fatalf("a sealed value reported a length it cannot know: %s", description)
	}

	empty := &object.Bytes{Value: []byte{}, Classified: buffer.Classified}
	if description := DescribeClassified(empty); !strings.Contains(description, "0 bytes") {
		t.Fatalf("an empty buffer that really is empty should say 0 bytes: %s", description)
	}
}
