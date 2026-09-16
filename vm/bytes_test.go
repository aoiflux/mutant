package vm

import (
	"bytes"
	"fmt"
	"testing"

	"mutant/mutil"
	"mutant/object"
	"mutant/security"
)

// runBytes compiles and runs src through the sealed path and returns the last
// value the program left on the stack.
func runBytes(t *testing.T, src string) object.Object {
	t.Helper()

	machine, err := runSealed(t, compileFresh(t, src))
	if err != nil {
		t.Fatalf("run %q: %v", src, err)
	}
	return machine.LastPoppedStackElement()
}

// valueOf follows the (value, err) convention into a MULTI_VALUE.
func valueOf(obj object.Object) object.Object {
	if multi, ok := obj.(*object.MultiValue); ok && len(multi.Values) > 0 {
		return multi.Values[0]
	}
	return obj
}

func TestBytesRoundTripThroughTheConversions(t *testing.T) {
	// Every byte 0x00-0xFF, the input that breaks a rune-based path.
	src := `let all = "";
for (let i = 0; i < 256; i = i + 1) {
	let ch, e = bytes_char_from_int(i);
	all = all + ch;
}
let buf, err = string_to_bytes(all, "raw");
buf;`

	value := valueOf(runBytes(t, src))
	buf, ok := value.(*object.Bytes)
	if !ok {
		t.Fatalf("string_to_bytes returned %T, want *object.Bytes", value)
	}
	if len(buf.Value) != 256 {
		t.Fatalf("buffer holds %d bytes, want 256", len(buf.Value))
	}
	for i, b := range buf.Value {
		if int(b) != i {
			t.Fatalf("byte %d is 0x%02x, want 0x%02x", i, b, i)
		}
	}
}

func TestBytesConcatenationProducesAFreshBuffer(t *testing.T) {
	src := `let a, e1 = string_to_bytes("4d5a", "hex");
let b, e2 = string_to_bytes("9000", "hex");
a + b;`

	buf, ok := runBytes(t, src).(*object.Bytes)
	if !ok {
		t.Fatalf("bytes + bytes produced %T", runBytes(t, src))
	}
	if !bytes.Equal(buf.Value, []byte{0x4d, 0x5a, 0x90, 0x00}) {
		t.Errorf("concatenation = %x, want 4d5a9000", buf.Value)
	}
}

// Equality is where a hex Inspect would have leaked: the fallback compares
// rendered forms, so without an explicit arm a buffer would equal the string
// spelling its own hex.
func TestBytesEqualityIsByContentAndType(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want bool
	}{
		{"equal buffers", `let a, e1 = string_to_bytes("4d5a", "hex");
let b, e2 = string_to_bytes("4d5a", "hex");
a == b;`, true},
		{"different buffers", `let a, e1 = string_to_bytes("4d5a", "hex");
let b, e2 = string_to_bytes("9000", "hex");
a == b;`, false},
		{"a buffer never equals the string of its hex", `let a, e1 = string_to_bytes("4d5a", "hex");
a == "4d5a";`, false},
		{"nor the raw text with the same bytes", `let a, e1 = string_to_bytes("MZ", "raw");
a == "MZ";`, false},
		{"inequality is the negation", `let a, e1 = string_to_bytes("4d5a", "hex");
a != "4d5a";`, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result, ok := runBytes(t, tc.src).(*object.Boolean)
			if !ok {
				t.Fatalf("comparison produced %T", runBytes(t, tc.src))
			}
			if result.Value != tc.want {
				t.Errorf("%s = %v, want %v", tc.name, result.Value, tc.want)
			}
		})
	}
}

// Indexing yields an integer, which is where buffers deliberately part company
// with strings: a buffer is indexed to compare a value, not to take a substring.
func TestBytesIndexYieldsAnInteger(t *testing.T) {
	cases := []struct {
		src  string
		want int64
	}{
		{`let b, e = string_to_bytes("4d5a90", "hex");
b[0];`, 0x4d},
		{`let b, e = string_to_bytes("4d5a90", "hex");
b[2];`, 0x90},
		{`let b, e = string_to_bytes("4d5a90", "hex");
b[-1];`, 0x90},
	}

	for _, tc := range cases {
		got, ok := runBytes(t, tc.src).(*object.Integer)
		if !ok {
			t.Fatalf("%q produced %T, want INTEGER", tc.src, runBytes(t, tc.src))
		}
		if got.Value != tc.want {
			t.Errorf("%q = %d, want %d", tc.src, got.Value, tc.want)
		}
	}

	// Past the end is null, as it is for arrays and strings.
	if _, ok := runBytes(t, "let b, e = string_to_bytes(\"4d\", \"hex\");\nb[9];").(*object.Null); !ok {
		t.Error("an out-of-range index did not produce null")
	}
}

func TestBytesIndexAssignmentWritesOneByte(t *testing.T) {
	src := `let b, e = string_to_bytes("4d5a", "hex");
b[0] = 255;
b;`

	buf, ok := runBytes(t, src).(*object.Bytes)
	if !ok {
		t.Fatalf("index assignment produced %T", runBytes(t, src))
	}
	if !bytes.Equal(buf.Value, []byte{0xff, 0x5a}) {
		t.Errorf("buffer = %x, want ff5a", buf.Value)
	}
}

// A buffer holds bytes, so storing anything that is not a byte has to fail
// rather than truncate: b[0] = 256 silently writing a zero is the class of bug
// this whole type exists to remove.
func TestBytesIndexAssignmentRejectsNonBytes(t *testing.T) {
	for _, src := range []string{
		"let b, e = string_to_bytes(\"4d5a\", \"hex\");\nb[0] = 256;\n",
		"let b, e = string_to_bytes(\"4d5a\", \"hex\");\nb[0] = -1;\n",
		"let b, e = string_to_bytes(\"4d5a\", \"hex\");\nb[0] = \"z\";\n",
		"let b, e = string_to_bytes(\"4d5a\", \"hex\");\nb[9] = 1;\n",
	} {
		if _, err := runSealed(t, compileFresh(t, src)); err == nil {
			t.Errorf("%q was accepted", src)
		}
	}
}

func TestBytesTruthinessAndLength(t *testing.T) {
	src := `let empty, e1 = string_to_bytes("", "raw");
let full, e2 = string_to_bytes("4d", "hex");
let out = [];
if (empty) { out = push(out, "empty-truthy"); }
if (full) { out = push(out, "full-truthy"); }
out = push(out, len(full));
out;`

	arr, ok := runBytes(t, src).(*object.Array)
	if !ok {
		t.Fatalf("produced %T", runBytes(t, src))
	}
	if len(arr.Elements) != 2 {
		t.Fatalf("got %d elements (%s), want 2 -- an empty buffer must be falsy", len(arr.Elements), arr.Inspect())
	}
	if arr.Elements[0].Inspect() != "full-truthy" {
		t.Errorf("first element = %q, want full-truthy", arr.Elements[0].Inspect())
	}
	if arr.Elements[1].Inspect() != "1" {
		t.Errorf("len(buffer) = %s, want 1", arr.Elements[1].Inspect())
	}
}

func TestBytesWorkAsHashKeys(t *testing.T) {
	src := `let k, e = string_to_bytes("4d5a", "hex");
let h = {};
h[k] = "mz";
h[k];`

	if got := runBytes(t, src).Inspect(); got != "mz" {
		t.Errorf("buffer key lookup = %q, want %q", got, "mz")
	}
}

// The silent-failure mode: EncryptObject's default arm returns an error that
// both call sites discard, keeping the plaintext object. A missing BYTES arm
// would therefore have meant buffers travelling unencrypted with nothing said.
func TestBytesAreEncryptedForStorage(t *testing.T) {
	const length = 4096
	password := fmt.Sprint(security.DerivePasswordFromInstructions([]byte("some instructions")))
	payload := []byte{0x4d, 0x5a, 0x90, 0x00}

	encrypted, err := mutil.EncryptObject(&object.Bytes{Value: payload}, length, password)
	if err != nil {
		t.Fatalf("EncryptObject: %v", err)
	}

	sealed, ok := encrypted.(*object.Encrypted)
	if !ok {
		t.Fatalf("EncryptObject returned %T, want *object.Encrypted -- a buffer would travel in the clear", encrypted)
	}
	if sealed.EncType != object.BYTES_OBJ {
		t.Errorf("EncType = %q, want %q", sealed.EncType, object.BYTES_OBJ)
	}
	if bytes.Equal(sealed.Value, payload) {
		t.Error("the encrypted value is the plaintext")
	}

	decrypted, err := mutil.DecryptObject(sealed, length, password)
	if err != nil {
		t.Fatalf("DecryptObject: %v", err)
	}
	buf, ok := decrypted.(*object.Bytes)
	if !ok {
		t.Fatalf("DecryptObject returned %T, want *object.Bytes", decrypted)
	}
	if !bytes.Equal(buf.Value, payload) {
		t.Errorf("round trip = %x, want %x", buf.Value, payload)
	}
}
