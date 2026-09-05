package builtin

import (
	"bytes"
	"strings"
	"testing"

	"mutant/object"
)

// allBytes is the input that distinguishes a byte-safe path from a rune-based
// one: every value 0x00-0xFF, most of which are not valid UTF-8.
func allBytes() []byte {
	out := make([]byte, 256)
	for i := range out {
		out[i] = byte(i)
	}
	return out
}

// call runs a builtin and follows the (value, err) convention into its pair.
func call(fn func(...object.Object) object.Object, args ...object.Object) (object.Object, *object.Error) {
	result := fn(args...)

	multi, ok := result.(*object.MultiValue)
	if !ok {
		if errObj, isErr := result.(*object.Error); isErr {
			return nil, errObj
		}
		return result, nil
	}
	if len(multi.Values) > 1 {
		if errObj, isErr := multi.Values[1].(*object.Error); isErr {
			return multi.Values[0], errObj
		}
	}
	return multi.Values[0], nil
}

func str(s string) *object.String { return &object.String{Value: s} }

func hexOf(data []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, len(data)*2)
	for _, b := range data {
		out = append(out, digits[b>>4], digits[b&0x0f])
	}
	return string(out)
}

// The done_when round trip: arbitrary binary in, byte-identical binary out.
func TestRawConversionIsByteIdentical(t *testing.T) {
	payload := allBytes()

	value, errObj := call(StringToBytes, str(string(payload)), str("raw"))
	if errObj != nil {
		t.Fatalf("string_to_bytes: %s", errObj.Message)
	}
	buf, ok := value.(*object.Bytes)
	if !ok {
		t.Fatalf("string_to_bytes returned %T, want *object.Bytes", value)
	}
	if !bytes.Equal(buf.Value, payload) {
		t.Fatal("the raw conversion altered the payload")
	}

	back, errObj := call(BytesToString, buf, str("raw"))
	if errObj != nil {
		t.Fatalf("bytes_to_string: %s", errObj.Message)
	}
	if got := back.(*object.String).Value; got != string(payload) {
		t.Error("the round trip through raw was not byte-identical")
	}
}

func TestConversionEncodings(t *testing.T) {
	cases := []struct {
		name     string
		encoding string
		text     string
		want     []byte
	}{
		{"hex decodes", "hex", "4d5a9000", []byte{0x4d, 0x5a, 0x90, 0x00}},
		{"base64 decodes", "base64", "TVqQAA==", []byte{0x4d, 0x5a, 0x90, 0x00}},
		{"latin1 maps each rune to one byte", "latin1", "ÿA", []byte{0xff, 0x41}},
		{"utf8 keeps valid text", "utf8", "héllo", []byte("héllo")},
		{"raw copies", "raw", "MZ", []byte{0x4d, 0x5a}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			value, errObj := call(StringToBytes, str(tc.text), str(tc.encoding))
			if errObj != nil {
				t.Fatalf("string_to_bytes(%q, %q): %s", tc.text, tc.encoding, errObj.Message)
			}
			if got := value.(*object.Bytes).Value; !bytes.Equal(got, tc.want) {
				t.Errorf("got %x, want %x", got, tc.want)
			}
		})
	}
}

// "utf8" validates rather than substituting. A silent U+FFFD is precisely the
// failure mode this type exists to remove, so a caller asserting UTF-8 over
// binary has to be told it is wrong.
func TestUTF8ConversionValidatesRatherThanSubstituting(t *testing.T) {
	invalid := &object.Bytes{Value: []byte{0xff, 0xfe, 0x00}}

	if _, errObj := call(BytesToString, invalid, str("utf8")); errObj == nil {
		t.Error("bytes_to_string accepted a buffer that is not valid UTF-8")
	}

	// The same buffer converts fine when the caller does not claim it is text.
	value, errObj := call(BytesToString, invalid, str("hex"))
	if errObj != nil {
		t.Fatalf("hex conversion failed: %s", errObj.Message)
	}
	if got := value.(*object.String).Value; got != "fffe00" {
		t.Errorf("hex = %q, want %q", got, "fffe00")
	}
}

func TestConversionsRejectBadInput(t *testing.T) {
	cases := []struct {
		name string
		run  func() (object.Object, *object.Error)
		want string
	}{
		{"unknown encoding going in", func() (object.Object, *object.Error) {
			return call(StringToBytes, str("x"), str("utf16"))
		}, "unknown encoding"},
		{"unknown encoding coming out", func() (object.Object, *object.Error) {
			return call(BytesToString, &object.Bytes{Value: []byte{1}}, str("utf16"))
		}, "unknown encoding"},
		{"malformed hex", func() (object.Object, *object.Error) {
			return call(StringToBytes, str("zz"), str("hex"))
		}, "string_to_bytes"},
		{"a rune latin1 cannot hold", func() (object.Object, *object.Error) {
			return call(StringToBytes, str("中"), str("latin1"))
		}, "latin1"},
		{"wrong arity", func() (object.Object, *object.Error) {
			return call(StringToBytes, str("x"))
		}, "wrong number of arguments"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, errObj := tc.run()
			if errObj == nil {
				t.Fatal("the call was accepted")
			}
			if !strings.Contains(errObj.Message, tc.want) {
				t.Errorf("error %q does not mention %q", errObj.Message, tc.want)
			}
		})
	}
}

// The family is shape-preserving: a buffer in, a buffer out; a string in, a
// string out. That is what lets it bridge the two without breaking a single
// program written before the type existed.
func TestBytesFamilyPreservesRepresentation(t *testing.T) {
	payload := []byte{0x4d, 0x5a, 0x90, 0x00}

	fromBytes, errObj := call(BytesSlice, &object.Bytes{Value: payload}, intObj(0), intObj(2))
	if errObj != nil {
		t.Fatalf("bytes_slice on a buffer: %s", errObj.Message)
	}
	if _, ok := fromBytes.(*object.Bytes); !ok {
		t.Errorf("bytes_slice of a BYTES returned %T, want *object.Bytes", fromBytes)
	}

	fromString, errObj := call(BytesSlice, str(string(payload)), intObj(0), intObj(2))
	if errObj != nil {
		t.Fatalf("bytes_slice on a string: %s", errObj.Message)
	}
	if _, ok := fromString.(*object.String); !ok {
		t.Errorf("bytes_slice of a STRING returned %T, want *object.String", fromString)
	}

	// Both spellings read the same byte.
	forBuffer, _ := call(BytesGet, &object.Bytes{Value: payload}, intObj(2))
	forString, _ := call(BytesGet, str(string(payload)), intObj(2))
	if forBuffer.Inspect() != forString.Inspect() {
		t.Errorf("bytes_get disagreed across representations: %s vs %s",
			forBuffer.Inspect(), forString.Inspect())
	}
}

// A cursor built over a buffer stays a buffer cursor as it is advanced.
func TestBytesCursorKeepsItsRepresentation(t *testing.T) {
	cursor, errObj := call(BytesCursorNew, &object.Bytes{Value: []byte{0x01, 0x02, 0x03, 0x04}})
	if errObj != nil {
		t.Fatalf("bytes_cursor_new: %s", errObj.Message)
	}

	// A cursor read yields {cursor, value}; the cursor half is what carries the
	// representation forward.
	read, errObj := call(BytesCursorReadU16LE, cursor)
	if errObj != nil {
		t.Fatalf("bytes_cursor_read_u16_le: %s", errObj.Message)
	}
	result, ok := read.(*object.Hash)
	if !ok {
		t.Fatalf("bytes_cursor_read_u16_le returned %T, want *object.Hash", read)
	}
	nextObj, ok := hashValueByStringKey(result, "cursor")
	if !ok {
		t.Fatal("the read result carries no cursor")
	}
	next, ok := nextObj.(*object.Hash)
	if !ok {
		t.Fatalf("the advanced cursor is %T, want *object.Hash", nextObj)
	}

	data, ok := hashValueByStringKey(next, "data")
	if !ok {
		t.Fatal("the advanced cursor lost its data field")
	}
	if _, ok := data.(*object.Bytes); !ok {
		t.Errorf("a buffer cursor advanced into a %s cursor", data.Type())
	}
}

// Every producer that predates the type returns byte-exact data in a STRING, so
// the raw bridge reaches all of them. This is the property that kept task 2
// from meaning a bytes-returning twin of every reader in the library.
func TestRawBridgeRecoversLegacyProducerOutput(t *testing.T) {
	payload := allBytes()

	decoded, errObj := call(HexDecode, str(hexOf(payload)))
	if errObj != nil {
		t.Fatalf("hex_decode: %s", errObj.Message)
	}
	bridged, errObj := call(StringToBytes, decoded, str("raw"))
	if errObj != nil {
		t.Fatalf("string_to_bytes: %s", errObj.Message)
	}
	if !bytes.Equal(bridged.(*object.Bytes).Value, payload) {
		t.Error("the raw bridge did not recover the producer's bytes")
	}

	// And the native producer agrees with the bridged one.
	native, errObj := call(HexDecodeBytes, str(hexOf(payload)))
	if errObj != nil {
		t.Fatalf("hex_decode_bytes: %s", errObj.Message)
	}
	if !bytes.Equal(native.(*object.Bytes).Value, payload) {
		t.Error("hex_decode_bytes and the raw bridge disagree")
	}
}
