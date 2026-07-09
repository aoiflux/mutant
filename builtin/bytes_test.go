package builtin

import (
	"strings"
	"testing"

	"mutant/object"
)

func cursorField(t *testing.T, cursorObj object.Object, key string) object.Object {
	t.Helper()

	cursor, ok := cursorObj.(*object.Hash)
	if !ok {
		t.Fatalf("cursor result is not Hash. got=%T", cursorObj)
	}

	value, ok := hashValueByStringKey(cursor, key)
	if !ok {
		t.Fatalf("cursor missing key %q", key)
	}

	return value
}

func TestBytesLen(t *testing.T) {
	result := BytesLen(&object.String{Value: "ABC"})

	payload, errObj := unwrapPair(t, result)
	if errObj != nil {
		t.Fatalf("unexpected error: %s", errObj.Inspect())
	}

	length, ok := payload.(*object.Integer)
	if !ok {
		t.Fatalf("bytes_len result is not Integer. got=%T", payload)
	}
	if length.Value != 3 {
		t.Fatalf("unexpected bytes_len value: got=%d, want=3", length.Value)
	}
}

func TestBytesGet(t *testing.T) {
	result := BytesGet(
		&object.String{Value: "\x00\x7F\xFF"},
		&object.Integer{Value: 2},
	)

	payload, errObj := unwrapPair(t, result)
	if errObj != nil {
		t.Fatalf("unexpected error: %s", errObj.Inspect())
	}

	value, ok := payload.(*object.Integer)
	if !ok {
		t.Fatalf("bytes_get result is not Integer. got=%T", payload)
	}
	if value.Value != 255 {
		t.Fatalf("unexpected bytes_get value: got=%d, want=255", value.Value)
	}
}

func TestBytesGetOutOfRange(t *testing.T) {
	result := BytesGet(
		&object.String{Value: "abc"},
		&object.Integer{Value: 3},
	)

	_, errObj := unwrapPair(t, result)
	if errObj == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(errObj.Message, "out of range") {
		t.Fatalf("unexpected error message: %q", errObj.Message)
	}
}

func TestBytesSlice(t *testing.T) {
	result := BytesSlice(
		&object.String{Value: "mutant"},
		&object.Integer{Value: 1},
		&object.Integer{Value: 3},
	)

	payload, errObj := unwrapPair(t, result)
	if errObj != nil {
		t.Fatalf("unexpected error: %s", errObj.Inspect())
	}

	value, ok := payload.(*object.String)
	if !ok {
		t.Fatalf("bytes_slice result is not String. got=%T", payload)
	}
	if value.Value != "uta" {
		t.Fatalf("unexpected bytes_slice value: got=%q, want=%q", value.Value, "uta")
	}
}

func TestBytesReadU16AndU32(t *testing.T) {
	input := &object.String{Value: "\x34\x12\x78\x56\x34\x12"}

	u16LE, errObj := unwrapPair(t, BytesReadU16LE(input, &object.Integer{Value: 0}))
	if errObj != nil {
		t.Fatalf("unexpected u16 le error: %s", errObj.Inspect())
	}
	if u16LE.(*object.Integer).Value != 0x1234 {
		t.Fatalf("unexpected u16 le value: %d", u16LE.(*object.Integer).Value)
	}

	u16BE, errObj := unwrapPair(t, BytesReadU16BE(input, &object.Integer{Value: 0}))
	if errObj != nil {
		t.Fatalf("unexpected u16 be error: %s", errObj.Inspect())
	}
	if u16BE.(*object.Integer).Value != 0x3412 {
		t.Fatalf("unexpected u16 be value: %d", u16BE.(*object.Integer).Value)
	}

	u32LE, errObj := unwrapPair(t, BytesReadU32LE(input, &object.Integer{Value: 2}))
	if errObj != nil {
		t.Fatalf("unexpected u32 le error: %s", errObj.Inspect())
	}
	if u32LE.(*object.Integer).Value != 0x12345678 {
		t.Fatalf("unexpected u32 le value: %d", u32LE.(*object.Integer).Value)
	}

	u32BE, errObj := unwrapPair(t, BytesReadU32BE(input, &object.Integer{Value: 2}))
	if errObj != nil {
		t.Fatalf("unexpected u32 be error: %s", errObj.Inspect())
	}
	if u32BE.(*object.Integer).Value != 0x78563412 {
		t.Fatalf("unexpected u32 be value: %d", u32BE.(*object.Integer).Value)
	}
}

func TestBytesReadU64(t *testing.T) {
	input := &object.String{Value: "\x08\x07\x06\x05\x04\x03\x02\x01"}

	u64LE, errObj := unwrapPair(t, BytesReadU64LE(input, &object.Integer{Value: 0}))
	if errObj != nil {
		t.Fatalf("unexpected u64 le error: %s", errObj.Inspect())
	}
	if u64LE.(*object.Integer).Value != 0x0102030405060708 {
		t.Fatalf("unexpected u64 le value: %d", u64LE.(*object.Integer).Value)
	}

	u64BE, errObj := unwrapPair(t, BytesReadU64BE(input, &object.Integer{Value: 0}))
	if errObj != nil {
		t.Fatalf("unexpected u64 be error: %s", errObj.Inspect())
	}
	if u64BE.(*object.Integer).Value != 0x0807060504030201 {
		t.Fatalf("unexpected u64 be value: %d", u64BE.(*object.Integer).Value)
	}
}

func TestBytesWriteU16AndU32(t *testing.T) {
	base := &object.String{Value: "\x00\x00\x00\x00\x00\x00"}

	patched16LE, errObj := unwrapPair(t, BytesWriteU16LE(base, &object.Integer{Value: 0}, &object.Integer{Value: 0x1234}))
	if errObj != nil {
		t.Fatalf("unexpected write u16 le error: %s", errObj.Inspect())
	}
	if patched16LE.(*object.String).Value[:2] != "\x34\x12" {
		t.Fatalf("unexpected write u16 le bytes")
	}

	patched16BE, errObj := unwrapPair(t, BytesWriteU16BE(base, &object.Integer{Value: 0}, &object.Integer{Value: 0x1234}))
	if errObj != nil {
		t.Fatalf("unexpected write u16 be error: %s", errObj.Inspect())
	}
	if patched16BE.(*object.String).Value[:2] != "\x12\x34" {
		t.Fatalf("unexpected write u16 be bytes")
	}

	patched32LE, errObj := unwrapPair(t, BytesWriteU32LE(base, &object.Integer{Value: 2}, &object.Integer{Value: 0x78563412}))
	if errObj != nil {
		t.Fatalf("unexpected write u32 le error: %s", errObj.Inspect())
	}
	segmentLE, segErr := unwrapPair(t, BytesSlice(patched32LE, &object.Integer{Value: 2}, &object.Integer{Value: 4}))
	if segErr != nil {
		t.Fatalf("unexpected slice error after write u32 le: %s", segErr.Inspect())
	}
	if segmentLE.(*object.String).Value != "\x12\x34\x56\x78" {
		t.Fatalf("unexpected write u32 le bytes")
	}

	patched32BE, errObj := unwrapPair(t, BytesWriteU32BE(base, &object.Integer{Value: 2}, &object.Integer{Value: 0x78563412}))
	if errObj != nil {
		t.Fatalf("unexpected write u32 be error: %s", errObj.Inspect())
	}
	segmentBE, segErr := unwrapPair(t, BytesSlice(patched32BE, &object.Integer{Value: 2}, &object.Integer{Value: 4}))
	if segErr != nil {
		t.Fatalf("unexpected slice error after write u32 be: %s", segErr.Inspect())
	}
	if segmentBE.(*object.String).Value != "\x78\x56\x34\x12" {
		t.Fatalf("unexpected write u32 be bytes")
	}
}

func TestBytesWriteU64RoundTrip(t *testing.T) {
	base := &object.String{Value: "\x00\x00\x00\x00\x00\x00\x00\x00"}
	patched, errObj := unwrapPair(t, BytesWriteU64LE(base, &object.Integer{Value: 0}, &object.Integer{Value: 0x0102030405060708}))
	if errObj != nil {
		t.Fatalf("unexpected write u64 le error: %s", errObj.Inspect())
	}

	decoded, errObj := unwrapPair(t, BytesReadU64LE(patched, &object.Integer{Value: 0}))
	if errObj != nil {
		t.Fatalf("unexpected read u64 le error: %s", errObj.Inspect())
	}
	if decoded.(*object.Integer).Value != 0x0102030405060708 {
		t.Fatalf("unexpected u64 roundtrip value: %d", decoded.(*object.Integer).Value)
	}
}

func TestBytesWriteOutOfRangeValue(t *testing.T) {
	result := BytesWriteU16LE(
		&object.String{Value: "\x00\x00"},
		&object.Integer{Value: 0},
		&object.Integer{Value: 70000},
	)

	_, errObj := unwrapPair(t, result)
	if errObj == nil {
		t.Fatalf("expected range error")
	}
	if !strings.Contains(errObj.Message, "exceeds max") {
		t.Fatalf("unexpected error message: %q", errObj.Message)
	}
}

func TestBytesCStrAt(t *testing.T) {
	input := &object.String{Value: "kernel32.dll\x00rest"}
	payload, errObj := unwrapPair(t, BytesCStrAt(input, &object.Integer{Value: 0}, &object.Integer{Value: 64}))
	if errObj != nil {
		t.Fatalf("unexpected error: %s", errObj.Inspect())
	}

	value, ok := payload.(*object.String)
	if !ok {
		t.Fatalf("bytes_cstr_at result is not String. got=%T", payload)
	}
	if value.Value != "kernel32.dll" {
		t.Fatalf("unexpected cstr value: got=%q", value.Value)
	}
}

func TestBytesHex(t *testing.T) {
	payload, errObj := unwrapPair(t, BytesHex(&object.Integer{Value: 4660}, &object.Integer{Value: 8}))
	if errObj != nil {
		t.Fatalf("unexpected error: %s", errObj.Inspect())
	}

	value, ok := payload.(*object.String)
	if !ok {
		t.Fatalf("bytes_hex result is not String. got=%T", payload)
	}
	if value.Value != "0x00001234" {
		t.Fatalf("unexpected bytes_hex value: got=%q", value.Value)
	}
}

func TestBytesCharRoundTrip(t *testing.T) {
	charPayload, errObj := unwrapPair(t, BytesCharFromInt(&object.Integer{Value: 65}))
	if errObj != nil {
		t.Fatalf("unexpected bytes_char_from_int error: %s", errObj.Inspect())
	}
	charStr, ok := charPayload.(*object.String)
	if !ok {
		t.Fatalf("bytes_char_from_int result is not String. got=%T", charPayload)
	}
	if charStr.Value != "A" {
		t.Fatalf("unexpected bytes_char_from_int value: %q", charStr.Value)
	}

	bytePayload, errObj := unwrapPair(t, BytesIntFromChar(&object.String{Value: "A"}))
	if errObj != nil {
		t.Fatalf("unexpected bytes_int_from_char error: %s", errObj.Inspect())
	}
	byteVal, ok := bytePayload.(*object.Integer)
	if !ok {
		t.Fatalf("bytes_int_from_char result is not Integer. got=%T", bytePayload)
	}
	if byteVal.Value != 65 {
		t.Fatalf("unexpected bytes_int_from_char value: %d", byteVal.Value)
	}
}

func TestBytesCursorBasics(t *testing.T) {
	cursorPayload, errObj := unwrapPair(t, BytesCursorNew(&object.String{Value: "ABC"}))
	if errObj != nil {
		t.Fatalf("unexpected bytes_cursor_new error: %s", errObj.Inspect())
	}

	offsetObj := cursorField(t, cursorPayload, "offset")
	offset, ok := offsetObj.(*object.Integer)
	if !ok || offset.Value != 0 {
		t.Fatalf("unexpected cursor offset after new")
	}

	tellPayload, errObj := unwrapPair(t, BytesCursorTell(cursorPayload))
	if errObj != nil {
		t.Fatalf("unexpected bytes_cursor_tell error: %s", errObj.Inspect())
	}
	tellValue := tellPayload.(*object.Integer)
	if tellValue.Value != 0 {
		t.Fatalf("unexpected cursor tell value: %d", tellValue.Value)
	}

	seekPayload, errObj := unwrapPair(t, BytesCursorSeek(cursorPayload, &object.Integer{Value: 2}))
	if errObj != nil {
		t.Fatalf("unexpected bytes_cursor_seek error: %s", errObj.Inspect())
	}

	seekOffset := cursorField(t, seekPayload, "offset").(*object.Integer)
	if seekOffset.Value != 2 {
		t.Fatalf("unexpected cursor offset after seek: %d", seekOffset.Value)
	}

	eofPayload, errObj := unwrapPair(t, BytesCursorEOF(seekPayload))
	if errObj != nil {
		t.Fatalf("unexpected bytes_cursor_eof error: %s", errObj.Inspect())
	}
	eofValue := eofPayload.(*object.Boolean)
	if eofValue.Value {
		t.Fatalf("expected eof=false")
	}
}

func TestBytesCursorReadChain(t *testing.T) {
	cursorPayload, errObj := unwrapPair(t, BytesCursorNew(&object.String{Value: "\x34\x12\x78\x56"}))
	if errObj != nil {
		t.Fatalf("unexpected cursor_new error: %s", errObj.Inspect())
	}

	read16Payload, errObj := unwrapPair(t, BytesCursorReadU16LE(cursorPayload))
	if errObj != nil {
		t.Fatalf("unexpected read_u16_le error: %s", errObj.Inspect())
	}

	read16Hash, ok := read16Payload.(*object.Hash)
	if !ok {
		t.Fatalf("read_u16_le result is not Hash. got=%T", read16Payload)
	}
	value16Obj, _ := hashValueByStringKey(read16Hash, "value")
	value16 := value16Obj.(*object.Integer)
	if value16.Value != 0x1234 {
		t.Fatalf("unexpected read_u16_le value: %d", value16.Value)
	}
	nextCursorObj, _ := hashValueByStringKey(read16Hash, "cursor")

	read16Offset := cursorField(t, nextCursorObj, "offset").(*object.Integer)
	if read16Offset.Value != 2 {
		t.Fatalf("unexpected cursor offset after read_u16_le: %d", read16Offset.Value)
	}

	read32Payload, errObj := unwrapPair(t, BytesCursorReadU16LE(nextCursorObj))
	if errObj != nil {
		t.Fatalf("unexpected second read_u16_le error: %s", errObj.Inspect())
	}
	read32Hash := read32Payload.(*object.Hash)
	value32Obj, _ := hashValueByStringKey(read32Hash, "value")
	value32 := value32Obj.(*object.Integer)
	if value32.Value != 0x5678 {
		t.Fatalf("unexpected second read_u16_le value: %d", value32.Value)
	}

	finalCursorObj, _ := hashValueByStringKey(read32Hash, "cursor")
	eofPayload, errObj := unwrapPair(t, BytesCursorEOF(finalCursorObj))
	if errObj != nil {
		t.Fatalf("unexpected eof error: %s", errObj.Inspect())
	}
	if !eofPayload.(*object.Boolean).Value {
		t.Fatalf("expected eof=true after consuming all bytes")
	}
}

func TestBytesCursorReadOutOfBounds(t *testing.T) {
	cursorPayload, errObj := unwrapPair(t, BytesCursorNew(&object.String{Value: "\x01"}))
	if errObj != nil {
		t.Fatalf("unexpected cursor_new error: %s", errObj.Inspect())
	}

	_, errObj = unwrapPair(t, BytesCursorReadU16LE(cursorPayload))
	if errObj == nil {
		t.Fatalf("expected out-of-bounds error")
	}
	if !strings.Contains(errObj.Message, "exceeds buffer length") {
		t.Fatalf("unexpected error message: %q", errObj.Message)
	}
}
