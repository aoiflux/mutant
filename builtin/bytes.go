package builtin

import (
	"fmt"
	"math"
	"strings"

	"mutant/object"
)

func BytesLen(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}

	value, errObj := requireBytesStringArg("bytes_len", args[0], 1)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	return resultAndError(intObj(int64(len(value))), nil)
}

func BytesGet(args ...object.Object) object.Object {
	if len(args) != 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=2", len(args)))
	}

	value, errObj := requireBytesStringArg("bytes_get", args[0], 1)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	offset, errObj := requireNonNegativeOffset("bytes_get", args[1], 2)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	if offset >= len(value) {
		return resultAndError(nil, newError("bytes_get: offset %d out of range for buffer length %d", offset, len(value)))
	}

	return resultAndError(intObj(int64(value[offset])), nil)
}

func BytesSlice(args ...object.Object) object.Object {
	if len(args) != 3 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=3", len(args)))
	}

	value, errObj := requireBytesStringArg("bytes_slice", args[0], 1)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	start, errObj := requireNonNegativeOffset("bytes_slice", args[1], 2)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	length, errObj := requireNonNegativeOffset("bytes_slice", args[2], 3)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	if start > len(value) {
		return resultAndError(nil, newError("bytes_slice: start %d out of range for buffer length %d", start, len(value)))
	}
	if start+length > len(value) {
		return resultAndError(nil, newError("bytes_slice: requested range start=%d length=%d exceeds buffer length %d", start, length, len(value)))
	}

	return resultAndError(stringObj(value[start:start+length]), nil)
}

func BytesReadU16LE(args ...object.Object) object.Object {
	return bytesReadUnsigned(args, "bytes_read_u16_le", 2, false)
}

func BytesReadU16BE(args ...object.Object) object.Object {
	return bytesReadUnsigned(args, "bytes_read_u16_be", 2, true)
}

func BytesReadU32LE(args ...object.Object) object.Object {
	return bytesReadUnsigned(args, "bytes_read_u32_le", 4, false)
}

func BytesReadU32BE(args ...object.Object) object.Object {
	return bytesReadUnsigned(args, "bytes_read_u32_be", 4, true)
}

func BytesReadU64LE(args ...object.Object) object.Object {
	return bytesReadUnsigned(args, "bytes_read_u64_le", 8, false)
}

func BytesReadU64BE(args ...object.Object) object.Object {
	return bytesReadUnsigned(args, "bytes_read_u64_be", 8, true)
}

func BytesWriteU16LE(args ...object.Object) object.Object {
	return bytesWriteUnsigned(args, "bytes_write_u16_le", 2, false)
}

func BytesWriteU16BE(args ...object.Object) object.Object {
	return bytesWriteUnsigned(args, "bytes_write_u16_be", 2, true)
}

func BytesWriteU32LE(args ...object.Object) object.Object {
	return bytesWriteUnsigned(args, "bytes_write_u32_le", 4, false)
}

func BytesWriteU32BE(args ...object.Object) object.Object {
	return bytesWriteUnsigned(args, "bytes_write_u32_be", 4, true)
}

func BytesWriteU64LE(args ...object.Object) object.Object {
	return bytesWriteUnsigned(args, "bytes_write_u64_le", 8, false)
}

func BytesWriteU64BE(args ...object.Object) object.Object {
	return bytesWriteUnsigned(args, "bytes_write_u64_be", 8, true)
}

func BytesCStrAt(args ...object.Object) object.Object {
	if len(args) != 3 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=3", len(args)))
	}

	value, errObj := requireBytesStringArg("bytes_cstr_at", args[0], 1)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	offset, errObj := requireNonNegativeOffset("bytes_cstr_at", args[1], 2)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	maxLength, errObj := requireNonNegativeOffset("bytes_cstr_at", args[2], 3)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	if offset > len(value) {
		return resultAndError(nil, newError("bytes_cstr_at: offset %d out of range for buffer length %d", offset, len(value)))
	}

	end := offset
	limit := offset + maxLength
	if limit > len(value) {
		limit = len(value)
	}

	for end < limit {
		if value[end] == 0 {
			break
		}
		end++
	}

	return resultAndError(stringObj(value[offset:end]), nil)
}

func BytesHex(args ...object.Object) object.Object {
	if len(args) != 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=2", len(args)))
	}

	valueObj, ok := args[0].(*object.Integer)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `bytes_hex` must be INTEGER, got %s", args[0].Type()))
	}

	widthObj, ok := args[1].(*object.Integer)
	if !ok {
		return resultAndError(nil, newError("argument 2 to `bytes_hex` must be INTEGER, got %s", args[1].Type()))
	}

	if widthObj.Value <= 0 {
		return resultAndError(nil, newError("bytes_hex: width must be > 0, got %d", widthObj.Value))
	}
	if widthObj.Value > 16 {
		return resultAndError(nil, newError("bytes_hex: width %d is too large, max=16", widthObj.Value))
	}

	formatted := fmt.Sprintf("0x%0*X", int(widthObj.Value), uint64(valueObj.Value))
	return resultAndError(stringObj(formatted), nil)
}

func BytesCharFromInt(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}

	valueObj, ok := args[0].(*object.Integer)
	if !ok {
		return resultAndError(nil, newError("argument to `bytes_char_from_int` must be INTEGER, got %s", args[0].Type()))
	}

	if valueObj.Value < 0 || valueObj.Value > 255 {
		return resultAndError(nil, newError("bytes_char_from_int: byte value out of range: %d", valueObj.Value))
	}

	return resultAndError(stringObj(string([]byte{byte(valueObj.Value)})), nil)
}

func BytesIntFromChar(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}

	valueObj, ok := args[0].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument to `bytes_int_from_char` must be STRING, got %s", args[0].Type()))
	}

	if len(valueObj.Value) == 0 {
		return resultAndError(nil, newError("bytes_int_from_char: input string is empty"))
	}

	return resultAndError(intObj(int64(valueObj.Value[0])), nil)
}

func BytesCursorNew(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}

	data, errObj := requireBytesStringArg("bytes_cursor_new", args[0], 1)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	return resultAndError(makeBytesCursor(data, 0), nil)
}

func BytesCursorTell(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}

	_, offset, _, errObj := requireBytesCursor("bytes_cursor_tell", args[0], 1)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	return resultAndError(intObj(int64(offset)), nil)
}

func BytesCursorSeek(args ...object.Object) object.Object {
	if len(args) != 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=2", len(args)))
	}

	data, _, cursorLen, errObj := requireBytesCursor("bytes_cursor_seek", args[0], 1)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	offset, errObj := requireNonNegativeOffset("bytes_cursor_seek", args[1], 2)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	if offset > cursorLen {
		return resultAndError(nil, newError("bytes_cursor_seek: offset %d out of range for buffer length %d", offset, cursorLen))
	}

	return resultAndError(makeBytesCursor(data, offset), nil)
}

func BytesCursorEOF(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}

	_, offset, cursorLen, errObj := requireBytesCursor("bytes_cursor_eof", args[0], 1)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	return resultAndError(boolObj(offset >= cursorLen), nil)
}

func BytesCursorReadU8(args ...object.Object) object.Object {
	return bytesCursorReadUnsigned(args, "bytes_cursor_read_u8", 1, false)
}

func BytesCursorReadU16LE(args ...object.Object) object.Object {
	return bytesCursorReadUnsigned(args, "bytes_cursor_read_u16_le", 2, false)
}

func BytesCursorReadU16BE(args ...object.Object) object.Object {
	return bytesCursorReadUnsigned(args, "bytes_cursor_read_u16_be", 2, true)
}

func BytesCursorReadU32LE(args ...object.Object) object.Object {
	return bytesCursorReadUnsigned(args, "bytes_cursor_read_u32_le", 4, false)
}

func BytesCursorReadU32BE(args ...object.Object) object.Object {
	return bytesCursorReadUnsigned(args, "bytes_cursor_read_u32_be", 4, true)
}

func BytesCursorReadU64LE(args ...object.Object) object.Object {
	return bytesCursorReadUnsigned(args, "bytes_cursor_read_u64_le", 8, false)
}

func BytesCursorReadU64BE(args ...object.Object) object.Object {
	return bytesCursorReadUnsigned(args, "bytes_cursor_read_u64_be", 8, true)
}

func bytesReadUnsigned(args []object.Object, opName string, size int, bigEndian bool) object.Object {
	if len(args) != 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=2", len(args)))
	}

	value, errObj := requireBytesStringArg(opName, args[0], 1)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	offset, errObj := requireNonNegativeOffset(opName, args[1], 2)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	if offset+size > len(value) {
		return resultAndError(nil, newError("%s: offset %d with size %d exceeds buffer length %d", opName, offset, size, len(value)))
	}

	result, errObj := decodeUnsignedAt(opName, value, offset, size, bigEndian)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	return resultAndError(intObj(int64(result)), nil)
}

func bytesCursorReadUnsigned(args []object.Object, opName string, size int, bigEndian bool) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}

	data, offset, cursorLen, errObj := requireBytesCursor(opName, args[0], 1)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	if offset+size > cursorLen {
		return resultAndError(nil, newError("%s: offset %d with size %d exceeds buffer length %d", opName, offset, size, cursorLen))
	}

	result, errObj := decodeUnsignedAt(opName, data, offset, size, bigEndian)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	nextCursor := makeBytesCursor(data, offset+size)
	readResult := makeHashObject(map[string]object.Object{
		"cursor": nextCursor,
		"value":  intObj(int64(result)),
	})

	return resultAndError(readResult, nil)
}

func decodeUnsignedAt(opName string, value string, offset int, size int, bigEndian bool) (uint64, *object.Error) {

	var result uint64
	if bigEndian {
		for i := 0; i < size; i++ {
			result = (result << 8) | uint64(value[offset+i])
		}
	} else {
		for i := size - 1; i >= 0; i-- {
			result = (result << 8) | uint64(value[offset+i])
		}
	}

	if result > math.MaxInt64 {
		return 0, newError("%s: decoded value %d exceeds INTEGER max %d", opName, result, int64(math.MaxInt64))
	}

	return result, nil
}

func bytesWriteUnsigned(args []object.Object, opName string, size int, bigEndian bool) object.Object {
	if len(args) != 3 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=3", len(args)))
	}

	value, errObj := requireBytesStringArg(opName, args[0], 1)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	offset, errObj := requireNonNegativeOffset(opName, args[1], 2)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	maxValue := maxValueForByteSize(size)
	encodedValue, errObj := requireIntegerWithinRange(opName, args[2], 3, maxValue)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	if offset+size > len(value) {
		return resultAndError(nil, newError("%s: offset %d with size %d exceeds buffer length %d", opName, offset, size, len(value)))
	}

	buf := []byte(value)
	if bigEndian {
		for i := size - 1; i >= 0; i-- {
			buf[offset+i] = byte(encodedValue & 0xFF)
			encodedValue >>= 8
		}
	} else {
		for i := 0; i < size; i++ {
			buf[offset+i] = byte(encodedValue & 0xFF)
			encodedValue >>= 8
		}
	}

	return resultAndError(stringObj(string(buf)), nil)
}

func maxValueForByteSize(size int) uint64 {
	switch size {
	case 2:
		return 0xFFFF
	case 4:
		return 0xFFFFFFFF
	case 8:
		return uint64(math.MaxInt64)
	default:
		return 0
	}
}

func requireBytesStringArg(opName string, arg object.Object, position int) (string, *object.Error) {
	str, ok := arg.(*object.String)
	if !ok {
		return "", newError("argument %d to `%s` must be STRING, got %s", position, opName, arg.Type())
	}
	return str.Value, nil
}

func requireNonNegativeOffset(opName string, arg object.Object, position int) (int, *object.Error) {
	intObj, ok := arg.(*object.Integer)
	if !ok {
		return 0, newError("argument %d to `%s` must be INTEGER, got %s", position, opName, arg.Type())
	}
	if intObj.Value < 0 {
		return 0, newError("%s: argument %d must be >= 0, got %d", opName, position, intObj.Value)
	}
	if intObj.Value > 1<<31-1 {
		return 0, newError("%s: argument %d is too large", opName, position)
	}
	return int(intObj.Value), nil
}

func requireIntegerWithinRange(opName string, arg object.Object, position int, max uint64) (uint64, *object.Error) {
	intObj, ok := arg.(*object.Integer)
	if !ok {
		return 0, newError("argument %d to `%s` must be INTEGER, got %s", position, opName, arg.Type())
	}
	if intObj.Value < 0 {
		return 0, newError("%s: argument %d must be >= 0, got %d", opName, position, intObj.Value)
	}
	value := uint64(intObj.Value)
	if value > max {
		return 0, newError("%s: argument %d value %d exceeds max %d", opName, position, value, max)
	}
	return value, nil
}

func requireBytesCursor(opName string, arg object.Object, position int) (string, int, int, *object.Error) {
	cursor, ok := arg.(*object.Hash)
	if !ok {
		return "", 0, 0, newError("argument %d to `%s` must be HASH, got %s", position, opName, arg.Type())
	}

	dataObj, ok := hashValueByStringKey(cursor, "data")
	if !ok {
		return "", 0, 0, newError("%s: cursor missing `data` field", opName)
	}
	dataStr, ok := dataObj.(*object.String)
	if !ok {
		return "", 0, 0, newError("%s: cursor field `data` must be STRING, got %s", opName, dataObj.Type())
	}

	offsetObj, ok := hashValueByStringKey(cursor, "offset")
	if !ok {
		return "", 0, 0, newError("%s: cursor missing `offset` field", opName)
	}
	offsetInt, ok := offsetObj.(*object.Integer)
	if !ok {
		return "", 0, 0, newError("%s: cursor field `offset` must be INTEGER, got %s", opName, offsetObj.Type())
	}
	if offsetInt.Value < 0 {
		return "", 0, 0, newError("%s: cursor offset must be >= 0, got %d", opName, offsetInt.Value)
	}
	if offsetInt.Value > 1<<31-1 {
		return "", 0, 0, newError("%s: cursor offset is too large", opName)
	}

	offset := int(offsetInt.Value)
	cursorLen := len(dataStr.Value)
	if offset > cursorLen {
		return "", 0, 0, newError("%s: cursor offset %d out of range for buffer length %d", opName, offset, cursorLen)
	}

	return dataStr.Value, offset, cursorLen, nil
}

func makeBytesCursor(data string, offset int) *object.Hash {
	return makeHashObject(map[string]object.Object{
		"data":   stringObj(data),
		"offset": intObj(int64(offset)),
	})
}

func bytesToHex(input string) string {
	if input == "" {
		return ""
	}
	parts := make([]string, len(input))
	for i := range input {
		parts[i] = fmt.Sprintf("%02X", input[i])
	}
	return strings.Join(parts, "")
}
