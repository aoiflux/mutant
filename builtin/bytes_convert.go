package builtin

import (
	"encoding/base64"
	"encoding/hex"
	"unicode/utf8"

	"mutant/object"
)

// Conversions between BYTES and STRING.
//
// They are explicit and they name an encoding, because the whole point of
// having two types is that the step between them is the one worth being
// deliberate about. An implicit coercion would put the corruption back exactly
// where it was: a buffer that silently became text somewhere upstream, and a
// text builtin that never knew.
//
// "raw" is the load-bearing encoding. Every producer that predates the BYTES
// type returns byte-exact data in a STRING, so string_to_bytes(fs_read(p),
// "raw") is a lossless bridge from all of them at once -- which is why adding
// this type did not require a bytes-returning twin of every reader in the
// standard library.

// byteEncodings are the encodings both conversions accept, listed for the error
// message so a wrong one teaches the right ones.
var byteEncodings = []string{"raw", "utf8", "latin1", "hex", "base64"}

func unknownEncoding(opName, encoding string) *object.Error {
	return newError("%s: unknown encoding %q, want one of %v", opName, encoding, byteEncodings)
}

// StringToBytes converts text to a buffer under a named encoding.
func StringToBytes(args ...object.Object) object.Object {
	if len(args) != 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=2", len(args)))
	}

	value, errObj := requireStringArg("string_to_bytes", args[0], 1)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	encoding, errObj := requireStringArg("string_to_bytes", args[1], 2)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	switch encoding {
	case "raw":
		return resultAndError(&object.Bytes{Value: []byte(value)}, nil)

	case "utf8":
		// Validating rather than substituting is the difference between this and
		// the text builtins the type exists to protect callers from: a caller
		// that says "utf8" is asserting something, and a silent U+FFFD would
		// turn that assertion into a wrong answer.
		if !utf8.ValidString(value) {
			return resultAndError(nil, newError("string_to_bytes: input is not valid UTF-8"))
		}
		return resultAndError(&object.Bytes{Value: []byte(value)}, nil)

	case "latin1":
		out := make([]byte, 0, len(value))
		for _, r := range value {
			if r > 0xFF {
				return resultAndError(nil, newError("string_to_bytes: %q is not representable in latin1", r))
			}
			out = append(out, byte(r))
		}
		return resultAndError(&object.Bytes{Value: out}, nil)

	case "hex":
		decoded, err := hex.DecodeString(value)
		if err != nil {
			return resultAndError(nil, newError("string_to_bytes: %s", err.Error()))
		}
		return resultAndError(&object.Bytes{Value: decoded}, nil)

	case "base64":
		decoded, err := base64.StdEncoding.DecodeString(value)
		if err != nil {
			return resultAndError(nil, newError("string_to_bytes: %s", err.Error()))
		}
		return resultAndError(&object.Bytes{Value: decoded}, nil)

	default:
		return resultAndError(nil, unknownEncoding("string_to_bytes", encoding))
	}
}

// BytesToString converts a buffer to text under a named encoding.
func BytesToString(args ...object.Object) object.Object {
	if len(args) != 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=2", len(args)))
	}

	value, errObj := requireBinaryArg("bytes_to_string", args[0], 1)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	encoding, errObj := requireStringArg("bytes_to_string", args[1], 2)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	switch encoding {
	case "raw":
		return resultAndError(stringObj(string(value)), nil)

	case "utf8":
		if !utf8.Valid(value) {
			return resultAndError(nil, newError("bytes_to_string: buffer is not valid UTF-8"))
		}
		return resultAndError(stringObj(string(value)), nil)

	case "latin1":
		var out []rune
		for _, b := range value {
			out = append(out, rune(b))
		}
		return resultAndError(stringObj(string(out)), nil)

	case "hex":
		return resultAndError(stringObj(hex.EncodeToString(value)), nil)

	case "base64":
		return resultAndError(stringObj(base64.StdEncoding.EncodeToString(value)), nil)

	default:
		return resultAndError(nil, unknownEncoding("bytes_to_string", encoding))
	}
}
